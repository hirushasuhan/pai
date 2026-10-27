/*
 * Personal Agentic AI (PAI) - Native Windows Launcher (pai.exe)
 *
 * Part of Milestone P2 for the v1.1.0 Packaging and Installer subsystem.
 * Specifications: docs/PACKAGING_SPEC.md, docs/adr/ADR-013-installer-and-distribution.md
 *
 * Responsibilities:
 *  1. Resolve installation root relative to launcher location (bin\pai.exe or pai.exe).
 *  2. Load and parse manifest.json to extract the pinned SHA-256 of bin\pai-core.exe.
 *  3. Verify bin\pai-core.exe SHA-256 against manifest before execution (fail-closed).
 *  4. Enforce security boundary:
 *     - Set PAI_CORE_BIN to <install_root>\bin\pai-core.exe.
 *     - Set PAI_CORE_SHA256 to the pinned hash (overrides user environment, Finding BE).
 *     - Set PAI_INSTALL_DIR to <install_root>.
 *     - Clear dangerous Python variables: PYTHONPATH, PYTHONHOME, PYTHONSTARTUP.
 *  5. Discover Python runtime:
 *     - Production / release: requires embedded runtime at <install_root>\python\python.exe.
 *     - Developer opt-in: system Python enabled only with PAI_ALLOW_SYSTEM_PYTHON=1 (with -E -s).
 *  6. Inherit caller's working directory (lpCurrentDirectory = NULL, Finding BM).
 *  7. Ignore Ctrl-C in launcher so Python child handles KeyboardInterrupt (Finding BT).
 *  8. Set safe DLL search order (Finding BS).
 *  9. Invoke python.exe research\pai.py %* forwarding all arguments and exit codes.
 *
 * Zero external dependencies. Uses only standard Windows APIs (kernel32, bcrypt).
 */

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <bcrypt.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define PAI_MAX_PATH 32768
#define SHA256_HEX_LEN 64
#define SHA256_BYTE_LEN 32

/* Helper: print wide error message to stderr */
static void print_error(const wchar_t *msg) {
    fwprintf(stderr, L"[PAI Launcher Error] %ls\n", msg);
    fflush(stderr);
}

/* Helper: print formatted wide error message to stderr */
static void print_error_f(const wchar_t *fmt, const wchar_t *arg) {
    fwprintf(stderr, L"[PAI Launcher Error] ");
    fwprintf(stderr, fmt, arg);
    fwprintf(stderr, L"\n");
    fflush(stderr);
}

/* Check if file exists */
static BOOL file_exists(const wchar_t *path) {
    DWORD attr = GetFileAttributesW(path);
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

/* Check if directory exists */
static BOOL dir_exists(const wchar_t *path) {
    DWORD attr = GetFileAttributesW(path);
    return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
}

/* Helper: compute SHA-256 of a file using Windows BCrypt */
static BOOL compute_file_sha256(const wchar_t *path, char *hex_out_lower) {
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status != 0) {
        CloseHandle(hFile);
        return FALSE;
    }

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return FALSE;
    }

    BYTE buffer[65536];
    DWORD bytesRead = 0;
    BOOL ok = TRUE;

    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        status = BCryptHashData(hHash, buffer, bytesRead, 0);
        if (status != 0) {
            ok = FALSE;
            break;
        }
    }

    BYTE hash_bytes[SHA256_BYTE_LEN];
    if (ok) {
        status = BCryptFinishHash(hHash, hash_bytes, sizeof(hash_bytes), 0);
        if (status != 0) {
            ok = FALSE;
        }
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);

    if (ok) {
        for (int i = 0; i < SHA256_BYTE_LEN; i++) {
            sprintf(hex_out_lower + (i * 2), "%02x", hash_bytes[i]);
        }
        hex_out_lower[SHA256_HEX_LEN] = '\0';
    }

    return ok;
}

/* Helper: strip trailing component from path in-place */
static void strip_last_component(wchar_t *path) {
    size_t len = wcslen(path);
    while (len > 0 && (path[len - 1] == L'\\' || path[len - 1] == L'/')) {
        path[len - 1] = L'\0';
        len--;
    }
    while (len > 0 && path[len - 1] != L'\\' && path[len - 1] != L'/') {
        path[len - 1] = L'\0';
        len--;
    }
    while (len > 0 && (path[len - 1] == L'\\' || path[len - 1] == L'/')) {
        path[len - 1] = L'\0';
        len--;
    }
}

/*
 * Parse manifest.json to extract the tag or version string.
 * Prefers "tag" (e.g. v1.0.0-rc1) if present, otherwise falls back to "version" (e.g. 1.0.0).
 */
static BOOL extract_tag_or_version_from_manifest(const wchar_t *manifest_path, wchar_t *version_out, size_t max_len) {
    HANDLE hFile = CreateFileW(manifest_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    LARGE_INTEGER size;
    if (!GetFileSizeEx(hFile, &size) || size.QuadPart > 10 * 1024 * 1024 || size.QuadPart < 32) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD file_size = (DWORD)size.QuadPart;
    char *buf = (char *)malloc(file_size + 1);
    if (!buf) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buf, file_size, &bytesRead, NULL) || bytesRead != file_size) {
        free(buf);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);
    buf[file_size] = '\0';

    /* First look for top-level "tag" */
    const char *key = "\"tag\"";
    const char *pos = strstr(buf, key);
    if (!pos) {
        /* Fall back to "version" */
        key = "\"version\"";
        pos = strstr(buf, key);
    }

    if (!pos) {
        free(buf);
        return FALSE;
    }

    const char *colon = strchr(pos + strlen(key), ':');
    if (!colon) {
        free(buf);
        return FALSE;
    }

    const char *start = strchr(colon, '"');
    if (!start) {
        free(buf);
        return FALSE;
    }
    start++;
    const char *end = strchr(start, '"');
    if (!end || (size_t)(end - start) >= max_len) {
        free(buf);
        return FALSE;
    }

    for (size_t i = 0; i < (size_t)(end - start); i++) {
        version_out[i] = (wchar_t)start[i];
    }
    version_out[end - start] = L'\0';

    free(buf);
    return TRUE;
}

/*
 * Parse manifest.json to extract the SHA-256 for bin/pai-core.exe.
 * Defends against decoy entries by locating the "files" object boundary first (Finding BR).
 */
static BOOL extract_core_sha256_from_manifest(const wchar_t *manifest_path, char *sha256_out) {
    HANDLE hFile = CreateFileW(manifest_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    LARGE_INTEGER size;
    if (!GetFileSizeEx(hFile, &size) || size.QuadPart > 10 * 1024 * 1024 || size.QuadPart < 32) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD file_size = (DWORD)size.QuadPart;
    char *buf = (char *)malloc(file_size + 1);
    if (!buf) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buf, file_size, &bytesRead, NULL) || bytesRead != file_size) {
        free(buf);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);
    buf[file_size] = '\0';

    /* Locate "files" dictionary boundary */
    const char *files_sec = strstr(buf, "\"files\"");
    if (!files_sec) {
        free(buf);
        return FALSE;
    }

    /* From files_sec, find exact key "bin/pai-core.exe" or "bin\\pai-core.exe" */
    const char *key1 = "\"bin/pai-core.exe\"";
    const char *pos = strstr(files_sec, key1);
    if (!pos) {
        const char *key2 = "\"bin\\\\pai-core.exe\"";
        pos = strstr(files_sec, key2);
    }
    if (!pos) {
        free(buf);
        return FALSE;
    }

    /* From key pos, find "sha256" within the file object */
    const char *sha_key = "\"sha256\"";
    const char *sha_pos = strstr(pos, sha_key);
    if (!sha_pos) {
        free(buf);
        return FALSE;
    }

    /* Verify sha_pos is within the same JSON object (before the next file key or closing brace) */
    const char *obj_close = strchr(pos, '}');
    if (obj_close && sha_pos > obj_close) {
        free(buf);
        return FALSE;
    }

    /* Locate opening quote of sha256 value */
    const char *val_start = strchr(sha_pos + strlen(sha_key), '"');
    if (!val_start) {
        free(buf);
        return FALSE;
    }
    val_start++; /* skip opening quote */

    /* Verify 64 hex characters followed by closing quote */
    for (int i = 0; i < SHA256_HEX_LEN; i++) {
        char c = val_start[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            free(buf);
            return FALSE;
        }
        sha256_out[i] = (char)tolower((unsigned char)c);
    }
    if (val_start[SHA256_HEX_LEN] != '"') {
        free(buf);
        return FALSE;
    }
    sha256_out[SHA256_HEX_LEN] = '\0';

    free(buf);
    return TRUE;
}

int wmain(int argc, wchar_t *argv[]) {
    (void)argc;
    (void)argv;

    /* Hardening: restrict DLL search order to System32 to prevent DLL hijacking (Finding BS) */
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);

    /* Ignore Ctrl-C in launcher process so child Python process handles KeyboardInterrupt (Finding BT) */
    SetConsoleCtrlHandler(NULL, TRUE);

    /* 1. Locate launcher executable path */
    wchar_t exe_path[PAI_MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, exe_path, PAI_MAX_PATH);
    if (len == 0 || len >= PAI_MAX_PATH) {
        print_error(L"Failed to determine launcher executable path.");
        return 1;
    }

    /* 2. Determine installation root directory */
    wchar_t launcher_dir[PAI_MAX_PATH];
    wcsncpy(launcher_dir, exe_path, PAI_MAX_PATH - 1);
    launcher_dir[PAI_MAX_PATH - 1] = L'\0';
    strip_last_component(launcher_dir);

    wchar_t install_root[PAI_MAX_PATH];
    wchar_t manifest_path[PAI_MAX_PATH];

    /* Test if manifest.json is in parent directory (standard bin\pai.exe layout) */
    wchar_t parent_dir[PAI_MAX_PATH];
    wcsncpy(parent_dir, launcher_dir, PAI_MAX_PATH - 1);
    parent_dir[PAI_MAX_PATH - 1] = L'\0';
    strip_last_component(parent_dir);

    _snwprintf(manifest_path, PAI_MAX_PATH, L"%ls\\manifest.json", parent_dir);
    if (file_exists(manifest_path)) {
        wcsncpy(install_root, parent_dir, PAI_MAX_PATH - 1);
        install_root[PAI_MAX_PATH - 1] = L'\0';
    } else {
        /* Test if manifest.json is in launcher_dir directly */
        _snwprintf(manifest_path, PAI_MAX_PATH, L"%ls\\manifest.json", launcher_dir);
        if (file_exists(manifest_path)) {
            wcsncpy(install_root, launcher_dir, PAI_MAX_PATH - 1);
            install_root[PAI_MAX_PATH - 1] = L'\0';
        } else {
            print_error(L"Cannot locate manifest.json in installation root. Reinstallation required.");
            return 1;
        }
    }

    /* Fast-path: pai --version / pai -v (prints tag, e.g. pai v1.0.0-rc1, Finding BT & spec §13) */
    if (argc == 2 && (wcscmp(argv[1], L"--version") == 0 || wcscmp(argv[1], L"-v") == 0)) {
        wchar_t ver[64];
        if (extract_tag_or_version_from_manifest(manifest_path, ver, 64)) {
            wprintf(L"pai %ls\n", ver);
            return 0;
        }
    }

    /* 3. Parse manifest.json and extract expected pai-core.exe hash */
    char expected_sha256[SHA256_HEX_LEN + 1];
    if (!extract_core_sha256_from_manifest(manifest_path, expected_sha256)) {
        print_error_f(L"Failed to read or parse bin/pai-core.exe SHA-256 in %ls", manifest_path);
        return 1;
    }

    /* 4. Verify pai-core.exe existence and integrity */
    wchar_t core_bin_path[PAI_MAX_PATH];
    _snwprintf(core_bin_path, PAI_MAX_PATH, L"%ls\\bin\\pai-core.exe", install_root);
    if (!file_exists(core_bin_path)) {
        print_error_f(L"pai-core binary not found at %ls", core_bin_path);
        return 1;
    }

    char actual_sha256[SHA256_HEX_LEN + 1];
    if (!compute_file_sha256(core_bin_path, actual_sha256)) {
        print_error_f(L"Failed to compute SHA-256 for %ls", core_bin_path);
        return 1;
    }

    if (strcmp(expected_sha256, actual_sha256) != 0) {
        fwprintf(stderr, L"[PAI Launcher Error] pai-core.exe SHA-256 verification failed (tampered or corrupt binary).\n");
        fwprintf(stderr, L"  Expected: %hs\n  Actual:   %hs\n", expected_sha256, actual_sha256);
        fflush(stderr);
        return 1;
    }

    /* 5. Verify research/pai.py existence */
    wchar_t script_path[PAI_MAX_PATH];
    _snwprintf(script_path, PAI_MAX_PATH, L"%ls\\research\\pai.py", install_root);
    if (!file_exists(script_path)) {
        print_error_f(L"research entrypoint not found at %ls", script_path);
        return 1;
    }

    /* 6. Discover Python runtime (Finding BN: embedded required in release; opt-in for system) */
    wchar_t python_exe[PAI_MAX_PATH];
    wchar_t embedded_python[PAI_MAX_PATH];
    _snwprintf(embedded_python, PAI_MAX_PATH, L"%ls\\python\\python.exe", install_root);

    BOOL is_embedded = FALSE;
    BOOL use_system_opt_in = FALSE;

    if (file_exists(embedded_python)) {
        wcsncpy(python_exe, embedded_python, PAI_MAX_PATH - 1);
        python_exe[PAI_MAX_PATH - 1] = L'\0';
        is_embedded = TRUE;
    } else {
        /* Check for explicit developer opt-in */
        wchar_t allow_sys[32];
        DWORD allow_len = GetEnvironmentVariableW(L"PAI_ALLOW_SYSTEM_PYTHON", allow_sys, 32);
        if (allow_len == 0 || wcscmp(allow_sys, L"1") != 0) {
            fwprintf(stderr, L"[PAI Launcher Error] Embedded Python runtime not found at %ls.\n", embedded_python);
            fwprintf(stderr, L"  Release installations require bundled embedded Python.\n");
            fwprintf(stderr, L"  (Developers: set PAI_ALLOW_SYSTEM_PYTHON=1 to opt-in to system Python).\n");
            fflush(stderr);
            return 1;
        }

        /* Developer opt-in: discover system Python by absolute path on PATH */
        DWORD found = SearchPathW(NULL, L"python.exe", NULL, PAI_MAX_PATH, python_exe, NULL);
        if (found == 0 || found >= PAI_MAX_PATH) {
            print_error(L"System Python not found on PATH.");
            return 1;
        }

        /* Verify discovered python_exe is an absolute path */
        if (python_exe[0] == L'.' || (python_exe[1] != L':' && (python_exe[0] != L'\\' || python_exe[1] != L'\\'))) {
            print_error(L"Discovered Python path is not an absolute path; refusing for security.");
            return 1;
        }
        use_system_opt_in = TRUE;
    }

    /* 7. Enforce security environment and set PAI variables */
    SetEnvironmentVariableW(L"PYTHONPATH", NULL);
    SetEnvironmentVariableW(L"PYTHONHOME", NULL);
    SetEnvironmentVariableW(L"PYTHONSTARTUP", NULL);

    wchar_t expected_sha256_w[SHA256_HEX_LEN + 1];
    for (int i = 0; i <= SHA256_HEX_LEN; i++) {
        expected_sha256_w[i] = (wchar_t)expected_sha256[i];
    }

    SetEnvironmentVariableW(L"PAI_CORE_BIN", core_bin_path);
    SetEnvironmentVariableW(L"PAI_CORE_SHA256", expected_sha256_w);
    SetEnvironmentVariableW(L"PAI_INSTALL_DIR", install_root);

    /* 8. Parse command-line arguments to forward to python */
    const wchar_t *raw_cmdline = GetCommandLineW();
    const wchar_t *args_start = raw_cmdline;

    /* Skip argv[0] */
    if (*args_start == L'"') {
        args_start++;
        while (*args_start && *args_start != L'"') {
            args_start++;
        }
        if (*args_start == L'"') {
            args_start++;
        }
    } else {
        while (*args_start && *args_start != L' ' && *args_start != L'\t') {
            args_start++;
        }
    }

    /* Skip whitespace after argv[0] */
    while (*args_start == L' ' || *args_start == L'\t') {
        args_start++;
    }

    /*
     * Build command line:
     * If developer opt-in system Python: "<python_exe>" -E -s "<script_path>" <args>
     * If embedded Python:               "<python_exe>" "<script_path>" <args>
     */
    size_t cmdline_len = wcslen(python_exe) + wcslen(script_path) + wcslen(args_start) + 32;
    wchar_t *full_cmdline = (wchar_t *)malloc(cmdline_len * sizeof(wchar_t));
    if (!full_cmdline) {
        print_error(L"Out of memory allocating child process command line.");
        return 1;
    }

    if (use_system_opt_in) {
        if (*args_start) {
            _snwprintf(full_cmdline, cmdline_len, L"\"%ls\" -E -s \"%ls\" %ls", python_exe, script_path, args_start);
        } else {
            _snwprintf(full_cmdline, cmdline_len, L"\"%ls\" -E -s \"%ls\"", python_exe, script_path);
        }
    } else {
        if (*args_start) {
            _snwprintf(full_cmdline, cmdline_len, L"\"%ls\" \"%ls\" %ls", python_exe, script_path, args_start);
        } else {
            _snwprintf(full_cmdline, cmdline_len, L"\"%ls\" \"%ls\"", python_exe, script_path);
        }
    }

    /* 9. Execute Python subprocess inheriting caller's working directory (lpCurrentDirectory = NULL, Finding BM) */
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    BOOL created = CreateProcessW(
        python_exe,       /* Application name */
        full_cmdline,     /* Command line */
        NULL,             /* Process attributes */
        NULL,             /* Thread attributes */
        TRUE,             /* Inherit handles (stdio) */
        0,                /* Creation flags */
        NULL,             /* Environment (inherits current process with our SetEnvironmentVariableW overrides) */
        NULL,             /* Working directory: NULL inherits caller's working directory! */
        &si,
        &pi
    );

    free(full_cmdline);

    if (!created) {
        DWORD err = GetLastError();
        fwprintf(stderr, L"[PAI Launcher Error] Failed to launch Python (error code %lu).\n", err);
        return 1;
    }

    /* Wait for child process to exit */
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (int)exit_code;
}
