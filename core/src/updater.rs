//! Pure-Rust Signed-Release Updater Verification (Slice 4).
//!
//! Provides cryptographically-verified, fail-closed release verification:
//! - Ed25519 signature verification over exact manifest bytes
//! - Pinned Constitution hash validation against trust root
//! - Strict version syntax (`^\d+\.\d+\.\d+$`) and anti-rollback monotonic check
//! - Path traversal defenses (rejecting leading slashes, backslashes, colons, `..`, empty segments)
//! - Exact file size and SHA-256 hash validation
//! - Exhaustive directory walk ensuring no unlisted files exist in release package

#![deny(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ed25519;

pub const MANIFEST: &str = "manifest.json";
pub const SIGNATURE: &str = "manifest.sig";
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024; // 1 MiB

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdaterError(pub String);

impl UpdaterError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl std::fmt::Display for UpdaterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for UpdaterError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustKey {
    pub id: String,
    pub public_hex: String,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustConfig {
    pub keys: Vec<TrustKey>,
    pub constitution_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMeta {
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub product: String,
    pub version: String,
    pub constitution_sha256: String,
    pub files: BTreeMap<String, FileMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedRelease {
    pub version: String,
    pub key_id: String,
    pub files: Vec<String>,
    pub manifest: Value,
}

pub fn parse_version(v: &str) -> Result<(u32, u32, u32), UpdaterError> {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return Err(UpdaterError::new(format!("bad version '{}'", v)));
    }
    for part in &parts {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
            return Err(UpdaterError::new(format!("bad version '{}'", v)));
        }
    }
    let a = parts[0].parse::<u32>().map_err(|_| UpdaterError::new(format!("bad version '{}'", v)))?;
    let b = parts[1].parse::<u32>().map_err(|_| UpdaterError::new(format!("bad version '{}'", v)))?;
    let c = parts[2].parse::<u32>().map_err(|_| UpdaterError::new(format!("bad version '{}'", v)))?;
    Ok((a, b, c))
}

fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, UpdaterError> {
    if !hex_str.len().is_multiple_of(2) {
        return Err(UpdaterError::new("invalid hex length"));
    }
    let mut out = Vec::with_capacity(hex_str.len() / 2);
    for i in 0..hex_str.len() / 2 {
        let byte = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .map_err(|_| UpdaterError::new("invalid hex digit"))?;
        out.push(byte);
    }
    Ok(out)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn sha256_file(path: &Path) -> Result<String, UpdaterError> {
    use std::io::Read;
    let file = fs::File::open(path).map_err(|e| UpdaterError::new(format!("failed to open file {}: {}", path.display(), e)))?;
    let mut reader = std::io::BufReader::with_capacity(1024 * 1024, file);
    let mut hasher = crate::verify_loop::Sha256Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(|e| UpdaterError::new(format!("failed to read file {}: {}", path.display(), e)))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(bytes_to_hex(&digest))
}

fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Verifies a staged or distribution release directory against trusted signing keys and pinned constitution.
pub fn verify_release(
    release_dir: &Path,
    trust: &TrustConfig,
    expected_product: &str,
    check_rollback: bool,
    highest_seen_version: Option<&str>,
) -> Result<VerifiedRelease, UpdaterError> {
    let mpath = release_dir.join(MANIFEST);
    let spath = release_dir.join(SIGNATURE);

    if !mpath.is_file() || !spath.is_file() {
        return Err(UpdaterError::new("manifest or signature missing"));
    }

    let manifest_meta = fs::metadata(&mpath).map_err(|e| UpdaterError::new(e.to_string()))?;
    if manifest_meta.len() > MAX_MANIFEST_BYTES as u64 {
        return Err(UpdaterError::new("manifest too large"));
    }

    let manifest_bytes = fs::read(&mpath).map_err(|e| UpdaterError::new(e.to_string()))?;
    let raw_sig = fs::read(&spath).map_err(|e| UpdaterError::new(e.to_string()))?;

    let sig_bytes: [u8; 64] = if raw_sig.len() == 64 {
        raw_sig.try_into().unwrap()
    } else {
        match std::str::from_utf8(&raw_sig) {
            Ok(s) => {
                let trimmed = s.strip_suffix("\r\n").or_else(|| s.strip_suffix('\n')).unwrap_or(s);
                if trimmed.len() == 128 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                    let decoded = hex_to_bytes(trimmed)?;
                    if decoded.len() == 64 {
                        decoded.try_into().unwrap()
                    } else {
                        return Err(UpdaterError::new("invalid signature length"));
                    }
                } else {
                    return Err(UpdaterError::new("invalid signature format (must be 64 raw bytes or 128 hex digits)"));
                }
            }
            Err(_) => return Err(UpdaterError::new("invalid signature encoding")),
        }
    };

    let mut verified_key_id: Option<String> = None;
    for key in &trust.keys {
        if key.public_hex.len() != 64 || !key.public_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(UpdaterError::new(format!("invalid trust key hex for key {}", key.id)));
        }
        let pub_bytes_vec = hex_to_bytes(&key.public_hex)
            .map_err(|_| UpdaterError::new(format!("invalid trust key hex for key {}", key.id)))?;
        if pub_bytes_vec.len() != 32 {
            return Err(UpdaterError::new(format!("invalid trust key length for key {}", key.id)));
        }
        if key.revoked {
            continue;
        }
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&pub_bytes_vec);

        if ed25519::verify(&pub_bytes, &manifest_bytes, &sig_bytes) {
            verified_key_id = Some(key.id.clone());
            break;
        }
    }

    let key_id = match verified_key_id {
        Some(kid) => kid,
        None => return Err(UpdaterError::new("signature invalid or signed by an unknown/revoked key")),
    };

    let manifest_val: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| UpdaterError::new("malformed manifest"))?;

    // Validate format is strictly integer 1 (not boolean, not float)
    let fmt_val = manifest_val.get("format").ok_or_else(|| UpdaterError::new("malformed manifest"))?;
    if !fmt_val.is_i64() && !fmt_val.is_u64() {
        return Err(UpdaterError::new("wrong manifest format or product"));
    }
    if fmt_val.as_i64() != Some(1) {
        return Err(UpdaterError::new("wrong manifest format or product"));
    }

    let manifest: Manifest = serde_json::from_value(manifest_val.clone())
        .map_err(|_| UpdaterError::new("malformed manifest"))?;

    if manifest.product != expected_product {
        return Err(UpdaterError::new("wrong manifest format or product"));
    }

    if manifest.constitution_sha256 != trust.constitution_sha256 {
        return Err(UpdaterError::new("Constitution hash differs from the pinned trust-root value"));
    }

    let v = parse_version(&manifest.version)?;
    if check_rollback {
        if let Some(h) = highest_seen_version {
            let highest = parse_version(h)?;
            if v <= highest {
                return Err(UpdaterError::new(format!(
                    "version {} is not newer than highest seen {} (anti-rollback)",
                    manifest.version, h
                )));
            }
        }
    }

    if manifest.files.is_empty() {
        return Err(UpdaterError::new("manifest lists no files"));
    }

    let root = release_dir.canonicalize().map_err(|e| UpdaterError::new(e.to_string()))?;

    for (rel, meta) in &manifest.files {
        if rel.starts_with('/') || rel.starts_with('\\') || rel.contains('\\') || rel.contains(':') {
            return Err(UpdaterError::new(format!("unsafe path in manifest: {:?}", rel)));
        }
        let parts: Vec<&str> = rel.split('/').collect();
        if parts.iter().any(|&p| p == ".." || p == "." || p.is_empty()) {
            return Err(UpdaterError::new(format!("unsafe path in manifest: {:?}", rel)));
        }

        let mut full_path = root.clone();
        for p in &parts {
            full_path.push(p);
        }

        if !full_path.exists() {
            return Err(UpdaterError::new(format!("listed file missing: {}", rel)));
        }

        // Symlink check
        let sym_meta = fs::symlink_metadata(&full_path).map_err(|e| UpdaterError::new(e.to_string()))?;
        if sym_meta.file_type().is_symlink() {
            return Err(UpdaterError::new(format!("path escapes release directory: {:?}", rel)));
        }

        let canon_full = full_path.canonicalize().map_err(|e| UpdaterError::new(e.to_string()))?;
        if !canon_full.starts_with(&root) {
            return Err(UpdaterError::new(format!("path escapes release directory: {:?}", rel)));
        }

        if !canon_full.is_file() {
            return Err(UpdaterError::new(format!("listed file missing: {}", rel)));
        }

        if !is_valid_sha256_hex(&meta.sha256) {
            return Err(UpdaterError::new(format!("bad digest entry for {}", rel)));
        }

        let file_meta = fs::metadata(&canon_full).map_err(|e| UpdaterError::new(e.to_string()))?;
        if file_meta.len() != meta.size {
            return Err(UpdaterError::new(format!("size mismatch: {}", rel)));
        }

        let actual_sha = sha256_file(&canon_full)?;
        if actual_sha != meta.sha256 {
            return Err(UpdaterError::new(format!("SHA-256 mismatch (tampered?): {}", rel)));
        }
    }

    // Check for unlisted files in release directory via non-following walk
    let mut listed_set = std::collections::BTreeSet::new();
    for k in manifest.files.keys() {
        listed_set.insert(k.clone());
    }
    listed_set.insert(MANIFEST.to_string());
    listed_set.insert(SIGNATURE.to_string());

    verify_directory_entries(&root, &root, &listed_set)?;

    let mut sorted_files: Vec<String> = manifest.files.keys().cloned().collect();
    sorted_files.sort();

    Ok(VerifiedRelease {
        version: manifest.version,
        key_id,
        files: sorted_files,
        manifest: manifest_val,
    })
}

fn verify_directory_entries(
    base: &Path,
    current: &Path,
    listed: &std::collections::BTreeSet<String>,
) -> Result<(), UpdaterError> {
    let entries = fs::read_dir(current).map_err(|e| UpdaterError::new(e.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|e| UpdaterError::new(e.to_string()))?;
        let file_type = entry.file_type().map_err(|e| UpdaterError::new(e.to_string()))?;
        let path = entry.path();
        if file_type.is_symlink() {
            return Err(UpdaterError::new(format!("symlink in release: {:?}", path)));
        }
        if file_type.is_dir() {
            verify_directory_entries(base, &path, listed)?;
        } else if file_type.is_file() {
            let rel = path.strip_prefix(base).map_err(|e| UpdaterError::new(e.to_string()))?;
            let mut parts = Vec::new();
            for c in rel.components() {
                if let Component::Normal(os_str) = c {
                    parts.push(os_str.to_string_lossy().to_string());
                }
            }
            let rel_str = parts.join("/");
            if !listed.contains(&rel_str) {
                return Err(UpdaterError::new(format!("unlisted file in release: {}", rel_str)));
            }
        } else {
            return Err(UpdaterError::new(format!("special or non-regular file in release: {:?}", path)));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("0.3.0").unwrap(), (0, 3, 0));
        assert_eq!(parse_version("10.200.34").unwrap(), (10, 200, 34));
        assert!(parse_version("0.3").is_err());
        assert!(parse_version("0.3.0.1").is_err());
        assert!(parse_version("v0.3.0").is_err());
        assert!(parse_version("0.3.x").is_err());
    }

    #[test]
    fn test_valid_sha256_hex() {
        assert!(is_valid_sha256_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_sha256_hex("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_sha256_hex("short"));
    }
}
