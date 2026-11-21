import os
import subprocess
from pathlib import Path

bin_dir = Path("desktop/bin")
bin_dir.mkdir(parents=True, exist_ok=True)

exe_path = bin_dir / "pai_folder_picker.exe"
cs_path = bin_dir / "pai_folder_picker.cs"

cs_source = """using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Pai {
    [ComImport, Guid("DC1C5A9C-E88A-4dde-A5A1-60F82A20AEF7")]
    public class FileOpenDialogRCW {}

    [ComImport, Guid("d57c7288-d4ad-4768-be02-9d969532d960"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IFileOpenDialog {
        [PreserveSig] int Show(IntPtr parent);
        void SetFileTypes();
        void SetFileTypeIndex();
        void GetFileTypeIndex();
        void Advise();
        void Unadvise();
        void SetOptions(uint fos);
        void GetOptions(out uint fos);
        void SetDefaultFolder(IShellItem psi);
        void SetFolder(IShellItem psi);
        void GetFolder(out IntPtr ppsi);
        void GetCurrentSelection(out IntPtr ppsi);
        void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string pszName);
        void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string pszTitle);
        void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string pszText);
        void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string pszLabel);
        void GetResult(out IShellItem ppsi);
        void AddPlace(IntPtr psi, int fdap);
        void SetDefaultExtension([MarshalAs(UnmanagedType.LPWStr)] string pszDefaultExtension);
        void Close(int hr);
        void SetClientGuid(ref Guid guid);
        void ClearClientData();
        void SetFilter(IntPtr pFilter);
        void GetResults(out IntPtr ppenum);
        void GetSelectedItems(out IntPtr ppsai);
    }

    [ComImport, Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IShellItem {
        void BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppv);
        void GetParent(out IShellItem ppsi);
        void GetDisplayName(uint sigdnName, [MarshalAs(UnmanagedType.LPWStr)] out string ppszName);
        void GetAttributes(uint sfgaoMask, out uint psfgaoAttribs);
        void Compare(IShellItem psi, uint hint, out int piOrder);
    }

    public static class Program {
        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int SHCreateItemFromParsingName(
            [MarshalAs(UnmanagedType.LPWStr)] string pszPath,
            IntPtr pbc,
            ref Guid riid,
            out IShellItem ppv
        );

        [STAThread]
        public static int Main(string[] args) {
            string title = args.Length > 0 ? args[0] : "Select Folder";
            string outPath = args.Length > 1 ? args[1] : "";
            string initialPath = args.Length > 2 ? args[2] : "";

            try {
                var dialog = (IFileOpenDialog)new FileOpenDialogRCW();
                uint options;
                dialog.GetOptions(out options);
                dialog.SetOptions(options | 0x20 | 0x40); // FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM
                
                if (!string.IsNullOrEmpty(title)) {
                    dialog.SetTitle(title);
                }

                if (!string.IsNullOrEmpty(initialPath) && Directory.Exists(initialPath)) {
                    try {
                        Guid iid = new Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe");
                        IShellItem folderItem;
                        if (SHCreateItemFromParsingName(initialPath, IntPtr.Zero, ref iid, out folderItem) == 0 && folderItem != null) {
                            dialog.SetFolder(folderItem);
                            dialog.SetDefaultFolder(folderItem);
                        }
                    } catch {}
                }

                IntPtr fg = GetForegroundWindow();
                int hr = dialog.Show(fg);
                if (hr == 0) {
                    IShellItem item;
                    dialog.GetResult(out item);
                    if (item != null) {
                        string selectedPath;
                        item.GetDisplayName(0x80058000, out selectedPath); // SIGDN_FILESYSPATH
                        if (!string.IsNullOrEmpty(selectedPath) && !string.IsNullOrEmpty(outPath)) {
                            File.WriteAllText(outPath, selectedPath);
                        }
                        return 0;
                    }
                }
                return 2; // Cancelled
            } catch (Exception ex) {
                if (!string.IsNullOrEmpty(outPath)) {
                    File.WriteAllText(outPath + ".err", ex.ToString());
                }
                return 1;
            }
        }
    }
}
"""

cs_path.write_text(cs_source, encoding="utf-8")
csc = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
p = subprocess.run([csc, "/nologo", "/target:winexe", f"/out:{exe_path}", str(cs_path)], capture_output=True, text=True)
print("Build code:", p.returncode)
print("Build stdout:", p.stdout)
print("Build stderr:", p.stderr)
print("EXE created:", exe_path.is_file(), "Size:", exe_path.stat().st_size if exe_path.is_file() else 0)
