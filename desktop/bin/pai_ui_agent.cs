using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Automation;
using System.Windows.Forms;

namespace PaiDesktopControl {
    internal static class Native {
        public const int INPUT_MOUSE = 0;
        public const int INPUT_KEYBOARD = 1;

        public const uint MOUSEEVENTF_MOVE = 0x0001;
        public const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
        public const uint MOUSEEVENTF_LEFTUP = 0x0004;
        public const uint MOUSEEVENTF_RIGHTDOWN = 0x0008;
        public const uint MOUSEEVENTF_RIGHTUP = 0x0010;
        public const uint MOUSEEVENTF_MIDDLEDOWN = 0x0020;
        public const uint MOUSEEVENTF_MIDDLEUP = 0x0040;
        public const uint MOUSEEVENTF_WHEEL = 0x0800;
        public const uint MOUSEEVENTF_VIRTUALDESK = 0x4000;
        public const uint MOUSEEVENTF_ABSOLUTE = 0x8000;

        public const uint KEYEVENTF_KEYUP = 0x0002;
        public const uint KEYEVENTF_UNICODE = 0x0004;

        public const int SM_XVIRTUALSCREEN = 76;
        public const int SM_YVIRTUALSCREEN = 77;
        public const int SM_CXVIRTUALSCREEN = 78;
        public const int SM_CYVIRTUALSCREEN = 79;

        public const int SW_RESTORE = 9;
        public const int SW_SHOW = 5;

        [StructLayout(LayoutKind.Sequential)]
        public struct POINT {
            public int X;
            public int Y;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RECT {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MOUSEINPUT {
            public int dx;
            public int dy;
            public uint mouseData;
            public uint dwFlags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KEYBDINPUT {
            public ushort wVk;
            public ushort wScan;
            public uint dwFlags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct INPUTUNION {
            [FieldOffset(0)] public MOUSEINPUT mi;
            [FieldOffset(0)] public KEYBDINPUT ki;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct INPUT {
            public int type;
            public INPUTUNION U;
        }

        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern bool SetProcessDPIAware();

        [DllImport("user32.dll")]
        public static extern bool GetCursorPos(out POINT lpPoint);

        [DllImport("user32.dll")]
        public static extern bool SetCursorPos(int X, int Y);

        [DllImport("user32.dll")]
        public static extern int GetSystemMetrics(int nIndex);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        public static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll")]
        public static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);

        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentThreadId();
    }

    internal static class Program {
        private static readonly Dictionary<string, ushort> KeyMap = new Dictionary<string, ushort>(StringComparer.OrdinalIgnoreCase) {
            {"enter", 0x0D}, {"return", 0x0D},
            {"tab", 0x09},
            {"esc", 0x1B}, {"escape", 0x1B},
            {"space", 0x20},
            {"backspace", 0x08}, {"back", 0x08},
            {"delete", 0x2E}, {"del", 0x2E},
            {"insert", 0x2D},
            {"home", 0x24}, {"end", 0x23},
            {"pageup", 0x21}, {"pgup", 0x21},
            {"pagedown", 0x22}, {"pgdn", 0x22},
            {"left", 0x25}, {"up", 0x26}, {"right", 0x27}, {"down", 0x28},
            {"ctrl", 0x11}, {"control", 0x11},
            {"alt", 0x12}, {"menu", 0x12},
            {"shift", 0x10},
            {"win", 0x5B}, {"lwin", 0x5B}, {"super", 0x5B},
            {"f1", 0x70}, {"f2", 0x71}, {"f3", 0x72}, {"f4", 0x73},
            {"f5", 0x74}, {"f6", 0x75}, {"f7", 0x76}, {"f8", 0x77},
            {"f9", 0x78}, {"f10", 0x79}, {"f11", 0x7A}, {"f12", 0x7B},
            {"a", 0x41}, {"b", 0x42}, {"c", 0x43}, {"d", 0x44}, {"e", 0x45},
            {"f", 0x46}, {"g", 0x47}, {"h", 0x48}, {"i", 0x49}, {"j", 0x4A},
            {"k", 0x4B}, {"l", 0x4C}, {"m", 0x4D}, {"n", 0x4E}, {"o", 0x4F},
            {"p", 0x50}, {"q", 0x51}, {"r", 0x52}, {"s", 0x53}, {"t", 0x54},
            {"u", 0x55}, {"v", 0x56}, {"w", 0x57}, {"x", 0x58}, {"y", 0x59}, {"z", 0x5A},
            {"0", 0x30}, {"1", 0x31}, {"2", 0x32}, {"3", 0x33}, {"4", 0x34},
            {"5", 0x35}, {"6", 0x36}, {"7", 0x37}, {"8", 0x38}, {"9", 0x39}
        };

        [STAThread]
        public static int Main(string[] args) {
            try { Native.SetProcessDPIAware(); } catch {}
            if (args.Length == 0) {
                PrintError("Missing command");
                return 1;
            }

            string cmd = args[0].ToLowerInvariant();
            bool checkFailsafe = true;
            for (int i = 0; i < args.Length; i++) {
                if (args[i] == "--no-failsafe") checkFailsafe = false;
            }

            try {
                if (cmd == "state") {
                    return CmdState(args);
                }
                if (cmd == "screenshot") {
                    return CmdScreenshot(args);
                }
                if (cmd == "focus_window") {
                    return CmdFocusWindow(args);
                }

                if (checkFailsafe && IsFailSafeTriggered()) {
                    Console.WriteLine("{\"ok\":false,\"failsafe\":true,\"error\":\"Aborted by top-left corner (0,0) failsafe.\"}");
                    return 2;
                }

                if (cmd == "mouse_move") return CmdMouseMove(args);
                if (cmd == "mouse_click") return CmdMouseClick(args);
                if (cmd == "mouse_drag") return CmdMouseDrag(args);
                if (cmd == "mouse_scroll") return CmdMouseScroll(args);
                if (cmd == "key_press") return CmdKeyPress(args);
                if (cmd == "hotkey") return CmdHotkey(args);
                if (cmd == "type_text") return CmdTypeText(args);
                if (cmd == "uia_click") return CmdUiaClick(args);
                if (cmd == "uia_set_text") return CmdUiaSetText(args);

                PrintError("Unknown command: " + cmd);
                return 1;
            } catch (Exception ex) {
                PrintError(ex.Message);
                return 1;
            }
        }

        private static bool IsFailSafeTriggered() {
            Native.POINT pt;
            if (Native.GetCursorPos(out pt)) {
                return pt.X <= 2 && pt.Y <= 2;
            }
            return false;
        }

        private static string GetArg(string[] args, string flag, string defVal) {
            for (int i = 0; i < args.Length - 1; i++) {
                if (args[i] == flag) return args[i + 1];
            }
            return defVal;
        }

        private static int GetIntArg(string[] args, string flag, int defVal) {
            string val = GetArg(args, flag, "");
            int res;
            if (!string.IsNullOrEmpty(val) && int.TryParse(val, out res)) return res;
            return defVal;
        }

        private static string JsonEsc(string s) {
            if (s == null) return "";
            StringBuilder sb = new StringBuilder(s.Length + 8);
            for (int i = 0; i < s.Length; i++) {
                char c = s[i];
                if (c == '\\') sb.Append("\\\\");
                else if (c == '"') sb.Append("\\\"");
                else if (c == '\b') sb.Append("\\b");
                else if (c == '\f') sb.Append("\\f");
                else if (c == '\n') sb.Append("\\n");
                else if (c == '\r') sb.Append("\\r");
                else if (c == '\t') sb.Append("\\t");
                else if (c < 32) sb.AppendFormat("\\u{0:x4}", (int)c);
                else sb.Append(c);
            }
            return sb.ToString();
        }

        private static void PrintError(string msg) {
            Console.WriteLine("{\"ok\":false,\"error\":\"" + JsonEsc(msg) + "\"}");
        }

        private static string GetProcessNameSafe(uint pid) {
            try {
                using (Process p = Process.GetProcessById((int)pid)) {
                    return p.ProcessName;
                }
            } catch {
                return "";
            }
        }

        private static string GetWindowTitleSafe(IntPtr hWnd) {
            int len = Native.GetWindowTextLength(hWnd);
            if (len <= 0) return "";
            StringBuilder sb = new StringBuilder(len + 1);
            Native.GetWindowText(hWnd, sb, sb.Capacity);
            return sb.ToString();
        }

        private class WindowInfo {
            public long Hwnd;
            public uint Pid;
            public string Process;
            public string Title;
            public int X, Y, W, H;
            public bool IsForeground;
        }

        private static List<WindowInfo> EnumerateVisibleWindows(IntPtr fgHwnd) {
            List<WindowInfo> list = new List<WindowInfo>();
            Native.EnumWindows(delegate(IntPtr hWnd, IntPtr lParam) {
                if (!Native.IsWindowVisible(hWnd)) return true;
                string title = GetWindowTitleSafe(hWnd);
                if (string.IsNullOrWhiteSpace(title)) return true;
                Native.RECT r;
                if (!Native.GetWindowRect(hWnd, out r)) return true;
                int w = r.Right - r.Left;
                int h = r.Bottom - r.Top;
                if (w < 40 || h < 20) return true;
                uint pid;
                Native.GetWindowThreadProcessId(hWnd, out pid);
                WindowInfo wi = new WindowInfo();
                wi.Hwnd = hWnd.ToInt64();
                wi.Pid = pid;
                wi.Process = GetProcessNameSafe(pid);
                wi.Title = title;
                wi.X = r.Left;
                wi.Y = r.Top;
                wi.W = w;
                wi.H = h;
                wi.IsForeground = (hWnd == fgHwnd);
                list.Add(wi);
                return list.Count < 35;
            }, IntPtr.Zero);
            return list;
        }

        private static int CmdState(string[] args) {
            int targetHwndInt = GetIntArg(args, "--hwnd", 0);
            int maxNodes = GetIntArg(args, "--max-nodes", 120);
            int maxDepth = GetIntArg(args, "--max-depth", 8);

            IntPtr fgHwnd = Native.GetForegroundWindow();
            IntPtr targetHwnd = targetHwndInt != 0 ? new IntPtr(targetHwndInt) : fgHwnd;

            int vLeft = Native.GetSystemMetrics(Native.SM_XVIRTUALSCREEN);
            int vTop = Native.GetSystemMetrics(Native.SM_YVIRTUALSCREEN);
            int vWidth = Native.GetSystemMetrics(Native.SM_CXVIRTUALSCREEN);
            int vHeight = Native.GetSystemMetrics(Native.SM_CYVIRTUALSCREEN);
            if (vWidth <= 0) vWidth = Screen.PrimaryScreen.Bounds.Width;
            if (vHeight <= 0) vHeight = Screen.PrimaryScreen.Bounds.Height;

            Native.POINT cursor;
            Native.GetCursorPos(out cursor);

            List<WindowInfo> windows = EnumerateVisibleWindows(fgHwnd);

            uint fgPid = 0;
            if (fgHwnd != IntPtr.Zero) Native.GetWindowThreadProcessId(fgHwnd, out fgPid);
            string fgTitle = fgHwnd != IntPtr.Zero ? GetWindowTitleSafe(fgHwnd) : "";
            string fgProc = fgPid != 0 ? GetProcessNameSafe(fgPid) : "";

            List<string> elemJsonList = new List<string>();
            if (targetHwnd != IntPtr.Zero) {
                try {
                    AutomationElement root = AutomationElement.FromHandle(targetHwnd);
                    if (root != null) {
                        CollectUiaElements(root, 0, maxDepth, maxNodes, elemJsonList);
                    }
                } catch {}
            }

            StringBuilder sb = new StringBuilder();
            sb.Append("{\"ok\":true,");
            sb.AppendFormat("\"screen\":{{\"left\":{0},\"top\":{1},\"width\":{2},\"height\":{3}}},", vLeft, vTop, vWidth, vHeight);
            sb.AppendFormat("\"cursor\":{{\"x\":{0},\"y\":{1}}},", cursor.X, cursor.Y);
            sb.AppendFormat("\"foreground\":{{\"hwnd\":{0},\"pid\":{1},\"process\":\"{2}\",\"title\":\"{3}\"}},",
                fgHwnd.ToInt64(), fgPid, JsonEsc(fgProc), JsonEsc(fgTitle));

            sb.Append("\"windows\":[");
            for (int i = 0; i < windows.Count; i++) {
                WindowInfo wi = windows[i];
                if (i > 0) sb.Append(",");
                sb.AppendFormat("{{\"hwnd\":{0},\"pid\":{1},\"process\":\"{2}\",\"title\":\"{3}\",\"rect\":[{4},{5},{6},{7}],\"foreground\":{8}}}",
                    wi.Hwnd, wi.Pid, JsonEsc(wi.Process), JsonEsc(wi.Title), wi.X, wi.Y, wi.W, wi.H, wi.IsForeground ? "true" : "false");
            }
            sb.Append("],");

            sb.Append("\"elements\":[");
            for (int i = 0; i < elemJsonList.Count; i++) {
                if (i > 0) sb.Append(",");
                sb.Append(elemJsonList[i]);
            }
            sb.Append("]}");

            Console.WriteLine(sb.ToString());
            return 0;
        }

        private static bool IsInteractiveControlType(ControlType ct) {
            return ct == ControlType.Button ||
                   ct == ControlType.Edit ||
                   ct == ControlType.Document ||
                   ct == ControlType.ComboBox ||
                   ct == ControlType.CheckBox ||
                   ct == ControlType.RadioButton ||
                   ct == ControlType.MenuItem ||
                   ct == ControlType.TabItem ||
                   ct == ControlType.ListItem ||
                   ct == ControlType.Hyperlink ||
                   ct == ControlType.TreeItem;
        }

        private static void CollectUiaElements(AutomationElement node, int depth, int maxDepth, int maxNodes, List<string> outJson) {
            if (node == null || depth > maxDepth || outJson.Count >= maxNodes) return;

            try {
                AutomationElement.AutomationElementInformation cur = node.Current;
                if (!cur.IsOffscreen && cur.IsEnabled) {
                    System.Windows.Rect rect = cur.BoundingRectangle;
                    if (!rect.IsEmpty && rect.Width >= 4 && rect.Height >= 4) {
                        ControlType ct = cur.ControlType;
                        string name = (cur.Name ?? "").Trim();
                        string aid = (cur.AutomationId ?? "").Trim();
                        if (IsInteractiveControlType(ct) || !string.IsNullOrEmpty(name)) {
                            if (IsInteractiveControlType(ct) || !string.IsNullOrEmpty(aid)) {
                                int x = (int)Math.Round(rect.Left);
                                int y = (int)Math.Round(rect.Top);
                                int w = (int)Math.Round(rect.Width);
                                int h = (int)Math.Round(rect.Height);
                                int cx = x + (w / 2);
                                int cy = y + (h / 2);
                                string typeShort = ct != null ? ct.ProgrammaticName.Replace("ControlType.", "") : "Unknown";
                                if (name.Length > 120) name = name.Substring(0, 120);
                                string entry = string.Format(
                                    "{{\"id\":{0},\"type\":\"{1}\",\"name\":\"{2}\",\"aid\":\"{3}\",\"cx\":{4},\"cy\":{5},\"rect\":[{6},{7},{8},{9}]}}",
                                    outJson.Count, JsonEsc(typeShort), JsonEsc(name), JsonEsc(aid), cx, cy, x, y, w, h
                                );
                                outJson.Add(entry);
                            }
                        }
                    }
                }
            } catch {}

            if (depth == maxDepth || outJson.Count >= maxNodes) return;

            try {
                TreeWalker walker = TreeWalker.ControlViewWalker;
                AutomationElement child = walker.GetFirstChild(node);
                int siblingGuard = 0;
                while (child != null && outJson.Count < maxNodes && siblingGuard < 80) {
                    CollectUiaElements(child, depth + 1, maxDepth, maxNodes, outJson);
                    child = walker.GetNextSibling(child);
                    siblingGuard++;
                }
            } catch {}
        }

        private static void MoveCursorAbsolute(int x, int y) {
            int vLeft = Native.GetSystemMetrics(Native.SM_XVIRTUALSCREEN);
            int vTop = Native.GetSystemMetrics(Native.SM_YVIRTUALSCREEN);
            int vWidth = Native.GetSystemMetrics(Native.SM_CXVIRTUALSCREEN);
            int vHeight = Native.GetSystemMetrics(Native.SM_CYVIRTUALSCREEN);
            if (vWidth <= 1) vWidth = Screen.PrimaryScreen.Bounds.Width;
            if (vHeight <= 1) vHeight = Screen.PrimaryScreen.Bounds.Height;

            int absX = (int)Math.Round(((double)(x - vLeft) * 65535.0) / Math.Max(1, vWidth - 1));
            int absY = (int)Math.Round(((double)(y - vTop) * 65535.0) / Math.Max(1, vHeight - 1));

            Native.INPUT[] inp = new Native.INPUT[1];
            inp[0].type = Native.INPUT_MOUSE;
            inp[0].U.mi.dx = absX;
            inp[0].U.mi.dy = absY;
            inp[0].U.mi.dwFlags = Native.MOUSEEVENTF_MOVE | Native.MOUSEEVENTF_ABSOLUTE | Native.MOUSEEVENTF_VIRTUALDESK;
            Native.SendInput(1, inp, Marshal.SizeOf(typeof(Native.INPUT)));
            Native.SetCursorPos(x, y);
        }

        private static int CmdMouseMove(string[] args) {
            if (args.Length < 3) { PrintError("Usage: mouse_move <x> <y>"); return 1; }
            int x = int.Parse(args[1]);
            int y = int.Parse(args[2]);
            MoveCursorAbsolute(x, y);
            Console.WriteLine("{\"ok\":true,\"action\":\"mouse_move\",\"x\":" + x + ",\"y\":" + y + "}");
            return 0;
        }

        private static int CmdMouseClick(string[] args) {
            if (args.Length < 3) { PrintError("Usage: mouse_click <x> <y>"); return 1; }
            int x = int.Parse(args[1]);
            int y = int.Parse(args[2]);
            string button = GetArg(args, "--button", "left").ToLowerInvariant();
            int clicks = GetIntArg(args, "--clicks", 1);
            if (clicks < 1) clicks = 1;
            if (clicks > 3) clicks = 3;

            uint downFlag = Native.MOUSEEVENTF_LEFTDOWN;
            uint upFlag = Native.MOUSEEVENTF_LEFTUP;
            if (button == "right") { downFlag = Native.MOUSEEVENTF_RIGHTDOWN; upFlag = Native.MOUSEEVENTF_RIGHTUP; }
            else if (button == "middle") { downFlag = Native.MOUSEEVENTF_MIDDLEDOWN; upFlag = Native.MOUSEEVENTF_MIDDLEUP; }

            MoveCursorAbsolute(x, y);
            Thread.Sleep(25);

            for (int c = 0; c < clicks; c++) {
                Native.INPUT[] inp = new Native.INPUT[2];
                inp[0].type = Native.INPUT_MOUSE;
                inp[0].U.mi.dwFlags = downFlag;
                inp[1].type = Native.INPUT_MOUSE;
                inp[1].U.mi.dwFlags = upFlag;
                Native.SendInput(2, inp, Marshal.SizeOf(typeof(Native.INPUT)));
                if (c + 1 < clicks) Thread.Sleep(40);
            }
            Console.WriteLine("{\"ok\":true,\"action\":\"mouse_click\",\"x\":" + x + ",\"y\":" + y + ",\"button\":\"" + JsonEsc(button) + "\",\"clicks\":" + clicks + "}");
            return 0;
        }

        private static int CmdMouseDrag(string[] args) {
            if (args.Length < 5) { PrintError("Usage: mouse_drag <x1> <y1> <x2> <y2>"); return 1; }
            int x1 = int.Parse(args[1]);
            int y1 = int.Parse(args[2]);
            int x2 = int.Parse(args[3]);
            int y2 = int.Parse(args[4]);

            MoveCursorAbsolute(x1, y1);
            Thread.Sleep(30);
            Native.INPUT[] down = new Native.INPUT[1];
            down[0].type = Native.INPUT_MOUSE;
            down[0].U.mi.dwFlags = Native.MOUSEEVENTF_LEFTDOWN;
            Native.SendInput(1, down, Marshal.SizeOf(typeof(Native.INPUT)));
            Thread.Sleep(40);

            int steps = 10;
            for (int i = 1; i <= steps; i++) {
                int ix = x1 + ((x2 - x1) * i) / steps;
                int iy = y1 + ((y2 - y1) * i) / steps;
                MoveCursorAbsolute(ix, iy);
                Thread.Sleep(15);
            }

            Native.INPUT[] up = new Native.INPUT[1];
            up[0].type = Native.INPUT_MOUSE;
            up[0].U.mi.dwFlags = Native.MOUSEEVENTF_LEFTUP;
            Native.SendInput(1, up, Marshal.SizeOf(typeof(Native.INPUT)));
            Console.WriteLine("{\"ok\":true,\"action\":\"mouse_drag\"}");
            return 0;
        }

        private static int CmdMouseScroll(string[] args) {
            if (args.Length < 4) { PrintError("Usage: mouse_scroll <x> <y> <delta>"); return 1; }
            int x = int.Parse(args[1]);
            int y = int.Parse(args[2]);
            int delta = int.Parse(args[3]);
            MoveCursorAbsolute(x, y);
            Thread.Sleep(20);
            Native.INPUT[] inp = new Native.INPUT[1];
            inp[0].type = Native.INPUT_MOUSE;
            inp[0].U.mi.dwFlags = Native.MOUSEEVENTF_WHEEL;
            inp[0].U.mi.mouseData = unchecked((uint)(delta * 120));
            Native.SendInput(1, inp, Marshal.SizeOf(typeof(Native.INPUT)));
            Console.WriteLine("{\"ok\":true,\"action\":\"mouse_scroll\",\"delta\":" + delta + "}");
            return 0;
        }

        private static int CmdKeyPress(string[] args) {
            if (args.Length < 2) { PrintError("Usage: key_press <key>"); return 1; }
            string key = args[1].Trim();
            ushort vk;
            if (!KeyMap.TryGetValue(key, out vk)) {
                PrintError("Unsupported key: " + key);
                return 1;
            }
            Native.INPUT[] inp = new Native.INPUT[2];
            inp[0].type = Native.INPUT_KEYBOARD;
            inp[0].U.ki.wVk = vk;
            inp[1].type = Native.INPUT_KEYBOARD;
            inp[1].U.ki.wVk = vk;
            inp[1].U.ki.dwFlags = Native.KEYEVENTF_KEYUP;
            Native.SendInput(2, inp, Marshal.SizeOf(typeof(Native.INPUT)));
            Console.WriteLine("{\"ok\":true,\"action\":\"key_press\",\"key\":\"" + JsonEsc(key) + "\"}");
            return 0;
        }

        private static int CmdHotkey(string[] args) {
            if (args.Length < 2) { PrintError("Usage: hotkey <mod+key>"); return 1; }
            string[] parts = args[1].Split(new char[] { '+' }, StringSplitOptions.RemoveEmptyEntries);
            List<ushort> vks = new List<ushort>();
            foreach (string p in parts) {
                ushort vk;
                if (!KeyMap.TryGetValue(p.Trim(), out vk)) {
                    PrintError("Unsupported hotkey token: " + p);
                    return 1;
                }
                vks.Add(vk);
            }
            if (vks.Count == 0) { PrintError("Empty hotkey"); return 1; }

            List<Native.INPUT> seq = new List<Native.INPUT>();
            for (int i = 0; i < vks.Count; i++) {
                Native.INPUT d = new Native.INPUT();
                d.type = Native.INPUT_KEYBOARD;
                d.U.ki.wVk = vks[i];
                seq.Add(d);
            }
            for (int i = vks.Count - 1; i >= 0; i--) {
                Native.INPUT u = new Native.INPUT();
                u.type = Native.INPUT_KEYBOARD;
                u.U.ki.wVk = vks[i];
                u.U.ki.dwFlags = Native.KEYEVENTF_KEYUP;
                seq.Add(u);
            }
            Native.INPUT[] arr = seq.ToArray();
            Native.SendInput((uint)arr.Length, arr, Marshal.SizeOf(typeof(Native.INPUT)));
            Console.WriteLine("{\"ok\":true,\"action\":\"hotkey\",\"keys\":\"" + JsonEsc(args[1]) + "\"}");
            return 0;
        }

        private static int CmdTypeText(string[] args) {
            string b64 = GetArg(args, "--b64", "");
            if (string.IsNullOrEmpty(b64)) {
                PrintError("Usage: type_text --b64 <base64_utf8>");
                return 1;
            }
            string text = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
            List<Native.INPUT> seq = new List<Native.INPUT>(text.Length * 2);
            for (int i = 0; i < text.Length; i++) {
                char ch = text[i];
                if (ch == '\r') continue;
                if (ch == '\n') {
                    Native.INPUT d = new Native.INPUT();
                    d.type = Native.INPUT_KEYBOARD;
                    d.U.ki.wVk = 0x0D;
                    Native.INPUT u = new Native.INPUT();
                    u.type = Native.INPUT_KEYBOARD;
                    u.U.ki.wVk = 0x0D;
                    u.U.ki.dwFlags = Native.KEYEVENTF_KEYUP;
                    seq.Add(d);
                    seq.Add(u);
                } else {
                    Native.INPUT d = new Native.INPUT();
                    d.type = Native.INPUT_KEYBOARD;
                    d.U.ki.wScan = (ushort)ch;
                    d.U.ki.dwFlags = Native.KEYEVENTF_UNICODE;
                    Native.INPUT u = new Native.INPUT();
                    u.type = Native.INPUT_KEYBOARD;
                    u.U.ki.wScan = (ushort)ch;
                    u.U.ki.dwFlags = Native.KEYEVENTF_UNICODE | Native.KEYEVENTF_KEYUP;
                    seq.Add(d);
                    seq.Add(u);
                }
            }
            if (seq.Count > 0) {
                Native.INPUT[] arr = seq.ToArray();
                Native.SendInput((uint)arr.Length, arr, Marshal.SizeOf(typeof(Native.INPUT)));
            }
            Console.WriteLine("{\"ok\":true,\"action\":\"type_text\",\"chars\":" + text.Length + "}");
            return 0;
        }

        private static int CmdFocusWindow(string[] args) {
            if (args.Length < 2) { PrintError("Usage: focus_window <title_or_process>"); return 1; }
            string query = args[1].Trim().ToLowerInvariant();
            IntPtr fgHwnd = Native.GetForegroundWindow();
            List<WindowInfo> windows = EnumerateVisibleWindows(fgHwnd);
            WindowInfo match = null;
            foreach (WindowInfo wi in windows) {
                if ((wi.Title ?? "").ToLowerInvariant().Contains(query) ||
                    (wi.Process ?? "").ToLowerInvariant().Contains(query)) {
                    match = wi;
                    break;
                }
            }
            if (match == null) {
                PrintError("No visible window matched: " + args[1]);
                return 1;
            }

            IntPtr target = new IntPtr(match.Hwnd);
            if (Native.IsIconic(target)) {
                Native.ShowWindow(target, Native.SW_RESTORE);
            } else {
                Native.ShowWindow(target, Native.SW_SHOW);
            }
            uint fgPid;
            uint fgThread = Native.GetWindowThreadProcessId(fgHwnd, out fgPid);
            uint curThread = Native.GetCurrentThreadId();
            if (fgThread != 0 && fgThread != curThread) {
                Native.AttachThreadInput(curThread, fgThread, true);
                Native.SetForegroundWindow(target);
                Native.AttachThreadInput(curThread, fgThread, false);
            } else {
                Native.SetForegroundWindow(target);
            }
            Console.WriteLine("{\"ok\":true,\"action\":\"focus_window\",\"hwnd\":" + match.Hwnd + ",\"title\":\"" + JsonEsc(match.Title) + "\"}");
            return 0;
        }

        private static AutomationElement FindElementByQuery(IntPtr hwnd, string query) {
            AutomationElement root = AutomationElement.FromHandle(hwnd);
            if (root == null) return null;
            string qLower = query.ToLowerInvariant();
            AutomationElement found = null;
            Queue<AutomationElement> queue = new Queue<AutomationElement>();
            queue.Enqueue(root);
            int visited = 0;
            TreeWalker walker = TreeWalker.ControlViewWalker;
            while (queue.Count > 0 && visited < 400) {
                AutomationElement cur = queue.Dequeue();
                visited++;
                try {
                    string name = (cur.Current.Name ?? "").Trim();
                    string aid = (cur.Current.AutomationId ?? "").Trim();
                    if ((!string.IsNullOrEmpty(name) && name.ToLowerInvariant().Contains(qLower)) ||
                        (!string.IsNullOrEmpty(aid) && aid.ToLowerInvariant() == qLower)) {
                        found = cur;
                        break;
                    }
                    AutomationElement child = walker.GetFirstChild(cur);
                    int c = 0;
                    while (child != null && c < 80) {
                        queue.Enqueue(child);
                        child = walker.GetNextSibling(child);
                        c++;
                    }
                } catch {}
            }
            return found;
        }

        private static int CmdUiaClick(string[] args) {
            if (args.Length < 2) { PrintError("Usage: uia_click <name_or_aid> [--hwnd <int>]"); return 1; }
            string query = args[1];
            int hwndInt = GetIntArg(args, "--hwnd", 0);
            IntPtr hwnd = hwndInt != 0 ? new IntPtr(hwndInt) : Native.GetForegroundWindow();
            AutomationElement el = FindElementByQuery(hwnd, query);
            if (el == null) { PrintError("UIA element not found: " + query); return 1; }

            object patObj;
            if (el.TryGetCurrentPattern(InvokePattern.Pattern, out patObj)) {
                ((InvokePattern)patObj).Invoke();
                Console.WriteLine("{\"ok\":true,\"action\":\"uia_click\",\"method\":\"invoke\",\"name\":\"" + JsonEsc(el.Current.Name) + "\"}");
                return 0;
            }
            System.Windows.Rect rect = el.Current.BoundingRectangle;
            if (!rect.IsEmpty) {
                int cx = (int)Math.Round(rect.Left + rect.Width / 2.0);
                int cy = (int)Math.Round(rect.Top + rect.Height / 2.0);
                return CmdMouseClick(new string[] { "mouse_click", cx.ToString(), cy.ToString() });
            }
            PrintError("UIA element has no InvokePattern or BoundingRectangle");
            return 1;
        }

        private static int CmdUiaSetText(string[] args) {
            if (args.Length < 2) { PrintError("Usage: uia_set_text <name_or_aid> --b64 <b64> [--hwnd <int>]"); return 1; }
            string query = args[1];
            string b64 = GetArg(args, "--b64", "");
            int hwndInt = GetIntArg(args, "--hwnd", 0);
            IntPtr hwnd = hwndInt != 0 ? new IntPtr(hwndInt) : Native.GetForegroundWindow();
            string text = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
            AutomationElement el = FindElementByQuery(hwnd, query);
            if (el == null) { PrintError("UIA element not found: " + query); return 1; }

            object patObj;
            if (el.TryGetCurrentPattern(ValuePattern.Pattern, out patObj)) {
                ((ValuePattern)patObj).SetValue(text);
                Console.WriteLine("{\"ok\":true,\"action\":\"uia_set_text\",\"method\":\"value_pattern\"}");
                return 0;
            }
            try { el.SetFocus(); } catch {}
            return CmdTypeText(new string[] { "type_text", "--b64", b64 });
        }

        private static int CmdScreenshot(string[] args) {
            string outPath = GetArg(args, "--out", "");
            int maxWidth = GetIntArg(args, "--max-width", 1280);

            int vLeft = Native.GetSystemMetrics(Native.SM_XVIRTUALSCREEN);
            int vTop = Native.GetSystemMetrics(Native.SM_YVIRTUALSCREEN);
            int vWidth = Native.GetSystemMetrics(Native.SM_CXVIRTUALSCREEN);
            int vHeight = Native.GetSystemMetrics(Native.SM_CYVIRTUALSCREEN);
            if (vWidth <= 0) vWidth = Screen.PrimaryScreen.Bounds.Width;
            if (vHeight <= 0) vHeight = Screen.PrimaryScreen.Bounds.Height;

            using (Bitmap rawBmp = new Bitmap(vWidth, vHeight, PixelFormat.Format24bppRgb)) {
                using (Graphics g = Graphics.FromImage(rawBmp)) {
                    g.CopyFromScreen(vLeft, vTop, 0, 0, new Size(vWidth, vHeight), CopyPixelOperation.SourceCopy);
                }

                Bitmap finalBmp = rawBmp;
                Bitmap scaledBmp = null;
                try {
                    if (maxWidth > 0 && vWidth > maxWidth) {
                        int newW = maxWidth;
                        int newH = (int)Math.Round(((double)vHeight * newW) / vWidth);
                        scaledBmp = new Bitmap(newW, newH);
                        using (Graphics sg = Graphics.FromImage(scaledBmp)) {
                            sg.InterpolationMode = InterpolationMode.HighQualityBicubic;
                            sg.DrawImage(rawBmp, 0, 0, newW, newH);
                        }
                        finalBmp = scaledBmp;
                    }

                    if (!string.IsNullOrEmpty(outPath)) {
                        string dir = Path.GetDirectoryName(outPath);
                        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
                        finalBmp.Save(outPath, ImageFormat.Png);
                        Console.WriteLine("{\"ok\":true,\"width\":" + finalBmp.Width + ",\"height\":" + finalBmp.Height + ",\"orig_width\":" + vWidth + ",\"orig_height\":" + vHeight + ",\"path\":\"" + JsonEsc(outPath) + "\"}");
                    } else {
                        using (MemoryStream ms = new MemoryStream()) {
                            finalBmp.Save(ms, ImageFormat.Png);
                            string b64 = Convert.ToBase64String(ms.ToArray());
                            Console.WriteLine("{\"ok\":true,\"width\":" + finalBmp.Width + ",\"height\":" + finalBmp.Height + ",\"orig_width\":" + vWidth + ",\"orig_height\":" + vHeight + ",\"base64\":\"" + b64 + "\"}");
                        }
                    }
                } finally {
                    if (scaledBmp != null) scaledBmp.Dispose();
                }
            }
            return 0;
        }
    }
}
