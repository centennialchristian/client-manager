using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class ProcessEx {

  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern bool CreateProcessAsUserA(
    IntPtr hToken,
    string lpApplicationName,
    string lpCommandLine,
    IntPtr lpProcessAttributes,
    IntPtr lpThreadAttributes,
    bool bInheritHandles,
    uint dwCreationFlags,
    IntPtr lpEnvironment,
    string lpCurrentDirectory,
    [In] ref STARTUPINFO lpStartupInfo,
    out PROCESS_INFORMATION lpProcessInformation
  );

  [StructLayout(LayoutKind.Sequential)]
  public struct PROCESS_INFORMATION {
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct SECURITY_ATTRIBUTES {
      public int nLength;
      public IntPtr lpSecurityDescriptor;
      public int bInheritHandle;
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct STARTUPINFO {
    public Int32 cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public Int32 dwX;
    public Int32 dwY;
    public Int32 dwXSize;
    public Int32 dwYSize;
    public Int32 dwXCountChars;
    public Int32 dwYCountChars;
    public Int32 dwFillAttribute;
    public Int32 dwFlags;
    public Int16 wShowWindow;
    public Int16 cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
  }

  [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
  public static extern bool DuplicateTokenEx(
    IntPtr ExistingTokenHandle,
    uint dwDesiredAccess,
    IntPtr lpThreadAttributes,
    int TokenType,
    int ImpersonationLevel,
    ref IntPtr DuplicateTokenHandle
  );

  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, IntPtr lpSECURITY_ATTRIBUTES, uint nSize);

  [DllImport("kernel32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool CloseHandle(IntPtr hObject);

  [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
  public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

  [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
  public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

  [DllImport("Wtsapi32.dll")]
  public static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

  public static bool StartProcessAsUser(int) {
    
  }
}