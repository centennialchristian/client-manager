using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class ProcessAsUser {
  private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
  private const int CREATE_NO_WINDOW = 0x08000000;
  private const int WINDOW_HIDE = 0;

  private IntPtr hUserToken = IntPtr.Zero;
  private IntPtr phEnvironment = IntPtr.Zero;

  private PROCESS_INFORMATION ProcessInfo = PROCESS_INFORMATION();

  public ProcessAsUser(int SessionId, string CommandLine, string WorkingDir, TimeSpan Timeout) {
    
    if (!WTSQueryUserToken(SessionId, ref hUserToken)) {
      throw new Exception("Unable to acquire user token from SessionId '"+SessionId.ToString()+'"');
    }

    STARTUPINFO startInfo = STARTUPINFO();
    startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
    startInfo.wShowWindow = WINDOW_HIDE;

    if (!CreateProcessAsUserA(
      hUserToken,
      IntPtr.Zero, // Application Name
      CommandLine, // Command Line
      IntPtr.Zero,
      IntPtr.Zero,
      false,
      CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
      phEnvironment,
      WorkingDir, // Working directory
      ref startInfo,
      out ProcessInfo
    )) {
      CloseHandle(hUserToken);
      throw new Exception("Failed to create process as user for SessionId '"+SessionId.ToString()+"'. Error code = "+Marshal.GetLastWin32Error());
    }
    try {
      
    } finally {
      if (hUserToken != IntPtr.Zero) {
        CloseHandle(hUserToken);
      }
      if (hProcEnv != IntPtr.Zero) {
        CloseHandle(hProcEnv);
      }
      if (procInfo.hThread != IntPtr.Zero) {
        CloseHandle(procInfo.hThread);
      }
      if (procInfo.hProcess != IntPtr.Zero) {
        CloseHandle(procInfo.hProcess);
      }
    }

  }

  [StructLayout(LayoutKind.Sequential)]
  private struct PROCESS_INFORMATION {
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
  }

  private enum SECURITY_IMPERSONATION_LEVEL {
    SecurityAnonymous = 0,
    SecurityIdentification = 1,
    SecurityImpersonation = 2,
    SecurityDelegation = 3,
  }

  [StructLayout(LayoutKind.Sequential)]
  private struct SECURITY_ATTRIBUTES {
      public int nLength;
      public IntPtr lpSecurityDescriptor;
      public int bInheritHandle;
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  private struct STARTUPINFO {
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

  private enum TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation = 2
  }

  [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
  private extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

  [DllImport("kernel32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private extern bool CloseHandle(IntPtr hObject);

  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  private extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, IntPtr lpSECURITY_ATTRIBUTES, uint nSize);
  
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  private extern bool CreateProcessAsUserA(
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

  [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

  [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
  private extern bool DuplicateTokenEx(
    IntPtr ExistingTokenHandle,
    uint dwDesiredAccess,
    IntPtr lpThreadAttributes,
    int TokenType,
    int ImpersonationLevel,
    ref IntPtr DuplicateTokenHandle
  );

  [DllImport("Wtsapi32.dll")]
  private extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

}