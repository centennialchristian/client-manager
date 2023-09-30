using Microsoft.Win32.SafeHandles;
using System;
using System.DateTime;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Thread.

namespace DeviceManager {

  public class ProcessAsUser : IDisposable {
    private bool disposed = false;
    private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const int CREATE_NO_WINDOW = 0x08000000;
    private const int WINDOW_HIDE = 0;

    private IntPtr hUserToken = IntPtr.Zero;
    private IntPtr phEnvironment = IntPtr.Zero;

    private IntPtr hStdoutReadHandle = IntPtr.Zero;
    private IntPtr hStdoutWriteHandle = IntPtr.Zero;
    private IntPtr hStderrReadHandle = IntPtr.Zero;
    private IntPtr hStderrWriteHandle = IntPtr.Zero;

    private PROCESS_INFORMATION ProcessInfo = PROCESS_INFORMATION();
    private STARTUPINFO startInfo = STARTUPINFO();

    public int ProcessId {
      get {
        return ProcessInfo.dwProcessId;
      }
    }

    public Start(int SessionId, string CommandLine, string WorkingDir) {
      
      IntPtr hImpersonateToken = IntPtr.Zero;
      if (!WTSQueryUserToken(SessionId, ref hImpersonateToken)) {
        throw new Exception("Unable to acquire user token from SessionId '"+SessionId.ToString()+'"');
      }

      bool dupTokenSuccess = DuplicateTokenEx(
        hImpersonateToken,
        0,
        IntPtr.Zero,
        (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
        (int)TOKEN_TYPE.TokenPrimary,
        ref hUserToken
      );
      CloseHandle(hImpersonateToken);
      if (!dupTokenSuccess) {
        throw new Exception("Unable to create a primary user token. Error code = "+Marshal.GetLastWin32Error());
      }

      STARTUPINFO startInfo = STARTUPINFO();
      startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
      startInfo.wShowWindow = WINDOW_HIDE;
      
      if (!CreatePipe(out hStdoutReadHandle, out hStdoutWriteHandle, IntPtr.Zero, 0)) {
        CloseHandle(hUserToken);
        throw Exception("Unable to create Pipe for stdout. Error code = "+Marshal.GetLastWin32Error());
      }
      if (!CreatePipe(out hStderrReadHandle, out hStderrWriteHandle, IntPtr.Zero, 0)) {
        CloseHandle(hUserToken);
        throw Exception("Unable to create Pipe for stderr. Error code = "+Marshal.GetLastWin32Error());
      }

      startInfo.hStdOutput = hStdoutWriteHandle;
      startInfo.hStdError = hStderrWriteHandle;

      bool procCreateSuccess = CreateProcessAsUserA(
        hUserToken,
        IntPtr.Zero, // Application Name
        CommandLine, // Command Line
        IntPtr.Zero,
        IntPtr.Zero,
        false,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        IntPtr.Zero,
        WorkingDir, // Working directory
        ref startInfo,
        out ProcessInfo
      );
      if (!procCreateSuccess) {
        throw new Exception("Failed to create process as user for SessionId '"+SessionId.ToString()+"'. Error code = "+Marshal.GetLastWin32Error());
      }
    }

    public void Dispose() {
      Dispose(disposing: true);
    }

    protected virtual void Dispose(bool disposing) {
      if (ProcessInfo.hThread != IntPtr.Zero) {
        CloseHandle(ProcessInfo.hThread);
      }
      if (ProcessInfo.hProcess != IntPtr.Zero) {
        CloseHandle(ProcessInfo.hProcess);
      }
      if (hStderrReadHandle != IntPtr.Zero) {
        CloseHandle(hStderrReadHandle);
      }
      if (hStderrWriteHandle != IntPtr.Zero) {
        CloseHandle(hStderrWriteHandle);
      }
      if (hStdoutReadHandle != IntPtr.Zero) {
        CloseHandle(hStdoutReadHandle);
      }
      if (hStdoutWriteHandle != IntPtr.Zero) {
        CloseHandle(hStdoutWriteHandle);
      }
      if (hUserToken != IntPtr.Zero) {
        CloseHandle(hUserToken);
      }
    }

    public string GetStdout() {
      string stdout;
      FileStream stdoutStream = new FileStream(hStdoutReadHandle);
      StreamReader stdoutReader = new StreamReader(stdoutStream);
      if ((stdout = stdoutReader.ReadLine()) != null) {
        string line;
        while ((line = stdoutReader.ReadLine()) != null) {
          stdout = stdout+"\n"+line;
        }
      }
      return stdout;
    }

    public string GetStderr() {
      stdoutReader.Close();
      string stderr;
      FileStream stderrStream = new FileStream(hStderrReadHandle);
      StreamReader stderrReader = new StreamReader(stderrStream);
      if ((stderr = stderrReader.ReadLine()) != null) {
        string line;
        while ((line = stderrReader.ReadLine()) != null) {
          stderr = stderr+"\n"+line;
        }
      }
      stderrReader.Close();
      return stderr;
    }

    public void TerminateProcess() {
    try {
      Process proc = GetProcessById(ProcessInfo.dwProcessId);
      if (!proc.HasExited) {
        proc.Kill();
      }
    } catch { }
    }
  }

  internal static class Win32Native {

    public static class SafeEnvHandle : SafeHandleZeroOrMinusOneIsInvalid {
      private SafeEnvHandle() {} : base(true);
      public SafeEnvHandle(IntPtr handle): base(true) {
        this.SetHandle(handle);
      }
      public SafeEnvHandle(IntPtr handle, bool ownHandle) : base(ownHandle) {
        this.SetHandle(handle);
      }

      protected override bool ReleaseHandle() {
        return Win32Native.CloseHandle(this.handle);
      }
    }

    [StructLayout(LayoutKind.Sequential)]
    public static struct PROCESS_INFORMATION {
      public IntPtr hProcess;
      public IntPtr hThread;
      public int dwProcessId;
      public int dwThreadId;
    }

    public static enum SECURITY_IMPERSONATION_LEVEL {
      SecurityAnonymous = 0,
      SecurityIdentification = 1,
      SecurityImpersonation = 2,
      SecurityDelegation = 3,
    }

    [StructLayout(LayoutKind.Sequential)]
    public static struct SECURITY_ATTRIBUTES {
      public int nLength;
      public IntPtr lpSecurityDescriptor;
      public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public static struct STARTUPINFO {
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
      public intPtr hStdError;
    }

    public static enum TOKEN_TYPE {
      TokenPrimary = 1,
      TokenImpersonation = 2
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CreateEnvironmentBlock(out Win32Native.SafeEnvHandle lpEnvironment, SafeAccessTokenHandle hToken, bool bInherit);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreatePipe(out Win32Native.SafeHandle hReadPipe, out Win32Native.SafeHandle hWritePipe, IntPtr lpSECURITY_ATTRIBUTES, uint nSize);
    
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessAsUserA(
      Win32Native.SafeHandle hToken,
      string lpApplicationName,
      string lpCommandLine,
      IntPtr lpProcessAttributes,
      IntPtr lpThreadAttributes,
      bool bInheritHandles,
      uint dwCreationFlags,
      Win32Native.SafeHandle lpEnvironment,
      string lpCurrentDirectory,
      [In] ref STARTUPINFO lpStartupInfo,
      out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
    public static extern bool DuplicateTokenEx(
      Win32Native.SafeHandle ExistingTokenHandle,
      uint dwDesiredAccess,
      IntPtr lpThreadAttributes,
      int TokenType,
      int ImpersonationLevel,
      ref Win32Native.SafeHandle DuplicateTokenHandle
    );

    [DllImport("Wtsapi32.dll")]
    public static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

  }
}