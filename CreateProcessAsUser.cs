using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace ClientManager {
  [StructLayout(LayoutKind.Sequential)]
  struct PROCESS_INFORMATION {
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
  }

  enum SECURITY_IMPERSONATION_LEVEL {
    SecurityAnonymous = 0,
    SecurityIdentification = 1,
    SecurityImpersonation = 2,
    SecurityDelegation = 3,
  }

  [StructLayout(LayoutKind.Sequential)]
  struct SECURITY_ATTRIBUTES {
    public int nLength;
    public IntPtr lpSecurityDescriptor;
    public int bInheritHandle;
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct STARTUPINFO {
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

  enum TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation = 2
  }

  public class SafeEnvHandle : SafeHandleZeroOrMinusOneIsInvalid {
    private SafeEnvHandle() : base(true) {}
    public SafeEnvHandle(IntPtr handle, bool ownHandle) : base(ownHandle) {
      this.SetHandle(handle);
    }
    protected override bool ReleaseHandle() {
      return Win32Native.CloseHandle(this.handle);
    }
  }

  public class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid {
    private SafeThreadHandle() : base(true) {}
    public SafeThreadHandle(IntPtr handle, bool ownHandle) : base(ownHandle) {
      this.SetHandle(handle);
    }
    protected override bool ReleaseHandle() {
      return Win32Native.CloseHandle(this.handle);
    }
  }

  public class ProcessAsUser : IDisposable {
    private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const int CREATE_NO_WINDOW = 0x08000000;
    private const int STARTF_USESTDHANDLES = 0x00000100;
    private const int STARTF_USESHOWWINDOW = 0x00000001;
    private const int WINDOW_HIDE = 0;

    private PROCESS_INFORMATION ProcessInfo;

    private SafeFileHandle StdoutReadHandle;
    private SafeFileHandle StderrReadHandle;
    private SafeProcessHandle UserProcessHandle;
    private SafeThreadHandle UserThreadHandle;

    ~ProcessAsUser() {
      Dispose();
    }

    public ProcessAsUser() {}

    public void Dispose() {
      if (!StderrReadHandle.IsClosed && !StderrReadHandle.IsInvalid) {
        StderrReadHandle.Close();
      }
      if (!StdoutReadHandle.IsClosed && !StdoutReadHandle.IsInvalid) {
        StdoutReadHandle.Close();
      }
      if (!UserProcessHandle.IsClosed && !UserProcessHandle.IsInvalid) {
        UserProcessHandle.Close();
      }
      if (!UserThreadHandle.IsClosed && !UserThreadHandle.IsInvalid) {
        UserThreadHandle.Close();
      }
    }

    public string GetStdout() {
      string stdout;
      FileStream stdoutStream = new FileStream(StdoutReadHandle,FileAccess.Read);
      StreamReader stdoutReader = new StreamReader(stdoutStream);
      if ((stdout = stdoutReader.ReadLine()) != null) {
        string line;
        while ((line = stdoutReader.ReadLine()) != null) {
          stdout = stdout+"\n"+line;
        }
      }
      stdoutReader.Close();
      return stdout;
    }

    public string GetStderr() {
      string stderr;
      FileStream stderrStream = new FileStream(StderrReadHandle,FileAccess.Read);
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

    public int ProcessId {
      get {
        return (int) ProcessInfo.dwProcessId;
      }
    }

    public void Start(int SessionId, string ProgramPath, string Arguments, string WorkingDir) {
      uint sessId = (uint) SessionId;
      
      IntPtr hImpersonateToken = new IntPtr.Zero;
      if (!Win32Native.WTSQueryUserToken(sessId, out hImpersonateToken)) {
        throw new Exception("Unable to acquire user token from SessionId '"+SessionId.ToString()+'"');
      }

      IntPtr hAccessToken = new IntPtr.Zero;
      bool dupTokenSuccess = Win32Native.DuplicateTokenEx(
        hImpersonateToken,
        0,
        IntPtr.Zero,
        (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
        (int)TOKEN_TYPE.TokenPrimary,
        out hAccessToken
      );
      Win32Native.CloseHandle(hImpersonateToken);
      if (!dupTokenSuccess) {
        throw new Exception("Unable to create a primary user token. Error code = "+Marshal.GetLastWin32Error());
      }
      IntPtr hStdoutPipeRead = IntPtr.Zero;
      IntPtr hStdoutPipeWrite = IntPtr.Zero;
      if (!Win32Native.CreatePipe(out hStdoutPipeRead, out hStdoutPipeWrite, IntPtr.Zero, 0)) {
        int lastWin32Error = Marshal.GetLastWin32Error();
        Win32Native.CloseHandle(hAccessToken);
        throw new Exception("Unable to create Pipe for stdout. Error code = "+lastWin32Error.ToString());
      }

      IntPtr hStderrPipeRead = IntPtr.Zero;
      IntPtr hStderrPipeWrite = IntPtr.Zero;
      if (!Win32Native.CreatePipe(out hStderrPipeRead, out hStderrPipeWrite, IntPtr.Zero, 0)) {
        int lastWin32Error = Marshal.GetLastWin32Error();
        Win32Native.CloseHandle(hAccessToken);
        Win32Native.CloseHandle(hStdoutPipeRead);
        Win32Native.CloseHandle(hStdoutPipeWrite);
        Dispose();
        throw new Exception("Unable to create Pipe for stderr. Error code = "+lastWin32Error.ToString());
      }

      STARTUPINFO ProcStartInfo = new STARTUPINFO();

      ProcStartInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
      ProcStartInfo.wShowWindow = WINDOW_HIDE;
      ProcStartInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESHOWWINDOW;
      ProcStartInfo.hStdOutput = hStdoutPipeWrite;
      ProcStartInfo.hStdError = hStderrPipeWrite;

      uint dwCreationFlags = (uint) (CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT);
      bool procCreateSuccess = Win32Native.CreateProcessAsUserA(
        hAccessToken,
        null, // Application Name
        CommandLine, // Command Line
        IntPtr.Zero,
        IntPtr.Zero,
        false,
        dwCreationFlags,
        IntPtr.Zero,
        WorkingDir, // Working directory
        ref ProcStartInfo,
        out ProcessInfo
      );
      Win32Native.CloseHandle(hStdoutPipeWrite);
      Win32Native.CloseHandle(hStderrPipeWrite);
      Win32Native.CloseHandle(hAccessToken);

      StdoutReadHandle = new SafeFileHandle(hStdoutPipeRead, true);
      StderrReadHandle = new SafeFileHandle(hStderrPipeRead, true);

      if (!procCreateSuccess) {
        int lastWin32Error = Marshal.GetLastWin32Error();
        Dispose();
        throw new Exception("Failed to create process as user for SessionId '"+SessionId.ToString()+"'. Error code = "+Marshal.GetLastWin32Error());
      }

      UserProcessHandle = new SafeProcessHandle(ProcessInfo.hProcess, true);
      UserThreadHandle = new SafeThreadHandle(ProcessInfo.hThread, true);
    }

    public void TerminateProcess() {
      try {
        Process proc = Process.GetProcessById(ProcessInfo.dwProcessId);
        if (!proc.HasExited) {
          proc.Kill();
        }
      } catch { }
    }
  }

  internal static class Win32Native {

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, IntPtr lpSECURITY_ATTRIBUTES, uint nSize);
    
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

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DestroyEnvironmentBlock(SafeEnvHandle lpEnvironment);

    [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
    public static extern bool DuplicateTokenEx(
      IntPtr ExistingTokenHandle,
      uint dwDesiredAccess,
      IntPtr lpThreadAttributes,
      int TokenType,
      int ImpersonationLevel,
      out IntPtr DuplicateTokenHandle
    );

    [DllImport("Wtsapi32.dll")]
    public static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

  }
}