using ClientManager;
using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

void main() {
  // string testCmdString = "Write-Output $env:USERPROFILE";
  // string testCmdB64 = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(testCmdString));
  // string CommandLine = "C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe -NoLogo -NonInteractive -ExecutionPolicy ByPass -WindowStyle Hidden -EncodedCommand "+testCmdB64;
  string CommandLine = "C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe -NoLogo -NonInteractive -ExecutionPolicy ByPass -WindowStyle Hidden -Command \"Write-Output $env:USERPROFILE\"";

  string WorkingDir = "C:\\Users\\2975\\AppData\\Local";
  Process[] explorerProcs = Process.GetProcessesByName("explorer");
  if (explorerProcs.Length > 0) {
    
    try {
      using (ClientManager.ProcessAsUser UserProc = new ClientManager.ProcessAsUser(explorerProcs[0].SessionId,CommandLine,WorkingDir)) {

        // TimeSpan timeout = new TimeSpan(0,0,2);
        int timeout = 2000;
        Console.WriteLine("Going to wait for the process to exit");
        if (!UserProc.WaitForProcess(timeout)) {
          Console.WriteLine("Timed out waiting for command to finish.");
          UserProc.TerminateProcess();
          UserProc.Dispose();
        }

        string? stdout = UserProc.GetStdout();
        string? stderr = UserProc.GetStderr();

        if (stdout != null) {
          Console.WriteLine("Standard Out:\n"+stdout+"\n");
        } else {
          Console.WriteLine("Standard Out was null");
        }

        if (stderr != null) {
          Console.WriteLine("Standard Error:\n"+stderr+"\n");
        } else {
          Console.WriteLine("Standard Error was null");
        }
        UserProc.Dispose();
      }
    } catch (Exception ex) {
      Console.WriteLine("unable to start process: "+ex.Message);
      return;
    }
  } else {
    Console.WriteLine("Did not find any process with name of 'explorer'");
  }
}

main();

namespace ClientManager {

  [StructLayout(LayoutKind.Sequential)]
  struct PROCESS_INFORMATION {
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
  }

  enum SECURITY_IMPERSONATION_LEVEL : int {
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

  enum TOKEN_ACCESS_LEVEL : int {
    AssignPrimary = 0x00000001,
    Duplicate = 0x00000002,
    Impersonate = 0x00000004,
    Query = 0x00000008,
    QuerySource = 0x00000010,
    AdjustPrivileges = 0x00000020,
    AdjustGroups = 0x00000040,
    AdjustDefault = 0x00000080,
    AdjustSessionId = 0x00000100,
    Read = 0x00020000 | Query,
    Write = 0x00020000 | AdjustPrivileges | AdjustGroups | AdjustDefault,
    AllAccess = 0x000F0000|AssignPrimary|Duplicate|Impersonate|Query|QuerySource|AdjustPrivileges|AdjustGroups|AdjustDefault|AdjustSessionId,
    MaximumAllowed = 0x02000000
  }

  enum TOKEN_TYPE : int {
    TokenPrimary = 1,
    TokenImpersonation = 2
  }

  public class ProcessAsUser : IDisposable {
    private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const int CREATE_NO_WINDOW = 0x08000000;
    private const int LOGON_WITH_PROFILE = 0x00000001;
    private const int STARTF_USESTDHANDLES = 0x00000100;
    private const int STARTF_USESHOWWINDOW = 0x00000001;
    private const int STILL_ACTIVE = 259;
    private const int WINDOW_HIDE = 0;

    private PROCESS_INFORMATION ProcessInfo;

    private IntPtr hAccessToken;
    private IntPtr hStdoutPipeRead;
    private IntPtr hStdoutPipeWrite;
    private IntPtr hStderrPipeRead;
    private IntPtr hStderrPipeWrite;

    ~ProcessAsUser() {
      Dispose();
    }

    public ProcessAsUser(int SessionId, string CommandLine, string WorkingDir) {
      uint sessId = (uint) SessionId;
      
      IntPtr hImpersonateToken;
      if (!Win32Native.WTSQueryUserToken(sessId, out hImpersonateToken)) {
        throw new Exception("Unable to acquire user token from SessionId '"+SessionId.ToString()+"'. Error code "+Marshal.GetLastWin32Error());
      }

      SECURITY_ATTRIBUTES duplicateTokenAttrs =  new SECURITY_ATTRIBUTES();
      duplicateTokenAttrs.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
      bool dupTokenSuccess = Win32Native.DuplicateTokenEx(
        hImpersonateToken,
        (int)(TOKEN_ACCESS_LEVEL.Query | TOKEN_ACCESS_LEVEL.Duplicate | TOKEN_ACCESS_LEVEL.AssignPrimary | TOKEN_ACCESS_LEVEL.Impersonate),
        duplicateTokenAttrs,
        (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
        (int)TOKEN_TYPE.TokenPrimary,
        out this.hAccessToken
      );
      int dupTokenWin32Error = Marshal.GetLastWin32Error();
      Win32Native.CloseHandle(hImpersonateToken);
      if (!dupTokenSuccess) {
        throw new Exception("Unable to create a primary user token. Error code = "+dupTokenWin32Error.ToString());
      }

      if (!Win32Native.CreatePipe(out this.hStdoutPipeRead, out this.hStdoutPipeWrite, IntPtr.Zero, 0)) {
        int lastWin32Error = Marshal.GetLastWin32Error();
        Win32Native.CloseHandle(this.hAccessToken);
        throw new Exception("Unable to create Pipe for stdout. Error code = "+lastWin32Error.ToString());
      }

      if (!Win32Native.CreatePipe(out this.hStderrPipeRead, out this.hStderrPipeWrite, IntPtr.Zero, 0)) {
        int lastWin32Error = Marshal.GetLastWin32Error();
        Win32Native.CloseHandle(this.hAccessToken);
        Win32Native.CloseHandle(this.hStdoutPipeRead);
        Win32Native.CloseHandle(this.hStdoutPipeWrite);
        throw new Exception("Unable to create Pipe for stderr. Error code = "+lastWin32Error.ToString());
      }

      STARTUPINFO ProcStartInfo = new STARTUPINFO();

      ProcStartInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
      ProcStartInfo.wShowWindow = WINDOW_HIDE;
      ProcStartInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
      ProcStartInfo.hStdOutput = this.hStdoutPipeWrite;
      ProcStartInfo.hStdError = this.hStderrPipeWrite;

      IntPtr hEnvironment;
      if (!Win32Native.CreateEnvironmentBlock(out hEnvironment, this.hAccessToken, false)) {
        int lastWin32Error = Marshal.GetLastWin32Error();
        Win32Native.CloseHandle(this.hAccessToken);
        Win32Native.CloseHandle(this.hStdoutPipeRead);
        Win32Native.CloseHandle(this.hStdoutPipeWrite);
        Win32Native.CloseHandle(this.hStderrPipeRead);
        Win32Native.CloseHandle(this.hStderrPipeWrite);
        throw new Exception("Unable to create environment block. Error code = "+lastWin32Error.ToString());
      }

      Console.WriteLine("CommandLine = "+CommandLine);
      // dwCreationFlags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
      bool procCreateSuccess = Win32Native.CreateProcessAsUserW(
        this.hAccessToken,
        null, // Application Name
        CommandLine, // Command Line
        IntPtr.Zero,
        IntPtr.Zero,
        false,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        hEnvironment,
        WorkingDir, // Working directory
        ref ProcStartInfo,
        out ProcessInfo
      );
      // bool procCreateSuccess = Win32Native.CreateProcessWithTokenW(
      //   hAccessToken,
      //   LOGON_WITH_PROFILE,
      //   null,
      //   CommandLine,
      //   CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
      //   this.hEnvironment,
      //   WorkingDir,
      //   ref ProcStartInfo,
      //   out this.ProcessInfo
      // );
      int createProcessWin32Err = Marshal.GetLastWin32Error();
      Win32Native.DestroyEnvironmentBlock(hEnvironment);
      Win32Native.CloseHandle(hEnvironment);
      if (!procCreateSuccess) {
        Win32Native.CloseHandle(this.hAccessToken);
        Win32Native.CloseHandle(this.hStdoutPipeWrite);
        Win32Native.CloseHandle(this.hStderrPipeWrite);
        Win32Native.CloseHandle(this.hStdoutPipeRead);
        Win32Native.CloseHandle(this.hStderrPipeRead);
        throw new Exception("Failed to create process as user for SessionId '"+SessionId.ToString()+"'. Error code = "+createProcessWin32Err.ToString());
      }
    }

    public void Dispose() {
      TerminateProcess();
      Win32Native.CloseHandle(hAccessToken);
      Win32Native.CloseHandle(hStderrPipeRead);
      Win32Native.CloseHandle(hStderrPipeWrite);
      Win32Native.CloseHandle(hStdoutPipeRead);
      Win32Native.CloseHandle(hStdoutPipeWrite);
      Win32Native.CloseHandle(ProcessInfo.hProcess);
      Win32Native.CloseHandle(ProcessInfo.hThread);
    }

    public string? GetStdout() {
      string? stdout;
      SafeFileHandle hStdout = new SafeFileHandle(this.hStdoutPipeRead, true);
      FileStream stdoutStream = new FileStream(hStdout,FileAccess.Read);
      if (stdoutStream != null) {
        StreamReader stdoutReader = new StreamReader(stdoutStream);
        if (stdoutReader != null) {
          if ((stdout = stdoutReader.ReadLine()) != null) {
            string? line;
            while ((line = stdoutReader.ReadLine()) != null) {
              stdout = stdout+"\n"+line;
            }
            return stdout;
          }
          stdoutReader.Close();
        } else {
          stdoutStream.Close();
        }
      }
      return null;
    }

    public string? GetStderr() {
      string? stderr;
      SafeFileHandle hStderr = new SafeFileHandle(this.hStderrPipeRead, true);
      FileStream stderrStream = new FileStream(hStderr,FileAccess.Read);
      if (stderrStream != null) {
        StreamReader stderrReader = new StreamReader(stderrStream);
        if (stderrReader != null) {
          if ((stderr = stderrReader.ReadLine()) != null) {
            string? line;
            while ((line = stderrReader.ReadLine()) != null) {
              stderr = stderr+"\n"+line;
            }
            return stderr;
          }
          stderrReader.Close();
        } else {
          stderrStream.Close();
        }
      }
      return null;
    }

    public int ProcessId {
      get {
        return (int) ProcessInfo.dwProcessId;
      }
    }

    public void TerminateProcess() {
      if (!this.CommandProcess.HasExited) {
        this.CommandProcess.Kill();
      }
    }

    public bool WaitForProcess(int Timeout) {

      int exitCode;
      if (!GetExitCodeThread(this.ProcessInfo.hThread, out exitCode)) {
        throw new Win32Exception("Error determining process status. Error code = "+Marshal.GetLastWin32Error());
      }

      int timer = 0;
      while (exitCode == STILL_ACTIVE && timer < Timeout) {
        Thread.Slep(1000);
        timer = timer + 1000;
        if (!GetExitCodeThread(this.ProcessInfo.hThread, out exitCode)) {
          throw new Win32Exception("Error determining process status. Error code = "+Marshal.GetLastWin32Error());
        }
      }

      if (timer < Timeout) {
        return true;
      }
      return false;
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
    public static extern bool CreateProcessAsUserW(
      IntPtr hToken,
      string? lpApplicationName,
      string lpCommandLine,
      IntPtr lpProcessAttributes,
      IntPtr lpThreadAttributes,
      bool bInheritHandles,
      int dwCreationFlags,
      IntPtr lpEnvironment,
      string lpCurrentDirectory,
      [In] ref STARTUPINFO lpStartupInfo,
      out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(
      IntPtr hToken,
      int dwLogonFlags,
      string? lpApplicationName,
      string lpCommandLine,
      int dwCreationFlags,
      IntPtr lpEnvironment,
      string lpCurrentDirectory,
      [In] ref STARTUPINFO lpStartupInfo,
      out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
    public static extern bool DuplicateTokenEx(
      IntPtr ExistingTokenHandle,
      int dwDesiredAccess,
      SECURITY_ATTRIBUTES lpThreadAttributes,
      int TokenType,
      int ImpersonationLevel,
      out IntPtr DuplicateTokenHandle
    );

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool GetExitCodeThread(IntPtr  hThread, out int lpExitCode);

    [DllImport("Wtsapi32.dll")]
    public static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

  }
}
