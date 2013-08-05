#include <Windows.h>

#include <stdio.h>

#include <Psapi.h>
#include <Shlwapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

#pragma warning(disable : 4311)
#pragma warning(disable : 4312)

const CHAR v_szTarget[] = "Diablo II.exe";
const CHAR v_szModule[] = "Demo.dll";

BYTE v_iModuleAction[] = {
  0x68, 0x00, 0x00, 0x00, 0x00, // PUSH dwReturnAddress

  0x60,                         // PUSHAD
  0x9C,                         // PUSHFD

  0x68, 0x00, 0x00, 0x00, 0x00, // PUSH pRemotePath
  0xB8, 0x00, 0x00, 0x00, 0x00, // MOV EAX, dwRemoteAddress (LoadLibraryA or FreeLibrary)

  0xFF, 0xD0,                   // CALL EAX

  0x9D,                         // POPFD
  0x61,                         // POPAD

  0xC3                          // RET
};

HMODULE GetWindowModuleHandle(HWND hWnd, LPCSTR szModuleName)
{
  HMODULE hModule[1024];

  DWORD dwSize = NULL;
  DWORD dwProcessID = NULL;

  CHAR szPath[MAX_PATH] = "";

  ::GetWindowThreadProcessId(hWnd, &dwProcessID);

  HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessID);

  if (!hProcess)
    return NULL;

  ::EnumProcessModules(hProcess, hModule, 1024, &dwSize);

  for (UINT i = 0; i < dwSize / sizeof(HMODULE); i++)
  {
    ::GetModuleFileNameEx(hProcess, hModule[i], szPath, MAX_PATH);
    ::PathStripPath(szPath);

    if (!::_stricmp(szPath, szModuleName))
      return hModule[i];
  }

  return NULL;
}

BOOL SetPrivilege()
{
  HANDLE hToken;
  LUID LocalUniqueIdentifier;
  TOKEN_PRIVILEGES TokenPrivileges;

  if (!::OpenProcessToken(::GetCurrentProcess(), (TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES), &hToken))
    return FALSE;

  if (!::LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &LocalUniqueIdentifier))
  {
    ::CloseHandle(hToken);
    return FALSE;
  }

  TokenPrivileges.PrivilegeCount = 1;
  TokenPrivileges.Privileges[0].Luid = LocalUniqueIdentifier;
  TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!::AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
  {
    ::CloseHandle(hToken);
    return FALSE;
  }

  ::CloseHandle(hToken);

  return TRUE;
}

BOOL main(INT argc, LPSTR* argv)
{
  CONTEXT Context;

  CHAR szDirectory[MAX_PATH] = "";
  CHAR szModulePath[MAX_PATH] = "";

  DWORD dwProcessID = NULL;
  DWORD dwRemoteAddress = NULL;
  DWORD dwOldProtect = NULL;

  if (!SetPrivilege())
    return EXIT_FAILURE;

  HWND hWnd = ::FindWindow("Diablo II", "Diablo II");

  if (!hWnd)
    return EXIT_FAILURE;

  ::GetCurrentDirectory(MAX_PATH, szDirectory);
  ::sprintf_s(szModulePath, MAX_PATH, "%s\\%s", szDirectory, v_szModule);

  HANDLE hFile = ::CreateFile(szModulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);

  if (hFile == INVALID_HANDLE_VALUE)
    return EXIT_FAILURE;

  DWORD dwThreadID = ::GetWindowThreadProcessId(hWnd, &dwProcessID);
  HANDLE hProcess = ::OpenProcess((PROCESS_VM_WRITE | PROCESS_VM_OPERATION), FALSE, dwProcessID);
  HANDLE hProcessThread = ::OpenThread((THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT), FALSE, dwThreadID);

  HMODULE hKernel = ::GetModuleHandle("kernel32.dll");
  HMODULE hRemoteModule = GetWindowModuleHandle(hWnd, v_szModule);

  if (!hRemoteModule)
    dwRemoteAddress = (DWORD)::GetProcAddress(hKernel, "LoadLibraryA");
  else
    dwRemoteAddress = (DWORD)::GetProcAddress(hKernel, "FreeLibrary");

  LPVOID pRemotePath = ::VirtualAllocEx(hProcess, NULL, ::strlen(szModulePath) + 1, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
  LPVOID pRemoteStub = ::VirtualAllocEx(hProcess, NULL, sizeof(v_iModuleAction), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

  ::SuspendThread(hProcessThread);

  Context.ContextFlags = CONTEXT_CONTROL;
  ::GetThreadContext(hProcessThread, &Context);

  *(LPDWORD)&v_iModuleAction[1] = Context.Eip;
  *(LPDWORD)&v_iModuleAction[8] = hRemoteModule ? (DWORD)hRemoteModule : (DWORD)pRemotePath;
  *(LPDWORD)&v_iModuleAction[13] = dwRemoteAddress;

  ::WriteProcessMemory(hProcess, pRemotePath, szModulePath, ::strlen(szModulePath) + 1, NULL);
  ::WriteProcessMemory(hProcess, pRemoteStub, v_iModuleAction, sizeof(v_iModuleAction), NULL);

  Context.Eip = (DWORD)pRemoteStub;
  Context.ContextFlags = CONTEXT_CONTROL;
  ::SetThreadContext(hProcessThread, &Context);

  ::ResumeThread(hProcessThread);

  ::Sleep(3000);

  ::VirtualFreeEx(hProcess, pRemotePath, ::strlen(szModulePath), MEM_DECOMMIT);
  ::VirtualFreeEx(hProcess, pRemoteStub, sizeof(v_iModuleAction), MEM_DECOMMIT);

  ::CloseHandle(hFile);
  ::CloseHandle(hProcess);
  ::CloseHandle(hProcessThread);

  return EXIT_SUCCESS;
}
