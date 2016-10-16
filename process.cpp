#include <windows.h>
#include <iostream>
#include <string>
#include <psapi.h>

#include "util.hpp"

BOOL GetThreadToken(
    HANDLE &hToken
    )
{
    //get hToken
	if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
    {
        if (GetLastError() == ERROR_NO_TOKEN)
        {
            if (!ImpersonateSelf(SecurityImpersonation))
                return false;

            if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)){
                DisplayError("OpenThreadToken");
                return false;
            }
         }
        else
            return false;
     }
     return true;
}

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    )
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if ( !LookupPrivilegeValue(
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup
            &luid ) )        // receives LUID of privilege
    {
        std::cout << "LookupPrivilegeValue error:" << GetLastError() << std::endl;
        //printf("LookupPrivilegeValue error: %u\n", GetLastError() );
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if ( !AdjustTokenPrivileges(
           hToken,
           FALSE,
           &tp,
           sizeof(TOKEN_PRIVILEGES),
           (PTOKEN_PRIVILEGES) NULL,
           (PDWORD) NULL) )
    {
          std::cout << "AdjustTokenPrivileges error:" << GetLastError() << std::endl;
          //printf("AdjustTokenPrivileges error: %u\n", GetLastError() );
          return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
          printf("The token does not have the specified privilege. \n");
          return FALSE;
    }

    return TRUE;
}

DWORD64 GetModuleBase(
    HANDLE hProc
    )
{
   HMODULE *hModules = NULL;
   char szBuf[100];
   DWORD cModules;
   DWORD64 dwBase = -1;
   //------

   EnumProcessModules(hProc, hModules, 0, &cModules);
   hModules = new HMODULE[cModules/sizeof(HMODULE)];

   if(GetProcessImageFileName(hProc, szBuf, sizeof(szBuf))) {
    dwBase = (DWORD64)szBuf;
   }else {
        DisplayError("GetProcessImageFileName");
    }

   delete[] hModules;
   return dwBase;
}

BOOL Inject(
    DWORD pId,
    char *dllName
)
{
    TCHAR fullDllPath[MAX_PATH];
    GetFullPathName(dllName, MAX_PATH, fullDllPath, NULL);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pId);
    DWORD hLibModule;
    std::cout << "Full Path\t" << fullDllPath << std::endl;
    if(hProcess)
    {
        LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        std::cout << "LoadLibAddr OK \t\t0x" << std::hex << LoadLibAddr << std::endl;
        LPVOID pLibRemote = VirtualAllocEx(hProcess, NULL, strlen(fullDllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        std::cout << "VirtualAllocEx OK \t" << std::hex << pLibRemote << std::endl;
        if(!WriteProcessMemory(hProcess, pLibRemote, fullDllPath, strlen(fullDllPath), NULL)) {
            DisplayError("Inject WriteProcessMemory");
            return false;
        }
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibAddr, pLibRemote, 0, NULL);
        std::cout << "CreateRemoteThread OK \t" << hThread << std::endl;
        if(WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) {
            DisplayError("Inject WaitForSingleObject");
            return false;
        }
        if(!GetExitCodeThread( hThread, &hLibModule )) {
            DisplayError("Inject GetExitCodeThread");
            return false;
        }
        if(!hLibModule) {
            std::cout << "Inject Failed" << hLibModule << std::endl;
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return false;
        }
        std::cout << "Inject OK \t\t0x" << hLibModule << std::endl;

        if(!VirtualFreeEx(hProcess, pLibRemote, strlen(fullDllPath), MEM_RELEASE)) {
            DisplayError("VirtualFreeEx");
            return false;
        }
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return true;
    }
    return false;
}
