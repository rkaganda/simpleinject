#include <windows.h>
#include <iostream>
#include <string>
#include <psapi.h>
#include <stdlib.h>

#include <tchar.h>
#include <stdio.h>

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

DWORD64 GetModuleBaseAddress(
    HANDLE hProc,
    std::string &sModuleName
    )
{
   HMODULE hModules[1024];
   DWORD cModules;
   char szBuf[100];
   DWORD64 dwBase = -1;
   //------

   if(EnumProcessModules(hProc, hModules, sizeof(hModules), &cModules)) {
      for(int i = 0; i < (int)(cModules/sizeof(HMODULE)); i++) {
         if(GetMappedFileName(hProc, hModules[i], szBuf, sizeof(szBuf))) {
            if(sModuleName.compare(strrchr(szBuf,'\\')+1) == 0) {
               dwBase = (DWORD64)hModules[i];
               break;
            }
         }else {
             DisplayError("GetModuleBaseName");
         }
      }
   }
   return dwBase;
}

DWORD64 GetModuleBaseAddress(
    HANDLE hProc
    )
{
   char szBuf[100];
   std::string moduleBaseName;

   if(GetProcessImageFileName(hProc, szBuf, sizeof(szBuf))) {
    moduleBaseName = std::string(szBuf);
    moduleBaseName = moduleBaseName.substr(moduleBaseName.find_last_of("\\")+1);
   }else {
        DisplayError("GetProcessImageFileName");
    }

   return GetModuleBaseAddress(hProc,moduleBaseName);
}

DWORD64 Inject(
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


        if(!VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE)) {
            DisplayError("VirtualFreeEx");
            return false;
        }
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return hLibModule;
    }
    return false;
}


