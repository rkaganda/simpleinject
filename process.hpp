#ifndef PROCESS_HPP_INCLUDED
#define PROCESS_HPP_INCLUDED

BOOL GetThreadToken(
    HANDLE &hToken
    );

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    );

DWORD64 GetModuleBaseAddress(
    HANDLE hProc,
    std::string &sModuleName
    );

DWORD64 GetModuleBaseAddress(
    HANDLE hProc
    );

int PrintModules( DWORD processID );

DWORD64 Inject(
    DWORD pId,
    char *dllName
);



#endif // PROCESS_HPP_INCLUDED
