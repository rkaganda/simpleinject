#include <iostream>
#include <windows.h>
#include <windowsx.h>
#include <stdint.h>
#include <psapi.h>

#include "util.hpp"
#include "process.hpp"

using namespace std;

int main()
{
    char const* wName = "Simple"; //WINDOW NAME
    char* wDLLName = "simpledll.dll"; //DLL NAME
    //DWORD64 address = 0x0;
	DWORD pid;
	HWND hwnd;
	HANDLE hToken;

	cout << "--------------" << endl;
    cout << "GETTING PROCESS \t\t" << endl;
    cout << "--------------" << endl;

    //get the thread token
    if(!GetThreadToken(hToken))
    {
        return RTN_ERROR;
    }


     // enable SeDebugPrivilege
    if(!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
    {
        DisplayError("SetPrivilege");

        // close token handle
        CloseHandle(hToken);

        // indicate failure
        return RTN_ERROR;
    }


	//get the process window
	hwnd = FindWindow(NULL,wName);
	if(!hwnd)
	{
        DisplayError("FindWindow");
        return RTN_ERROR;
	}

	//get process id
    GetWindowThreadProcessId(hwnd,&pid);
    cout << "WindowName\t" << wName << endl;
    cout << "PID\t\t" << pid << endl;

    //get process handle
    HANDLE phandle = OpenProcess(PROCESS_VM_READ|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_QUERY_INFORMATION,0,pid);
    if(!phandle)
    {
        DisplayError("OpenProcess");
        return RTN_ERROR;
    }
    DWORD64 pProcessBaseAddress = GetModuleBase(phandle);
    cout << "BaseAddress\t0x" << hex << pProcessBaseAddress << endl;

    MEMORY_BASIC_INFORMATION memoryInformation;

    if(!VirtualQueryEx(phandle,(LPCVOID)pProcessBaseAddress,&memoryInformation,sizeof(memoryInformation))) {
        DisplayError("VirtualQueryEx");
        return RTN_ERROR;
    }
    cout << "RegionSize: \t" << memoryInformation.RegionSize << endl;
    cout << endl;

    cout << "--------------" << endl;
    cout << "INJECTING \t" << wDLLName << endl;
    cout << "--------------" << endl;
    //read the memory
    if(!Inject(pid,wDLLName)) {
        return RTN_ERROR;
    }

    cout << "Press Any Key." << endl;
    cin.get();
	return RTN_OK;
}
