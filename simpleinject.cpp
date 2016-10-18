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
	DWORD pid;
	DWORD64 injectedModuleAddress = 0;
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
    cout << "WindowName\t\t" << wName << endl;
    cout << "PID\t\t\t" << pid << endl;

    //get process handle
    //HANDLE phandle = OpenProcess(PROCESS_VM_READ|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_QUERY_INFORMATION,0,pid);
    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS,0,pid);
    if(!phandle)
    {
        DisplayError("OpenProcess");
        return RTN_ERROR;
    }
    DWORD64 pProcessBaseAddress = GetModuleBaseAddress(phandle);
    cout << "ProcessBaseAddress\t0x" << hex << pProcessBaseAddress << endl;

    cout << "Press any key to inject DLL or Crtl+C to exit.";
    cin.get();

    cout << "--------------" << endl;
    cout << "INJECTING \t" << wDLLName << endl;
    cout << "--------------" << endl;
    //read the memory
    injectedModuleAddress = Inject(pid,wDLLName);
    if(!injectedModuleAddress) {
        return RTN_ERROR;
    }

    cout << "Press any key to patch CALL instruction or Crtl+C to exit.";
    cin.get();

    cout << "--------------" << endl;
    cout << "PATCHING CALL \t" << endl;
    cout << "--------------" << endl;

    DWORD64 callAddress = pProcessBaseAddress+0x8DDCB; //baseAddress + offset
    int callOperand = 0;
    DWORD callDestination;
    DWORD injectedModuleCallAddress = (injectedModuleAddress+0x1530) - (pProcessBaseAddress+0x8DDCB+5) ; //call = destination - next

    cout << "Call Address \t\t0x" << hex << callAddress << endl;
    if(!ReadProcessMemory(phandle,(LPCVOID)callAddress,&callOperand,1,NULL)) {
        DisplayError("ReadProcessMemory");
        return RTN_ERROR;
    }

    if(!ReadProcessMemory(phandle,(LPCVOID)(callAddress+1),&callDestination,sizeof(callDestination),NULL)) {
        DisplayError("ReadProcessMemory");
        return RTN_ERROR;
    }
    cout << "Call Operhand\t\t0x" << hex << callOperand << endl;
    cout << "Call Destination\t0x" << hex << callDestination << endl;

    if(!(callOperand==0xe8 && callDestination==0xfff73730)) {
        cout << "Incorrect Operand or Destination" << endl;
    }



    cout << "Patch Destination\tx" << hex << injectedModuleCallAddress << endl;
    if(!WriteProcessMemory(phandle,(LPVOID)(callAddress+1),&injectedModuleCallAddress,4,NULL)) {
        DisplayError("WriteProcessMemory");
        return RTN_ERROR;
    }

	return RTN_OK;
}
