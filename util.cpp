#include <fstream>
#include <windows.h>

void DisplayError(
    char const* szAPI    // pointer to failed API name
    )
{
    LPTSTR MessageBuffer;
    DWORD dwBufferLength;

    fprintf(stderr,"%s() error!\n", szAPI);

    if((dwBufferLength=FormatMessage(
                FORMAT_MESSAGE_ALLOCATE_BUFFER |
                FORMAT_MESSAGE_FROM_SYSTEM,
                NULL,
                GetLastError(),
                GetSystemDefaultLangID(),
                (LPTSTR) &MessageBuffer,
                0,
                NULL
                )))
    {
        DWORD dwBytesWritten;

        //
        // Output message string on stderr
        //
        WriteFile(
                GetStdHandle(STD_ERROR_HANDLE),
                MessageBuffer,
                dwBufferLength,
                &dwBytesWritten,
                NULL
                );

        //
        // free the buffer allocated by the system
        //
        LocalFree(MessageBuffer);
    }
}
