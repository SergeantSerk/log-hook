// injector_simple.cpp - Simple injector with basic argument support
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "detours.h"

#pragma comment(lib, "detours.lib")

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <target_executable> [args...]\n", argv[0]);
        printf("\nExamples:\n");
        printf("  %s notepad.exe\n", argv[0]);
        printf("  %s calc.exe\n", argv[0]);
        printf("  %s cmd.exe /c dir\n", argv[0]);
        printf("\nNote: HookDLL.dll must be in the same directory as this injector\n");
        return 1;
    }

    // Use HookDLL.dll in the same directory
    char dllPath[MAX_PATH];
    GetModuleFileNameA(NULL, dllPath, MAX_PATH);

    // Replace the executable name with DLL name
    char* lastSlash = strrchr(dllPath, '\\');
    if (lastSlash)
        strcpy_s(lastSlash + 1, MAX_PATH - (lastSlash + 1 - dllPath), "HookDLL.dll");
    else
        strcpy_s(dllPath, MAX_PATH, "HookDLL.dll");

    // Build command line
    char cmdLine[2048] = {0};
    strcpy_s(cmdLine, sizeof(cmdLine), argv[1]);

    for (int i = 2; i < argc; i++)
    {
        strcat_s(cmdLine, sizeof(cmdLine), " ");
        strcat_s(cmdLine, sizeof(cmdLine), argv[i]);
    }

    printf("Injecting: %s\n", dllPath);
    printf("Target: %s\n", cmdLine);
    printf("\n");

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(STARTUPINFOA);

    // Create process with DLL injection
    BOOL success = DetourCreateProcessWithDllA(
        NULL,           // No module name (use command line)
        cmdLine,        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory
        &si,            // Pointer to STARTUPINFO structure
        &pi,            // Pointer to PROCESS_INFORMATION structure
        dllPath,        // DLL to inject
        NULL            // No additional DLLs
    );

    if (success)
    {
        printf("Successfully launched process with PID %d\n", pi.dwProcessId);

        // Clean up handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        printf("Failed to create process. Error: %d\n", GetLastError());
        return 1;
    }

    return 0;
}
