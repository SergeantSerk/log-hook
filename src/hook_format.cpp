// hook_format_function.cpp - Hook the custom format function
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <iostream>
#include <vector>
#include <string>
#include "detours.h"

#pragma comment(lib, "detours.lib")

// Global variables
static HANDLE g_hConsole = NULL;
static FILE *g_logFile = NULL;
static bool g_consoleAllocated = false;
static int g_callCounter = 0;

// Original function pointer - we'll determine the signature dynamically
static void *g_originalFormat = nullptr;

// Function to create console
bool CreateConsoleWindow()
{
    if (g_consoleAllocated)
        return true;

    if (!AllocConsole())
    {
        DWORD error = GetLastError();
        if (error != ERROR_ACCESS_DENIED)
            return false;
    }

    freopen_s((FILE **)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE **)stderr, "CONOUT$", "w", stderr);
    freopen_s((FILE **)stdin, "CONIN$", "r", stdin);

    SetConsoleTitleA("Format Function Hook Logger");
    g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    SetConsoleTextAttribute(g_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("=== Format Function Hook Console ===\n");
    SetConsoleTextAttribute(g_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    g_consoleAllocated = true;
    return true;
}

// Initialize log file
bool InitializeLogFile()
{
    if (g_logFile != NULL)
        return true;

    char logPath[MAX_PATH];
    GetTempPathA(MAX_PATH, logPath);
    strcat_s(logPath, MAX_PATH, "format_hook.log");

    fopen_s(&g_logFile, logPath, "w");
    if (g_logFile)
    {
        fprintf(g_logFile, "=== Format Function Hook Log ===\n");
        fprintf(g_logFile, "Process ID: %d\n", GetCurrentProcessId());
        fprintf(g_logFile, "Log file: %s\n\n", logPath);
        fflush(g_logFile);
        return true;
    }
    return false;
}

// Hook function - assumes format function returns char* and takes format string + args
// Based on your disassembly: format(format_string, double, int, char*)
char *__cdecl Hooked_format(const char *format, ...)
{
    CreateConsoleWindow();
    InitializeLogFile();
    g_callCounter++;

    // Get the caller address for debugging
    void *caller = _ReturnAddress();

    // Call original function with va_list
    va_list args;
    va_start(args, format);

    // Call original - we need to reconstruct the call
    typedef char *(__cdecl * format_func)(const char *, ...);
    format_func original = (format_func)g_originalFormat;

    // Extract arguments based on the format string "[%.2f][%d] %s"
    double timeValue = va_arg(args, double);
    int threadId = va_arg(args, int);
    char *message = va_arg(args, char *);

    char *result = original(format, timeValue, threadId, message);

    va_end(args);

    // Log the intercepted call
    SYSTEMTIME st;
    GetLocalTime(&st);

    char logMessage[1024];
    sprintf_s(logMessage, sizeof(logMessage),
              "[%02d:%02d:%02d.%03d] 0x%p: \"%s\"\n",
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
              caller,
              result ? result : "(null)");

    // Output to console
    if (g_hConsole != NULL)
    {
        SetConsoleTextAttribute(g_hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("%s", logMessage);
        SetConsoleTextAttribute(g_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    // Output to file
    if (g_logFile)
    {
        fprintf(g_logFile, "%s", logMessage);
        fflush(g_logFile);
    }

    // Debug output
    OutputDebugStringA(logMessage);

    return result;
}

// Function to hook by address (since we know the function address)
bool HookFormatByAddress()
{
    // The base address where your program loads (usually 0x00400000 for .exe)
    HMODULE hModule = GetModuleHandleA(NULL); // Get main executable
    DWORD_PTR baseAddress = (DWORD_PTR)hModule;

    printf("Main module base address: 0x%p\n", hModule);

    // Calculate the actual address of the format function
    // You mentioned it's called from 0x009e17fd, but we need the target address
    // Looking at your disasm: "call format" - we need to find where format is

    // Method 1: Try to find the function by scanning for the call pattern
    BYTE *scanStart = (BYTE *)baseAddress;
    BYTE *scanEnd = scanStart + 0x01000000; // Scan first 16MB

    // Look for the call pattern: E8 XX XX XX XX (call relative)
    // At 0x009e17fd: e8 ce3c0000 call format
    // At 0x009e18da: e8 f13b0000 call format

    DWORD_PTR formatAddr = 0;

    // Calculate format address from the first call
    BYTE *callSite1 = (BYTE *)(baseAddress + 0x009e17fd - 0x00400000);
    if (callSite1[0] == 0xE8) // call instruction
    {
        DWORD relativeOffset = *(DWORD *)(callSite1 + 1);
        formatAddr = (DWORD_PTR)(callSite1 + 5 + relativeOffset);
        printf("Format function calculated address: 0x%p\n", (void *)formatAddr);
    }

    if (formatAddr == 0)
    {
        printf("Could not calculate format function address\n");
        return false;
    }

    g_originalFormat = (void *)formatAddr;

    // Install hook using Detours
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    LONG result = DetourAttach(&g_originalFormat, Hooked_format);

    if (result == NO_ERROR)
    {
        LONG commitResult = DetourTransactionCommit();
        if (commitResult == NO_ERROR)
        {
            printf("Successfully hooked format function at 0x%p\n", (void *)formatAddr);
            return true;
        }
        else
        {
            printf("Failed to commit hook transaction: %d\n", commitResult);
        }
    }
    else
    {
        printf("Failed to attach hook: %d\n", result);
        DetourTransactionAbort();
    }

    return false;
}

// Alternative: Hook by instruction pointer patching
bool HookFormatByPatching()
{
    HMODULE hModule = GetModuleHandleA(NULL);
    DWORD_PTR baseAddress = (DWORD_PTR)hModule;

    // Calculate actual addresses of the call sites
    BYTE *callSite1 = (BYTE *)(baseAddress + 0x009e17fd - 0x00400000);
    BYTE *callSite2 = (BYTE *)(baseAddress + 0x009e18da - 0x00400000);

    printf("Call site 1: 0x%p\n", callSite1);
    printf("Call site 2: 0x%p\n", callSite2);

    // This is more complex - would require creating a trampoline
    // and patching the call sites to jump to our hook
    printf("Instruction patching method not implemented in this example\n");
    return false;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        CreateConsoleWindow();
        InitializeLogFile();

        printf("=== Format Function Hook DLL Loaded ===\n");
        printf("Process ID: %d\n", GetCurrentProcessId());
        printf("Hook DLL Base Address: 0x%p\n", hModule);

        // Try to hook the format function
        if (HookFormatByAddress())
        {
            printf("Format function hook installed successfully!\n\n");
        }
        else
        {
            printf("Failed to install format function hook!\n\n");
        }

        break;

    case DLL_PROCESS_DETACH:
        if (g_originalFormat)
        {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(&g_originalFormat, Hooked_format);
            DetourTransactionCommit();
        }

        if (g_logFile)
        {
            fprintf(g_logFile, "\n=== Format hook session ended ===\n");
            fprintf(g_logFile, "Total intercepted calls: %d\n", g_callCounter);
            fclose(g_logFile);
            g_logFile = NULL;
        }

        if (g_consoleAllocated)
        {
            printf("\nFormat hook DLL unloading...\n");
            printf("Total intercepted calls: %d\n", g_callCounter);
            FreeConsole();
        }

        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void DummyFunction() {}
