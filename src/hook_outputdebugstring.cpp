// hook_outputdebugstring.cpp - Hook OutputDebugStringA and OutputDebugStringW
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <string>
#include <set>
#include "detours.h"

#pragma comment(lib, "detours.lib")

// Global variables
static HANDLE g_hConsole = NULL;
static FILE *g_logFile = NULL;
static bool g_consoleAllocated = false;
static int g_callCounter = 0;

// Original function pointers
static void(WINAPI *Original_OutputDebugStringA)(LPCSTR lpOutputString) = OutputDebugStringA;
static void(WINAPI *Original_OutputDebugStringW)(LPCWSTR lpOutputString) = OutputDebugStringW;

// Filter strings (same filtering system as _vsnprintf hook)
static std::set<std::string> g_filterSet = {
    "source param",
    "g_boneLocalTM",
    "MACRO_",
    "icon1",
    // Add your specific filters here
};

// Global counters
static int g_totalCalls = 0;
static int g_filteredCalls = 0;

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

    std::ios_base::sync_with_stdio(true);

    SetConsoleTitleA("OutputDebugString Hook Logger");
    g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    SetConsoleTextAttribute(g_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("=== OutputDebugString Hook Console ===\n");
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
    strcat_s(logPath, MAX_PATH, "outputdebugstring_hook.log");

    fopen_s(&g_logFile, logPath, "w");
    if (g_logFile)
    {
        fprintf(g_logFile, "=== OutputDebugString Hook Log ===\n");
        fprintf(g_logFile, "Process ID: %d\n", GetCurrentProcessId());
        fprintf(g_logFile, "Log file: %s\n\n", logPath);
        fflush(g_logFile);
        return true;
    }
    return false;
}

// Function to check if a string should be filtered
bool ShouldFilterCall(const char *message)
{
    if (!message)
        return false;

    std::string messageStr(message);

    for (const auto &filter : g_filterSet)
    {
        if (messageStr.find(filter) != std::string::npos)
        {
            g_filteredCalls++;
            return true;
        }
    }

    return false;
}

// Function to convert wide string to multi-byte
std::string WideStringToString(LPCWSTR wstr)
{
    if (!wstr)
        return "(null)";

    int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (size <= 0)
        return "(conversion error)";

    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], size, NULL, NULL);

    return result;
}

// Hook function for OutputDebugStringA
void WINAPI Hooked_OutputDebugStringA(LPCSTR lpOutputString)
{
    g_totalCalls++;

    // Always call original first to preserve program behavior
    Original_OutputDebugStringA(lpOutputString);

    // Check if we should filter this call
    if (ShouldFilterCall(lpOutputString))
    {
        return; // Skip logging
    }

    CreateConsoleWindow();
    InitializeLogFile();

    g_callCounter++;

    // Get timestamp and caller info
    SYSTEMTIME st;
    GetLocalTime(&st);
    void *caller = _ReturnAddress();

    // Create log message
    char logMessage[2048];
    sprintf_s(logMessage, sizeof(logMessage),
              "[%02d:%02d:%02d.%03d] #%d OutputDebugStringA from 0x%p: %s",
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
              g_callCounter, caller, lpOutputString ? lpOutputString : "(null)");

    // Make sure message ends with newline
    size_t len = strlen(logMessage);
    if (len > 0 && logMessage[len - 1] != '\n')
    {
        strcat_s(logMessage, sizeof(logMessage), "\n");
    }

    // Console output
    if (g_hConsole != NULL)
    {
        SetConsoleTextAttribute(g_hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("%s", logMessage);
        SetConsoleTextAttribute(g_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    // File output
    if (g_logFile)
    {
        fprintf(g_logFile, "%s", logMessage);
        fflush(g_logFile);
    }
}

// Hook function for OutputDebugStringW
void WINAPI Hooked_OutputDebugStringW(LPCWSTR lpOutputString)
{
    g_totalCalls++;

    // Always call original first to preserve program behavior
    Original_OutputDebugStringW(lpOutputString);

    // Convert to string for filtering
    std::string messageStr = WideStringToString(lpOutputString);

    // Check if we should filter this call
    if (ShouldFilterCall(messageStr.c_str()))
    {
        return; // Skip logging
    }

    CreateConsoleWindow();
    InitializeLogFile();

    g_callCounter++;

    // Get timestamp and caller info
    SYSTEMTIME st;
    GetLocalTime(&st);
    void *caller = _ReturnAddress();

    // Create log message
    char logMessage[2048];
    sprintf_s(logMessage, sizeof(logMessage),
              "[%02d:%02d:%02d.%03d] #%d OutputDebugStringW from 0x%p: %s",
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
              g_callCounter, caller, messageStr.c_str());

    // Make sure message ends with newline
    size_t len = strlen(logMessage);
    if (len > 0 && logMessage[len - 1] != '\n')
    {
        strcat_s(logMessage, sizeof(logMessage), "\n");
    }

    // Console output
    if (g_hConsole != NULL)
    {
        SetConsoleTextAttribute(g_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("%s", logMessage);
        SetConsoleTextAttribute(g_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    // File output
    if (g_logFile)
    {
        fprintf(g_logFile, "%s", logMessage);
        fflush(g_logFile);
    }
}

// Runtime filter control functions
extern "C" __declspec(dllexport) void AddFilter(const char *filterString)
{
    if (filterString)
    {
        g_filterSet.insert(std::string(filterString));
        printf("Added filter: %s\n", filterString);
    }
}

extern "C" __declspec(dllexport) void RemoveFilter(const char *filterString)
{
    if (filterString)
    {
        g_filterSet.erase(std::string(filterString));
        printf("Removed filter: %s\n", filterString);
    }
}

extern "C" __declspec(dllexport) void ListFilters()
{
    printf("\nActive filters (%d total):\n", (int)g_filterSet.size());
    for (const auto &filter : g_filterSet)
    {
        printf("  - %s\n", filter.c_str());
    }
    printf("\n");
}

extern "C" __declspec(dllexport) void ShowStats()
{
    printf("\nOutputDebugString Hook Statistics:\n");
    printf("  Total calls: %d\n", g_totalCalls);
    printf("  Filtered calls: %d\n", g_filteredCalls);
    printf("  Displayed calls: %d\n", g_callCounter);
    printf("  Filter efficiency: %.1f%%\n\n",
           g_totalCalls > 0 ? (float)g_filteredCalls / g_totalCalls * 100.0f : 0.0f);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);

        CreateConsoleWindow();
        InitializeLogFile();

        printf("=== OutputDebugString Hook DLL Loaded ===\n");
        printf("Process ID: %d\n", GetCurrentProcessId());
        printf("DLL Base Address: 0x%p\n", hModule);

        // Install hooks using Detours
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourAttach(&(PVOID &)Original_OutputDebugStringA, Hooked_OutputDebugStringA);
        DetourAttach(&(PVOID &)Original_OutputDebugStringW, Hooked_OutputDebugStringW);

        LONG result = DetourTransactionCommit();

        if (result == NO_ERROR)
        {
            printf("Successfully hooked OutputDebugStringA and OutputDebugStringW\n");
            printf("Ready to intercept debug output!\n\n");
        }
        else
        {
            printf("Failed to install hooks. Error: %d\n", result);
        }

        break;
    }
    case DLL_PROCESS_DETACH:
    {
        // Remove hooks
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID &)Original_OutputDebugStringA, Hooked_OutputDebugStringA);
        DetourDetach(&(PVOID &)Original_OutputDebugStringW, Hooked_OutputDebugStringW);
        DetourTransactionCommit();

        if (g_logFile)
        {
            fprintf(g_logFile, "\n=== OutputDebugString hook session ended ===\n");
            fprintf(g_logFile, "Total calls: %d, Displayed: %d, Filtered: %d\n",
                    g_totalCalls, g_callCounter, g_filteredCalls);
            fclose(g_logFile);
            g_logFile = NULL;
        }

        if (g_consoleAllocated)
        {
            printf("\nOutputDebugString hook DLL unloading...\n");
            printf("Total intercepted: %d, Displayed: %d\n", g_totalCalls, g_callCounter);
            FreeConsole();
        }

        break;
    }
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void DummyFunction() {}
