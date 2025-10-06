// simple_outputdebugstring_hook.cpp - Simple OutputDebugString hook
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include "detours.h"

#pragma comment(lib, "detours.lib")

// Original function pointers
static void (WINAPI *Original_OutputDebugStringA)(LPCSTR lpOutputString) = OutputDebugStringA;
static void (WINAPI *Original_OutputDebugStringW)(LPCWSTR lpOutputString) = OutputDebugStringW;

static HANDLE g_hConsole = NULL;
static FILE* g_logFile = NULL;
static bool g_consoleAllocated = false;
static int g_callCounter = 0;

bool CreateConsoleWindow()
{
    if (g_consoleAllocated) return true;

    if (AllocConsole())
    {
        freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
        freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);
        freopen_s((FILE**)stdin, "CONIN$", "r", stdin);

        SetConsoleTitleA("Simple OutputDebugString Hook");
        g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        g_consoleAllocated = true;

        printf("=== Simple OutputDebugString Hook ===\n");
    }

    return true;
}

bool InitializeLogFile()
{
    if (g_logFile) return true;

    char logPath[MAX_PATH];
    GetTempPathA(MAX_PATH, logPath);
    strcat_s(logPath, MAX_PATH, "debug_output_simple.log");

    fopen_s(&g_logFile, logPath, "w");
    if (g_logFile)
    {
        fprintf(g_logFile, "=== Simple OutputDebugString Log ===\n\n");
        fflush(g_logFile);
    }

    return true;
}

// Simple hook for OutputDebugStringA
void WINAPI Hooked_OutputDebugStringA_Simple(LPCSTR lpOutputString)
{
    // Always call original first
    Original_OutputDebugStringA(lpOutputString);

    // Log to our console and file
    if (lpOutputString)
    {
        CreateConsoleWindow();
        InitializeLogFile();

        g_callCounter++;

        SYSTEMTIME st;
        GetLocalTime(&st);

        char logMessage[1024];
        sprintf_s(logMessage, sizeof(logMessage), 
                 "[%02d:%02d:%02d.%03d] #%d DEBUG: %s",
                 st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                 g_callCounter, lpOutputString);

        if (g_hConsole) printf("%s", logMessage);
        if (g_logFile) { fprintf(g_logFile, "%s", logMessage); fflush(g_logFile); }
    }
}

// Simple hook for OutputDebugStringW
void WINAPI Hooked_OutputDebugStringW_Simple(LPCWSTR lpOutputString)
{
    // Always call original first
    Original_OutputDebugStringW(lpOutputString);

    // Convert to ASCII and log
    if (lpOutputString)
    {
        CreateConsoleWindow();
        InitializeLogFile();

        g_callCounter++;

        // Convert wide string to ASCII
        char buffer[1024];
        WideCharToMultiByte(CP_ACP, 0, lpOutputString, -1, buffer, sizeof(buffer), NULL, NULL);

        SYSTEMTIME st;
        GetLocalTime(&st);

        char logMessage[1024];
        sprintf_s(logMessage, sizeof(logMessage), 
                 "[%02d:%02d:%02d.%03d] #%d DEBUG_W: %s",
                 st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                 g_callCounter, buffer);

        if (g_hConsole) printf("%s", logMessage);
        if (g_logFile) { fprintf(g_logFile, "%s", logMessage); fflush(g_logFile); }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateConsoleWindow();
        InitializeLogFile();

        printf("=== Simple OutputDebugString Hook DLL ===\n");

        // Install hooks
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourAttach(&(PVOID&)Original_OutputDebugStringA, Hooked_OutputDebugStringA_Simple);
        DetourAttach(&(PVOID&)Original_OutputDebugStringW, Hooked_OutputDebugStringW_Simple);

        if (DetourTransactionCommit() == NO_ERROR)
        {
            printf("OutputDebugString hooks installed successfully!\n\n");
        }

        break;

    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)Original_OutputDebugStringA, Hooked_OutputDebugStringA_Simple);
        DetourDetach(&(PVOID&)Original_OutputDebugStringW, Hooked_OutputDebugStringW_Simple);
        DetourTransactionCommit();

        if (g_logFile)
        {
            fprintf(g_logFile, "\nTotal debug messages intercepted: %d\n", g_callCounter);
            fclose(g_logFile);
        }

        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void DummyFunction() { }
