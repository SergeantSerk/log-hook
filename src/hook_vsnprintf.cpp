// hook_vsnprintf_comprehensive.cpp - Hooks _vsnprintf from ALL loaded modules
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <iostream>
#include <vector>
#include <string>
#include <tlhelp32.h>
#include <psapi.h>
#include "detours.h"

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "psapi.lib")

// Structure to hold hook information for different modules
struct ModuleHook
{
    HMODULE hModule;
    std::string moduleName;
    void *originalFunction;
    void *hookFunction;
    bool isHooked;
    DWORD moduleBase;
    DWORD moduleSize;
};

// Global variables
static HANDLE g_hConsole = NULL;
static FILE *g_logFile = NULL;
static bool g_consoleAllocated = false;
static std::vector<ModuleHook> g_hooks;
static int g_callCounter = 0;

// Forward declarations for different hook functions
int __cdecl Hooked_vsnprintf_0(char *buffer, size_t count, const char *format, va_list argptr);
int __cdecl Hooked_vsnprintf_1(char *buffer, size_t count, const char *format, va_list argptr);
int __cdecl Hooked_vsnprintf_2(char *buffer, size_t count, const char *format, va_list argptr);
int __cdecl Hooked_vsnprintf_3(char *buffer, size_t count, const char *format, va_list argptr);
int __cdecl Hooked_vsnprintf_4(char *buffer, size_t count, const char *format, va_list argptr);
int __cdecl Hooked_vsnprintf_5(char *buffer, size_t count, const char *format, va_list argptr);
int __cdecl Hooked_vsnprintf_6(char *buffer, size_t count, const char *format, va_list argptr);
int __cdecl Hooked_vsnprintf_7(char *buffer, size_t count, const char *format, va_list argptr);
int __cdecl Hooked_vsnprintf_8(char *buffer, size_t count, const char *format, va_list argptr);
int __cdecl Hooked_vsnprintf_9(char *buffer, size_t count, const char *format, va_list argptr);

// Array of hook functions
void *g_hookFunctions[] = {
    (void *)Hooked_vsnprintf_0, (void *)Hooked_vsnprintf_1, (void *)Hooked_vsnprintf_2,
    (void *)Hooked_vsnprintf_3, (void *)Hooked_vsnprintf_4, (void *)Hooked_vsnprintf_5,
    (void *)Hooked_vsnprintf_6, (void *)Hooked_vsnprintf_7, (void *)Hooked_vsnprintf_8,
    (void *)Hooked_vsnprintf_9};

// Function to create console for GUI applications
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

    SetConsoleTitleA("Comprehensive _vsnprintf Hook Logger");
    g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    SetConsoleTextAttribute(g_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("=== Comprehensive _vsnprintf Hook Console ===\n");
    SetConsoleTextAttribute(g_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    g_consoleAllocated = true;
    return true;
}

// Function to initialize log file
bool InitializeLogFile()
{
    if (g_logFile != NULL)
        return true;

    char logPath[MAX_PATH];
    GetTempPathA(MAX_PATH, logPath);
    strcat_s(logPath, MAX_PATH, "vsnprintf_comprehensive.log");

    fopen_s(&g_logFile, logPath, "w");
    if (g_logFile)
    {
        fprintf(g_logFile, "=== Comprehensive _vsnprintf Hook Log ===\n");
        fprintf(g_logFile, "Process ID: %d\n", GetCurrentProcessId());
        fprintf(g_logFile, "Log file: %s\n\n", logPath);
        fflush(g_logFile);
        return true;
    }
    return false;
}

// Enhanced logging function with filtering
void LogVsnprintfCall(const char *moduleName, char *buffer, int result, size_t count, const char *format)
{
    if (result <= 0 || buffer == nullptr)
        return;

    CreateConsoleWindow();
    InitializeLogFile();

    g_callCounter++;

    // Create safe copy of buffer
    size_t safe_len = min((size_t)result, count - 1);
    if (safe_len > 200)
        safe_len = 200;

    char *safe_buffer = new char[safe_len + 1];
    memcpy(safe_buffer, buffer, safe_len);
    safe_buffer[safe_len] = '\0';

    SYSTEMTIME st;
    GetLocalTime(&st);
    void *caller = _ReturnAddress();

    //if (caller == reinterpret_cast<void*>(0x610E346D)) // this one spams the logs with bone anims
    if (safe_buffer != nullptr && safe_buffer[0] == '[')
    {
        char logMessage[1024];
        sprintf_s(logMessage, sizeof(logMessage),
                  "[%02d:%02d:%02d.%03d] #%d %s::_vsnprintf(len=%d) @ 0x%p: %s\n",
                  st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                  g_callCounter, moduleName, result, caller, safe_buffer);

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

        // Debug output
        OutputDebugStringA(logMessage);
    }

    delete[] safe_buffer;
}

// Hook function implementations
#define IMPLEMENT_HOOK_FUNCTION(index)                                                                   \
    int __cdecl Hooked_vsnprintf_##index(char *buffer, size_t count, const char *format, va_list argptr) \
    {                                                                                                    \
        if (index >= g_hooks.size())                                                                     \
            return -1;                                                                                   \
        auto &hook = g_hooks[index];                                                                     \
        typedef int(__cdecl * vsnprintf_func)(char *, size_t, const char *, va_list);                    \
        vsnprintf_func original = (vsnprintf_func)hook.originalFunction;                                 \
        int result = original(buffer, count, format, argptr);                                            \
        LogVsnprintfCall(hook.moduleName.c_str(), buffer, result, count, format);                        \
        return result;                                                                                   \
    }

IMPLEMENT_HOOK_FUNCTION(0)
IMPLEMENT_HOOK_FUNCTION(1)
IMPLEMENT_HOOK_FUNCTION(2)
IMPLEMENT_HOOK_FUNCTION(3)
IMPLEMENT_HOOK_FUNCTION(4)
IMPLEMENT_HOOK_FUNCTION(5)
IMPLEMENT_HOOK_FUNCTION(6)
IMPLEMENT_HOOK_FUNCTION(7)
IMPLEMENT_HOOK_FUNCTION(8)
IMPLEMENT_HOOK_FUNCTION(9)

// Function to enumerate all loaded modules and find _vsnprintf
void EnumerateAndHookModules()
{
    printf("\nScanning ALL loaded modules for _vsnprintf...\n");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        printf("Failed to create module snapshot\n");
        return;
    }

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    int moduleCount = 0;
    if (Module32First(hSnapshot, &me32))
    {
        do
        {
            if (moduleCount >= 10)
                break; // Limit to 10 modules due to hook function limit

            printf("Checking module: %s (Base: 0x%p, Size: 0x%X)\n",
                   me32.szModule, me32.modBaseAddr, me32.modBaseSize);

            HMODULE hMod = GetModuleHandleA(me32.szModule);
            if (hMod)
            {
                void *vsnprintfAddr = GetProcAddress(hMod, "_vsnprintf");
                if (vsnprintfAddr)
                {
                    printf("  -> _vsnprintf found at address: 0x%p\n", vsnprintfAddr);

                    ModuleHook hook = {0};
                    hook.hModule = hMod;
                    hook.moduleName = me32.szModule;
                    hook.originalFunction = vsnprintfAddr;
                    hook.hookFunction = g_hookFunctions[moduleCount];
                    hook.isHooked = false;
                    hook.moduleBase = (DWORD)me32.modBaseAddr;
                    hook.moduleSize = me32.modBaseSize;

                    g_hooks.push_back(hook);
                    moduleCount++;
                }
                else
                {
                    // Also check for other common variants
                    void *otherVariants[] = {
                        GetProcAddress(hMod, "vsnprintf"),
                        GetProcAddress(hMod, "_vsnprintf_l"),
                        GetProcAddress(hMod, "_vsnprintf_s")};

                    const char *variantNames[] = {"vsnprintf", "_vsnprintf_l", "_vsnprintf_s"};

                    for (int i = 0; i < 3; i++)
                    {
                        if (otherVariants[i])
                        {
                            printf("  -> %s found at address: 0x%p\n", variantNames[i], otherVariants[i]);
                        }
                    }
                }
            }

        } while (Module32Next(hSnapshot, &me32));
    }

    CloseHandle(hSnapshot);

    printf("\nFound %d modules with _vsnprintf\n", (int)g_hooks.size());

    // Install hooks using Detours
    printf("\nInstalling hooks...\n");
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    int hookCount = 0;
    for (size_t i = 0; i < g_hooks.size(); i++)
    {
        auto &hook = g_hooks[i];
        LONG result = DetourAttach(&hook.originalFunction, hook.hookFunction);
        if (result == NO_ERROR)
        {
            hook.isHooked = true;
            hookCount++;
            printf("Successfully hooked _vsnprintf in %s\n", hook.moduleName.c_str());
        }
        else
        {
            printf("Failed to hook _vsnprintf in %s (error: %d)\n", hook.moduleName.c_str(), result);
        }
    }

    LONG commitResult = DetourTransactionCommit();

    printf("\nHook installation complete!\n");
    printf("Successfully installed %d hooks\n", hookCount);
    printf("Transaction result: %d\n\n", commitResult);

    if (hookCount > 0)
    {
        printf("Ready to intercept _vsnprintf calls from ALL modules!\n");
        printf("Debug parameter calls are filtered out for cleaner output.\n\n");
    }
}

// Function to remove all hooks
void RemoveAllHooks()
{
    if (g_hooks.empty())
        return;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    for (auto &hook : g_hooks)
    {
        if (hook.isHooked)
        {
            DetourDetach(&hook.originalFunction, hook.hookFunction);
        }
    }

    DetourTransactionCommit();
    g_hooks.clear();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        CreateConsoleWindow();
        InitializeLogFile();

        printf("=== Comprehensive _vsnprintf Hook DLL Loaded ===\n");
        printf("Process ID: %d\n", GetCurrentProcessId());
        printf("DLL Base Address: 0x%p\n", hModule);

        // Enumerate and hook all modules
        EnumerateAndHookModules();

        break;

    case DLL_PROCESS_DETACH:
        RemoveAllHooks();

        if (g_logFile)
        {
            fprintf(g_logFile, "\n=== Comprehensive hook session ended ===\n");
            fprintf(g_logFile, "Total intercepted calls: %d\n", g_callCounter);
            fclose(g_logFile);
            g_logFile = NULL;
        }

        if (g_consoleAllocated)
        {
            printf("\nComprehensive hook DLL unloading...\n");
            printf("Total intercepted calls: %d\n", g_callCounter);
            FreeConsole();
        }

        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void DummyFunction() {}
