// hook_vsnprintf_comprehensive_wsprintfw_sprintfs.cpp
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <iostream>
#include <vector>
#include <string>
#include <tlhelp32.h>
#include <psapi.h>
#include <wchar.h>
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
    bool isWide; // true for wsprintfW
    bool isSprintfSecure; // true for sprintf_s
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

// wsprintfW hook (single function reused for multiple modules)
int __cdecl Hooked_wsprintfW(wchar_t *buffer, const wchar_t *format, ...);

// sprintf_s hook (single function reused for multiple modules)
// signature: int sprintf_s(char *buffer, size_t sizeOfBuffer, const char *format, ...);
int __cdecl Hooked_sprintf_s(char *buffer, size_t sizeOfBuffer, const char *format, ...);

// Array of hook functions for _vsnprintf (indexed)
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

    SetConsoleTitleA("Comprehensive Hook Logger (_vsnprintf, wsprintfW, sprintf_s)");
    g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    SetConsoleTextAttribute(g_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("=== Comprehensive Hook Console ===\n");
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
    strcat_s(logPath, MAX_PATH, "many_printf_comprehensive.log");

    fopen_s(&g_logFile, logPath, "w");
    if (g_logFile)
    {
        fprintf(g_logFile, "=== Comprehensive Hook Log ===\n");
        fprintf(g_logFile, "Process ID: %d\n", GetCurrentProcessId());
        fprintf(g_logFile, "Log file: %s\n\n", logPath);
        fflush(g_logFile);
        return true;
    }
    return false;
}

// Enhanced logging function with filtering for narrow strings
void LogVsnprintfCall(const char *moduleName, char *buffer, int result, size_t count, const char *format)
{
    if (result <= 0 || buffer == nullptr)
        return;

    CreateConsoleWindow();
    InitializeLogFile();

    g_callCounter++;

    // Create safe copy of buffer
    size_t safe_len = min((size_t)result, count > 0 ? count - 1 : (size_t)result);
    if (safe_len > 200)
        safe_len = 200;

    char *safe_buffer = new char[safe_len + 1];
    memcpy(safe_buffer, buffer, safe_len);
    safe_buffer[safe_len] = '\0';

    SYSTEMTIME st;
    GetLocalTime(&st);
    void *caller = _ReturnAddress();

    if (safe_buffer != nullptr && safe_buffer[0] == '[')
    {
        char logMessage[2048];
        sprintf_s(logMessage, sizeof(logMessage),
                  "[%02d:%02d:%02d.%03d] #%d %s::(_vsnprintf len=%d) @ 0x%p: %s\n",
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

// Logging function for wide wsprintfW calls (converts to UTF-8)
void LogWsprintfWCall(const char *moduleName, const wchar_t *wbuffer, int result)
{
    if (result <= 0 || wbuffer == nullptr)
        return;

    CreateConsoleWindow();
    InitializeLogFile();

    g_callCounter++;

    size_t safe_len = (size_t)result;
    if (safe_len > 200)
        safe_len = 200;

    // Convert a safe prefix of the wide buffer to UTF-8
    int needed = WideCharToMultiByte(CP_UTF8, 0, wbuffer, (int)safe_len, NULL, 0, NULL, NULL);
    std::string utf8;
    if (needed > 0)
    {
        utf8.resize(needed);
        WideCharToMultiByte(CP_UTF8, 0, wbuffer, (int)safe_len, &utf8[0], needed, NULL, NULL);
    }
    else
    {
        utf8 = "<conversion failed>";
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    void *caller = _ReturnAddress();

    char logMessage[4096];
    sprintf_s(logMessage, sizeof(logMessage),
              "[%02d:%02d:%02d.%03d] #%d %s::wsprintfW(len=%d) @ 0x%p: %s\n",
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
              g_callCounter, moduleName, result, caller, utf8.c_str());

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

// Hook function implementations for _vsnprintf
#define IMPLEMENT_HOOK_FUNCTION(index)                                                                   \
    int __cdecl Hooked_vsnprintf_##index(char *buffer, size_t count, const char *format, va_list argptr) \
    {                                                                                                    \
        if (index >= (int)g_hooks.size())                                                                \
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

// Generic Hooked_wsprintfW implementation (formats the buffer using _vsnwprintf and logs)
int __cdecl Hooked_wsprintfW(wchar_t *buffer, const wchar_t *format, ...)
{
    if (buffer == nullptr || format == nullptr)
        return -1;

    va_list args;
    va_start(args, format);
    // emulate wsprintfW (unsafe) with a large cap
    int result = _vsnwprintf(buffer, 32767, format, args);
    va_end(args);

    // Find module name from return address
    void *caller = _ReturnAddress();
    const char *moduleName = "unknown";
    for (auto &h : g_hooks)
    {
        DWORD base = h.moduleBase;
        DWORD size = h.moduleSize;
        if (base != 0 && size != 0)
        {
            uintptr_t c = (uintptr_t)caller;
            uintptr_t b = (uintptr_t)base;
            if (c >= b && c < b + (uintptr_t)size)
            {
                moduleName = h.moduleName.c_str();
                break;
            }
        }
    }

    LogWsprintfWCall(moduleName, buffer, result);
    return result;
}

// Generic Hooked_sprintf_s implementation (formats the buffer using vsnprintf_s and logs)
int __cdecl Hooked_sprintf_s(char *buffer, size_t sizeOfBuffer, const char *format, ...)
{
    if (buffer == nullptr || format == nullptr)
        return -1;

    va_list args;
    va_start(args, format);
    // Use _TRUNCATE behavior to avoid buffer overrun, emulate sprintf_s
    int result = vsnprintf_s(buffer, sizeOfBuffer, _TRUNCATE, format, args);
    va_end(args);

    // Find module name from return address
    void *caller = _ReturnAddress();
    const char *moduleName = "unknown";
    for (auto &h : g_hooks)
    {
        DWORD base = h.moduleBase;
        DWORD size = h.moduleSize;
        if (base != 0 && size != 0)
        {
            uintptr_t c = (uintptr_t)caller;
            uintptr_t b = (uintptr_t)base;
            if (c >= b && c < b + (uintptr_t)size)
            {
                moduleName = h.moduleName.c_str();
                break;
            }
        }
    }

    // Log using the same narrow logger; only logs messages that start with '['
    LogVsnprintfCall(moduleName, buffer, result, sizeOfBuffer, format);
    return result;
}

// Function to enumerate all loaded modules and find _vsnprintf, wsprintfW and sprintf_s
void EnumerateAndHookModules()
{
    printf("\nScanning ALL loaded modules for _vsnprintf, wsprintfW, and sprintf_s...\n");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        printf("Failed to create module snapshot\n");
        return;
    }

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    int moduleCount = 0;
    const int MAX_HOOKS = 50; // increased limit
    if (Module32First(hSnapshot, &me32))
    {
        do
        {
            if (moduleCount >= MAX_HOOKS)
                break;

            printf("Checking module: %s (Base: 0x%p, Size: 0x%X)\n",
                   me32.szModule, me32.modBaseAddr, me32.modBaseSize);

            HMODULE hMod = GetModuleHandleA(me32.szModule);
            if (hMod)
            {
                // Check _vsnprintf and variants
                void *vsnprintfAddr = GetProcAddress(hMod, "_vsnprintf");
                if (vsnprintfAddr)
                {
                    printf("  -> _vsnprintf found at address: 0x%p\n", vsnprintfAddr);

                    ModuleHook hook = {0};
                    hook.hModule = hMod;
                    hook.moduleName = me32.szModule;
                    hook.originalFunction = vsnprintfAddr;
                    hook.hookFunction = g_hookFunctions[moduleCount % (sizeof(g_hookFunctions)/sizeof(g_hookFunctions[0]))];
                    hook.isHooked = false;
                    hook.moduleBase = (DWORD)me32.modBaseAddr;
                    hook.moduleSize = me32.modBaseSize;
                    hook.isWide = false;
                    hook.isSprintfSecure = false;

                    g_hooks.push_back(hook);
                    moduleCount++;
                }
                else
                {
                    // Also check for other common vsnprintf variants (informational only)
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

                // Check for wsprintfW (wide)
                void *wsprintfWAddr = GetProcAddress(hMod, "wsprintfW");
                if (wsprintfWAddr)
                {
                    printf("  -> wsprintfW found at address: 0x%p\n", wsprintfWAddr);

                    ModuleHook hook = {0};
                    hook.hModule = hMod;
                    hook.moduleName = me32.szModule;
                    hook.originalFunction = wsprintfWAddr;
                    hook.hookFunction = (void *)Hooked_wsprintfW; // generic wide hook
                    hook.isHooked = false;
                    hook.moduleBase = (DWORD)me32.modBaseAddr;
                    hook.moduleSize = me32.modBaseSize;
                    hook.isWide = true;
                    hook.isSprintfSecure = false;

                    g_hooks.push_back(hook);
                    moduleCount++;
                }

                // Check for sprintf_s (secure narrow)
                void *sprintf_s_addr = GetProcAddress(hMod, "sprintf_s");
                if (sprintf_s_addr)
                {
                    printf("  -> sprintf_s found at address: 0x%p\n", sprintf_s_addr);

                    ModuleHook hook = {0};
                    hook.hModule = hMod;
                    hook.moduleName = me32.szModule;
                    hook.originalFunction = sprintf_s_addr;
                    hook.hookFunction = (void *)Hooked_sprintf_s; // generic sprintf_s hook
                    hook.isHooked = false;
                    hook.moduleBase = (DWORD)me32.modBaseAddr;
                    hook.moduleSize = me32.modBaseSize;
                    hook.isWide = false;
                    hook.isSprintfSecure = true;

                    g_hooks.push_back(hook);
                    moduleCount++;
                }
            }

        } while (Module32Next(hSnapshot, &me32));
    }

    CloseHandle(hSnapshot);

    printf("\nFound %d modules with hooks to install\n", (int)g_hooks.size());

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
            if (hook.isWide)
                printf("Successfully hooked wsprintfW in %s\n", hook.moduleName.c_str());
            else if (hook.isSprintfSecure)
                printf("Successfully hooked sprintf_s in %s\n", hook.moduleName.c_str());
            else
                printf("Successfully hooked _vsnprintf in %s\n", hook.moduleName.c_str());
        }
        else
        {
            if (hook.isWide)
                printf("Failed to hook wsprintfW in %s (error: %d)\n", hook.moduleName.c_str(), result);
            else if (hook.isSprintfSecure)
                printf("Failed to hook sprintf_s in %s (error: %d)\n", hook.moduleName.c_str(), result);
            else
                printf("Failed to hook _vsnprintf in %s (error: %d)\n", hook.moduleName.c_str(), result);
        }
    }

    LONG commitResult = DetourTransactionCommit();

    printf("\nHook installation complete!\n");
    printf("Successfully installed %d hooks\n", hookCount);
    printf("Transaction result: %d\n\n", commitResult);

    if (hookCount > 0)
    {
        printf("Ready to intercept _vsnprintf, wsprintfW, and sprintf_s calls from ALL modules!\n");
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

        printf("=== Comprehensive Hook DLL Loaded ===\n");
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
