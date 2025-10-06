// hook.cpp
// Build as a DLL. Link with detours.lib
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <detours.h>
#include <cstdio>
#include <cstdarg>
#include <string>
#include <mutex>
#include <fstream>

#pragma comment(lib, "detours.lib")

static std::mutex g_logMutex;
static std::ofstream g_logFile;

// Helper: thread-safe append to log file
void LogFormatted(const char* tag, const char* buf)
{
    std::lock_guard<std::mutex> lk(g_logMutex);
    if (!g_logFile.is_open()) {
        // fallback path; ensure folder exists (C:\Temp usually exists)
        g_logFile.open("C:\\Temp\\format_hook.log", std::ios::app | std::ios::out);
    }
    if (g_logFile.is_open()) {
        g_logFile << "[" << tag << "] " << buf << "\n";
        g_logFile.flush();
    }
}

// ------------------- Hook for vfprintf -------------------
using vfprintf_t = int(__cdecl*)(FILE*, const char*, va_list);
static vfprintf_t Real_vfprintf = nullptr;

int __cdecl My_vfprintf(FILE* stream, const char* format, va_list args)
{
    // Format into a buffer for logging using a copy of va_list
    va_list copy1, copy2;
    va_copy(copy1, args);
    va_copy(copy2, args);

    // try small stack buffer first
    char stackbuf[4096];
    int needed = _vsnprintf_s(stackbuf, sizeof(stackbuf), _TRUNCATE, format, copy1);
    va_end(copy1);

    if (needed >= 0 && needed < (int)sizeof(stackbuf)) {
        LogFormatted("vfprintf", stackbuf);
    } else {
        // allocate dynamic buffer if needed
        int bufsize = (needed > 0) ? (needed + 1) : 32768;
        std::string dyn(bufsize, '\0');
        int res = vsnprintf_s(dyn.data(), dyn.size(), _TRUNCATE, format, copy2);
        (void)res;
        LogFormatted("vfprintf", dyn.c_str());
    }
    va_end(copy2);

    // call original implementation (pass original args - we already copied before use)
    return Real_vfprintf(stream, format, args);
}

// ------------------- Hook for vsnprintf (C-runtime) -------------------
using vsnprintf_t = int(__cdecl*)(char*, size_t, const char*, va_list);
static vsnprintf_t Real_vsnprintf = nullptr;

int __cdecl My_vsnprintf(char* buf, size_t bufcount, const char* format, va_list args)
{
    va_list copy1;
    va_copy(copy1, args);
    // format to temp buffer to log
    char tmp[4096];
    int needed = _vsnprintf_s(tmp, sizeof(tmp), _TRUNCATE, format, copy1);
    va_end(copy1);
    if (needed >= 0) LogFormatted("vsnprintf", tmp);
    else LogFormatted("vsnprintf", "(truncated)");
    return Real_vsnprintf(buf, bufcount, format, args);
}

// ------------------- Hook for FormatMessageW / FormatMessageA -------------------
using FormatMessageW_t = DWORD(WINAPI*)(DWORD, LPCVOID, DWORD, DWORD, LPWSTR, DWORD, va_list*);
static FormatMessageW_t Real_FormatMessageW = nullptr;

DWORD WINAPI My_FormatMessageW(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId,
    DWORD dwLanguageId, LPWSTR lpBuffer, DWORD nSize, va_list* Arguments)
{
    // We can attempt to call the real function and then log the result in lpBuffer
    DWORD res = Real_FormatMessageW(dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments);
    if (res > 0 && lpBuffer) {
        // lpBuffer is UTF-16, convert to UTF-8 for log
        int utf8len = WideCharToMultiByte(CP_UTF8, 0, lpBuffer, -1, nullptr, 0, nullptr, nullptr);
        if (utf8len > 0) {
            std::string s(utf8len, '\0');
            WideCharToMultiByte(CP_UTF8, 0, lpBuffer, -1, s.data(), utf8len, nullptr, nullptr);
            LogFormatted("FormatMessageW", s.c_str());
        }
    }
    return res;
}

using FormatMessageA_t = DWORD(WINAPI*)(DWORD, LPCVOID, DWORD, DWORD, LPSTR, DWORD, va_list*);
static FormatMessageA_t Real_FormatMessageA = nullptr;

DWORD WINAPI My_FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId,
    DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list* Arguments)
{
    DWORD res = Real_FormatMessageA(dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments);
    if (res > 0 && lpBuffer) {
        LogFormatted("FormatMessageA", lpBuffer);
    }
    return res;
}

// ------------------- DllMain (attach detours) -------------------
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        // open log file early
        std::lock_guard<std::mutex> lk(g_logMutex);
        g_logFile.open("C:\\Temp\\format_hook.log", std::ios::app | std::ios::out);

        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        // Resolve real functions
        HMODULE ucrt = GetModuleHandleA("ucrtbase.dll"); // typical on modern Windows
        if (!ucrt) ucrt = GetModuleHandleA("msvcr120.dll"); // fallback
        // fallbacks: use standard function addresses (should be linked)
        if (!Real_vfprintf) Real_vfprintf = vfprintf;
        if (!Real_vsnprintf) Real_vsnprintf = vsnprintf;

        // Attach detours (some functions may be in different CRT modules depending on the app)
        DetourAttach(reinterpret_cast<PVOID*>(&Real_vfprintf), My_vfprintf);
        DetourAttach(reinterpret_cast<PVOID*>(&Real_vsnprintf), My_vsnprintf);

        // Attach FormatMessage
        HMODULE kernel = GetModuleHandleA("kernel32.dll");
        if (!Real_FormatMessageW) {
            Real_FormatMessageW = (FormatMessageW_t)GetProcAddress(kernel, "FormatMessageW");
        }
        if (!Real_FormatMessageA) {
            Real_FormatMessageA = (FormatMessageA_t)GetProcAddress(kernel, "FormatMessageA");
        }
        if (Real_FormatMessageW) DetourAttach(reinterpret_cast<PVOID*>(&Real_FormatMessageW), My_FormatMessageW);
        if (Real_FormatMessageA) DetourAttach(reinterpret_cast<PVOID*>(&Real_FormatMessageA), My_FormatMessageA);

        LONG l = DetourTransactionCommit();
        if (l != NO_ERROR) {
            // failed to attach; write to log
            LogFormatted("hook", "DetourTransactionCommit failed");
        } else {
            LogFormatted("hook", "Detours attached");
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Real_vfprintf) DetourDetach(reinterpret_cast<PVOID*>(&Real_vfprintf), My_vfprintf);
        if (Real_vsnprintf) DetourDetach(reinterpret_cast<PVOID*>(&Real_vsnprintf), My_vsnprintf);
        if (Real_FormatMessageW) DetourDetach(reinterpret_cast<PVOID*>(&Real_FormatMessageW), My_FormatMessageW);
        if (Real_FormatMessageA) DetourDetach(reinterpret_cast<PVOID*>(&Real_FormatMessageA), My_FormatMessageA);
        DetourTransactionCommit();

        std::lock_guard<std::mutex> lk(g_logMutex);
        if (g_logFile.is_open()) g_logFile.close();
    }
    return TRUE;
}
