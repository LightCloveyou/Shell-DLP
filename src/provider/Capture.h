#pragma once
#include <windows.h>
#include <string>
#include <string_view>

namespace guard {
struct ProcessInfo {
    DWORD ppid = 0, windowsSession = MAXDWORD, elevated = MAXDWORD, integrity = MAXDWORD;
    DWORD architecture = 0, nativeArchitecture = 0;
    ULONGLONG created = 0, parentCreated = 0;
    std::wstring image, commandLine, userSid, userName, parentImage, parentCommandLine;
};
struct ProcessContext {
    const ProcessInfo* fixed = nullptr;
    DWORD pid = 0, tid = 0;
    std::wstring cwd;
};
struct CaptureExtras {
    ULONGLONG redirectChainSize = 0, allSize = 0;
    DWORD known = 0, values = 0;
};
ProcessContext SnapshotContext() noexcept;
void QueueCapture(ProcessContext&&, ULONGLONG sequence, ULONGLONG session, ULONGLONG size,
                  DWORD flags, DWORD result, const char* reason, std::wstring_view app,
                  std::wstring_view source, std::wstring_view content, std::string&& ast,
                  CaptureExtras extras) noexcept;
}
