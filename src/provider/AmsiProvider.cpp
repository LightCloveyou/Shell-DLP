#include "stdafx.h"
#include "AstBridge.h"
#include "Capture.h"
#include "Policy.h"
#include <cstring>
#include <string>

using namespace Microsoft::WRL;

HMODULE g_currentModule;

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        g_currentModule = module;
        DisableThreadLibraryCalls(module);
        Module<InProc>::GetModule().Create();
        break;

    case DLL_PROCESS_DETACH:
        Module<InProc>::GetModule().Terminate();
        break;
    }
    return TRUE;
}

#pragma region COM server boilerplate
HRESULT WINAPI DllCanUnloadNow()
{
    return Module<InProc>::GetModule().Terminate() ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(_In_ REFCLSID rclsid, _In_ REFIID riid, _Outptr_ LPVOID FAR* ppv)
{
    return Module<InProc>::GetModule().GetClassObject(rclsid, riid, ppv);
}
#pragma endregion

class
    DECLSPEC_UUID("B19A3622-9E37-46C6-9A76-D48332292DC7")
    PowerShell7Guard : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IAntimalwareProvider, FtmBase>
{
public:
    IFACEMETHOD(Scan)(_In_ IAmsiStream* stream, _Out_ AMSI_RESULT* result) override;
    IFACEMETHOD_(void, CloseSession)(_In_ ULONGLONG session) override;
    IFACEMETHOD(DisplayName)(_Outptr_ LPWSTR* displayName) override;

};

namespace {
constexpr ULONG MaxNameBytes = 128 * 1024;

struct ScanBuffer
{
    explicit ScanBuffer(ULONG length) noexcept : size(length),
        text(static_cast<wchar_t*>(HeapAlloc(GetProcessHeap(), 0, length))) {}
    ScanBuffer(const ScanBuffer&) = delete;
    ScanBuffer& operator=(const ScanBuffer&) = delete;
    ~ScanBuffer()
    {
        if (text) {
            SecureZeroMemory(text, size);
            HeapFree(GetProcessHeap(), 0, text);
        }
    }
    const ULONG size;
    wchar_t* const text;
};

enum class NameState : ULONG { Unavailable, Empty, Present };

template<class Inspect>
NameState ReadName(IAmsiStream* stream, AMSI_ATTRIBUTE attr, Inspect inspect) noexcept
{
    ULONG required = 0;
    if (stream->GetAttribute(attr, 0, nullptr, &required) != E_NOT_SUFFICIENT_BUFFER ||
        required < sizeof(wchar_t) || required > MaxNameBytes || required % sizeof(wchar_t) != 0)
        return NameState::Unavailable;

    ScanBuffer buffer(required);
    if (!buffer.text) return NameState::Unavailable;
    ULONG actual = 0;
    if (stream->GetAttribute(attr, buffer.size, reinterpret_cast<PBYTE>(buffer.text), &actual) != S_OK ||
        actual < sizeof(wchar_t) || actual > buffer.size || actual % sizeof(wchar_t) != 0)
        return NameState::Unavailable;

    const auto length = actual / sizeof(wchar_t) - 1;
    const std::wstring_view name{buffer.text, length};
    if (buffer.text[length] != L'\0' || name.find(L'\0') != std::wstring_view::npos)
        return NameState::Unavailable;
    inspect(name);
    return name.empty() ? NameState::Empty : NameState::Present;
}

template<class T>
bool ReadFixed(IAmsiStream* stream, AMSI_ATTRIBUTE attr, T& value) noexcept
{
    T data{};
    ULONG actual = 0;
    if (stream->GetAttribute(attr, sizeof(data), reinterpret_cast<PBYTE>(&data), &actual) != S_OK ||
        actual != sizeof(data)) return false;
    value = data;
    return true;
}

// Session values are opaque and may be pointer-sized. Never write a raw value to ETW.
struct SessionSlot { ULONGLONG raw; ULONGLONG id; };
SRWLOCK sessionLock = SRWLOCK_INIT;
SessionSlot sessions[64]{};
ULONGLONG lastSessionId = 0;
volatile LONG64 scanSequence = 0;

ULONGLONG SessionId(ULONGLONG raw) noexcept
{
    if (!raw) return 0;
    AcquireSRWLockExclusive(&sessionLock);
    SessionSlot* freeSlot = nullptr;
    ULONGLONG id = 0;
    for (auto& slot : sessions) {
        if (slot.raw == raw) { id = slot.id; break; }
        if (!slot.raw && !freeSlot) freeSlot = &slot;
    }
    if (!id && freeSlot) {
        id = ++lastSessionId;
        *freeSlot = {raw, id};
    }
    ReleaseSRWLockExclusive(&sessionLock);
    return id;
}

struct CaptureText {
    std::wstring value;
    void Assign(std::wstring_view view) noexcept { try { value = view; } catch (...) {} }
    ~CaptureText() {
        if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t));
    }
};

template<class Capture>
const char* Reason(IAmsiStream* stream, AMSI_RESULT& result, bool sizeKnown,
                   ULONGLONG size, const char*& input, const guard::ProcessContext& process,
                   Capture capture) noexcept
{
    if (!sizeKnown) return "missing:size-unavailable";
    if (size > guard::AmsiContentLimit()) return "missing:oversize";
    if (size == 0 || size % sizeof(wchar_t)) return "missing:not-utf16";

    ScanBuffer buffer(static_cast<ULONG>(size));
    if (!buffer.text) return "missing:allocation";
    PBYTE address = nullptr;
    SIZE_T bytesCopied = 0;
    if (ReadFixed(stream, AMSI_ATTRIBUTE_CONTENT_ADDRESS, address) && address &&
        ReadProcessMemory(GetCurrentProcess(), address, buffer.text, buffer.size, &bytesCopied) &&
        bytesCopied == buffer.size) {
        input = "memory";
    } else {
        input = "stream";
        ULONG pos = 0;
        while (pos < buffer.size) {
            const ULONG remaining = buffer.size - pos;
            const ULONG requested = remaining < 4096 ? remaining : 4096;
            ULONG count = 0;
            if (FAILED(stream->Read(pos, requested, reinterpret_cast<PBYTE>(buffer.text) + pos, &count)) ||
                count == 0 || count > requested)
                return "missing:read";
            pos += count;
        }
    }

    const std::wstring_view text{buffer.text, buffer.size / sizeof(wchar_t)};
    auto ast = guard::ParseAst(text);
    auto decision = guard::Evaluate(text) == guard::Decision::Uncovered ? guard::Decision::Uncovered
        : guard::Decision::InformationMissing; // no hidden canary policy when the configured engine is unavailable
    const char* reason = nullptr;
    if (!process.pid) {
        decision = guard::Decision::InformationMissing;
        reason = "missing:process-context";
    } else {
        switch (ast.decision) {
            case 0: decision = guard::Decision::Uncovered; break;
            case 1: decision = guard::Decision::Block; break;
            case 2: decision = guard::Decision::NoMatch; break;
            case 3: decision = guard::Decision::InformationMissing; break;
            case 4: decision = guard::Decision::InformationMissing; reason = "missing:ast-syntax"; break;
            case 5: decision = guard::Decision::InformationMissing; reason = "warn:sensitive-rule"; break;
            case 6: decision = guard::Decision::NoMatch; reason = "allow:git-remote-allowlist"; break;
            default: if (decision == guard::Decision::InformationMissing) reason = "missing:rule-engine"; break;
        }
    }
    switch (decision) {
    case guard::Decision::Block:
        result = AMSI_RESULT_BLOCKED_BY_ADMIN_START;
        reason = "block:configured-rule";
        break;
    case guard::Decision::NoMatch:
        if (!reason) reason = "no-match:configured-rules";
        break;
    case guard::Decision::InformationMissing:
        if (!reason) reason = "missing:rule-input";
        break;
    default:
        reason = "uncovered:command-shape";
    }
    capture(text, reason, std::move(ast.json));
    return reason;
}
}

HRESULT PowerShell7Guard::Scan(IAmsiStream* stream, AMSI_RESULT* result)
{
    if (!result) return E_POINTER;
    *result = AMSI_RESULT_NOT_DETECTED;
    if (!stream) return E_INVALIDARG;
    CaptureText appText, sourceText;
    bool isPowerShell7 = false;
    const auto app = ReadName(stream, AMSI_ATTRIBUTE_APP_NAME, [&](std::wstring_view name) noexcept {
        isPowerShell7 = guard::IsPowerShell7(name);
        if (isPowerShell7) appText.Assign(name);
    });
    if (app == NameState::Present && !isPowerShell7) return S_OK;

    const auto sequence = static_cast<ULONGLONG>(InterlockedIncrement64(&scanSequence));
    ULONGLONG size = 0;
    const bool sizeKnown = isPowerShell7 && ReadFixed(stream, AMSI_ATTRIBUTE_CONTENT_SIZE, size);
    const char* input = "none";
    auto process = guard::SnapshotContext();
    bool log = isPowerShell7;
    if (process.fixed && !process.fixed->image.empty()) {
        const auto& image = process.fixed->image;
        const auto slash = image.find_last_of(L"\\/");
        log = _wcsicmp(image.c_str() + (slash == std::wstring::npos ? 0 : slash + 1), L"pwsh.exe") == 0;
    }
    NameState source = NameState::Unavailable;
    ULONG_PTR session = 0;
    bool sessionKnown = false;
    guard::CaptureExtras extras;
    if (isPowerShell7) {
        source = ReadName(stream, AMSI_ATTRIBUTE_CONTENT_NAME, [&](std::wstring_view name) noexcept {
            sourceText.Assign(name);
        });
        sessionKnown = ReadFixed(stream, AMSI_ATTRIBUTE_SESSION, session);
        {
            if (ReadFixed(stream, AMSI_ATTRIBUTE_REDIRECT_CHAIN_SIZE, extras.redirectChainSize)) extras.known |= 1u;
            if (ReadFixed(stream, AMSI_ATTRIBUTE_ALL_SIZE, extras.allSize)) extras.known |= 2u;
            PVOID address = nullptr;
            if (ReadFixed(stream, AMSI_ATTRIBUTE_REDIRECT_CHAIN_ADDRESS, address)) {
                extras.known |= 4u;
                if (address) extras.values |= 4u;
            }
            if (ReadFixed(stream, AMSI_ATTRIBUTE_ALL_ADDRESS, address)) {
                extras.known |= 8u;
                if (address) extras.values |= 8u;
            }
            BOOL quiet = FALSE;
            if (ReadFixed(stream, AMSI_ATTRIBUTE_QUIET, quiet) && (quiet == FALSE || quiet == TRUE)) {
                extras.known |= 16u;
                if (quiet) extras.values |= 16u;
            }
        }
    }
    const auto id = SessionId(session);
    bool captured = false;
    const auto capture = [&](std::wstring_view text, const char* reason, std::string&& ast) noexcept {
        if (!log) return;
        DWORD flags = (sizeKnown ? 1u : 0u) | (!text.empty() ? 2u : 0u) |
            (sessionKnown ? 4u : 0u) | (session ? 8u : 0u) |
            (std::strcmp(input, "memory") == 0 ? 16u : std::strcmp(input, "stream") == 0 ? 32u : 0u) |
            (static_cast<DWORD>(app) << 8) | (static_cast<DWORD>(source) << 10);
        guard::QueueCapture(std::move(process), sequence, id, size, flags, *result, reason,
                            appText.value, sourceText.value, text, std::move(ast), extras);
        captured = true;
    };
    const auto reason = isPowerShell7 ? Reason(stream, *result, sizeKnown, size, input, process, capture) : "missing:app-name";
    if (!captured) capture({}, reason, {});
    return S_OK;
}

void PowerShell7Guard::CloseSession(ULONGLONG raw)
{
    if (!raw) return;
    AcquireSRWLockExclusive(&sessionLock);
    for (auto& slot : sessions) {
        if (slot.raw == raw) { slot = {}; break; }
    }
    ReleaseSRWLockExclusive(&sessionLock);
}

HRESULT PowerShell7Guard::DisplayName(LPWSTR* displayName)
{
    if (!displayName) return E_POINTER;
    constexpr wchar_t name[] = L"PowerShell7Guard";
    *displayName = static_cast<LPWSTR>(CoTaskMemAlloc(sizeof(name)));
    if (!*displayName) return E_OUTOFMEMORY;
    std::memcpy(*displayName, name, sizeof(name));
    return S_OK;
}

CoCreatableClass(PowerShell7Guard);

#pragma region Install / uninstall

HRESULT SetKeyStringValue(_In_ HKEY key, _In_opt_ PCWSTR subkey, _In_opt_ PCWSTR valueName, _In_ PCWSTR stringValue)
{
    const size_t bytes = (wcslen(stringValue) + 1) * sizeof(wchar_t);
    if (bytes > MAXDWORD) return E_INVALIDARG;
    LONG status = RegSetKeyValue(key, subkey, valueName, REG_SZ, stringValue, static_cast<DWORD>(bytes));
    return HRESULT_FROM_WIN32(status);
}

STDAPI DllRegisterServer()
{
    wchar_t modulePath[MAX_PATH];
    const DWORD pathLength = GetModuleFileName(g_currentModule, modulePath, ARRAYSIZE(modulePath));
    if (pathLength == 0 || pathLength >= ARRAYSIZE(modulePath))
    {
        return E_UNEXPECTED;
    }

    // Create a standard COM registration for our CLSID.
    // The class must be registered as "Both" threading model
    // and support multithreaded access.
    wchar_t clsidString[40];
    if (StringFromGUID2(__uuidof(PowerShell7Guard), clsidString, ARRAYSIZE(clsidString)) == 0)
    {
        return E_UNEXPECTED;
    }

    wchar_t keyPath[200];
    HRESULT hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls", clsidString);
    if (FAILED(hr)) return hr;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, L"PowerShell7Guard");
    if (FAILED(hr)) return hr;

    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls\\InProcServer32", clsidString);
    if (FAILED(hr)) return hr;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, modulePath);
    if (FAILED(hr)) return hr;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, L"ThreadingModel", L"Both");
    if (FAILED(hr)) return hr;

    // Register this CLSID as an anti-malware provider.
    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Microsoft\\AMSI\\Providers\\%ls", clsidString);
    if (FAILED(hr)) return hr;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, L"PowerShell7Guard");
    if (FAILED(hr)) return hr;

    return S_OK;
}

STDAPI DllUnregisterServer()
{
    wchar_t clsidString[40];
    if (StringFromGUID2(__uuidof(PowerShell7Guard), clsidString, ARRAYSIZE(clsidString)) == 0)
    {
        return E_UNEXPECTED;
    }

    // Unregister this CLSID as an anti-malware provider.
    wchar_t keyPath[200];
    HRESULT hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Microsoft\\AMSI\\Providers\\%ls", clsidString);
    if (FAILED(hr)) return hr;
    LONG status = RegDeleteTree(HKEY_LOCAL_MACHINE, keyPath);
    if (status != NO_ERROR && status != ERROR_PATH_NOT_FOUND && status != ERROR_FILE_NOT_FOUND) return HRESULT_FROM_WIN32(status);

    // Unregister this CLSID as a COM server.
    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls", clsidString);
    if (FAILED(hr)) return hr;
    status = RegDeleteTree(HKEY_LOCAL_MACHINE, keyPath);
    if (status != NO_ERROR && status != ERROR_PATH_NOT_FOUND && status != ERROR_FILE_NOT_FOUND) return HRESULT_FROM_WIN32(status);

    return S_OK;
}
#pragma endregion
