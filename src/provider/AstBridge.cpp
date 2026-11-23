#include "AstBridge.h"
#include <windows.h>
#include <cstring>

extern HMODULE g_currentModule;
namespace guard {
namespace {
using HostDelegate = int (__cdecl*)(void*, int, void**);
using LoadBytes = int (WINAPI*)(const void*, size_t, const void*, size_t, void*, void*);
using FindMethod = int (WINAPI*)(LPCWSTR, LPCWSTR, LPCWSTR, void*, void*, void**);
using Run = int (WINAPI*)(void*, int);
struct Request { const wchar_t* source; char* output; int length, capacity, decision; };
struct LoadRequest { const void* bytes; int length; Run analyze; };

template<class T> T Export(HMODULE module, const char* name) noexcept {
    const auto address = GetProcAddress(module, name);
    static_assert(sizeof(T) == sizeof(address));
    T target = nullptr;
    std::memcpy(&target, &address, sizeof(target));
    return target;
}

Run Initialize() noexcept {
    // Do not start a second runtime or load an external DLL. Reuse pwsh's CoreCLR.
    const auto host = GetModuleHandleW(L"hostfxr.dll");
    if (!host) return nullptr;
    const auto get = Export<HostDelegate>(host, "hostfxr_get_runtime_delegate");
    void* bytes = nullptr;
    void* find = nullptr;
    if (!get || get(nullptr, 8, &bytes) != 0 || get(nullptr, 6, &find) != 0 || !bytes || !find) return nullptr;
    auto embedded = [](WORD id, DWORD& length) noexcept -> const void* {
        const auto resource = FindResourceW(g_currentModule, MAKEINTRESOURCEW(id), MAKEINTRESOURCEW(10));
        if (!resource) return nullptr;
        length = SizeofResource(g_currentModule, resource);
        const auto handle = LoadResource(g_currentModule, resource);
        return handle ? LockResource(handle) : nullptr;
    };
    DWORD loaderLength = 0, astLength = 0;
    const auto loader = embedded(102, loaderLength);
    const auto ast = embedded(101, astLength);
    if (!loader || !ast || !loaderLength || !astLength || astLength > 2 * 1024 * 1024) return nullptr;
    // Only the small stable loader goes into the default context. If another
    // Guard already loaded it, the same ABI is available via its fixed name.
    reinterpret_cast<LoadBytes>(bytes)(loader, loaderLength, nullptr, 0, nullptr, nullptr);
    void* method = nullptr;
    if (reinterpret_cast<FindMethod>(find)(L"PowerShell7Guard.Loader.Entry, PowerShell7Guard.Loader",
         L"Open", nullptr, nullptr, nullptr, &method) != 0 || !method) return nullptr;
    LoadRequest load{ast, static_cast<int>(astLength), nullptr};
    if (reinterpret_cast<Run>(method)(&load, sizeof(load)) != 0) return nullptr;
    return load.analyze;
}

Run analyzer = nullptr;
BOOL CALLBACK InitializeOnce(PINIT_ONCE, PVOID, PVOID*) noexcept {
    static ULONGLONG retryAt = 0;
    if (GetTickCount64() < retryAt) return FALSE;
    analyzer = Initialize();
    if (!analyzer) retryAt = GetTickCount64() + 500;
    return analyzer != nullptr;
}
}

static int Analyze(Request& req) noexcept {
    // Native calls made by the parser or loader must not re-enter AST evaluation.
    static thread_local bool active = false;
    if (active || !GetModuleHandleW(L"hostfxr.dll")) return -1;
    active = true;
    struct Reset { bool& flag; ~Reset() { flag = false; } } reset{active};
    try {
        static INIT_ONCE initialized = INIT_ONCE_STATIC_INIT;
        if (!InitOnceExecuteOnce(&initialized, InitializeOnce, nullptr, nullptr)) return -1;
        return analyzer(&req, sizeof(req));
    } catch (...) { return -1; }
}

unsigned AmsiContentLimit() noexcept {
    Request query{};
    const int limit = Analyze(query);
    return limit > 0 ? static_cast<unsigned>(limit) : 65536u;
}

AstResult ParseAst(std::wstring_view text) noexcept {
    try {
        AstResult out;
        Request query{};
        query.capacity = -1;
        const int capacity = Analyze(query);
        if (capacity <= 0) {
            out.json = R"({"status":"unavailable"})";
            return out;
        }
        out.json.resize(static_cast<size_t>(capacity));
        Request req{text.data(), out.json.data(), static_cast<int>(text.size()), static_cast<int>(out.json.size()), -1};
        const int result = Analyze(req);
        out.decision = req.decision;
        if (result < 0 || result > req.capacity) {
            switch (result) {
                case -2: out.json = R"({"status":"external-using-skipped"})"; break;
                case -4: out.json = R"({"status":"script-byte-limit"})"; break;
                case -3: out.json = R"({"status":"output-limit"})"; break;
                default: out.json = R"({"status":"unavailable"})"; break;
            }
        } else {
            out.json.resize(result);
        }
        return out;
    } catch (...) { return {}; }
}
}
