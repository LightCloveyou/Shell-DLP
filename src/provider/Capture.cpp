#define NOMINMAX
#include "Capture.h"
#include "JournalPath.h"
#include <lmcons.h>
#include <sddl.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace guard {
namespace {
constexpr LONG maxQueued = 32;
constexpr DWORD maxLogBytes = 5 * 1024 * 1024;
volatile LONG pending = 0;
const int moduleMarker = 0;

struct Handle {
    HANDLE value;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};

ULONGLONG Ticks(FILETIME time) noexcept {
    return (static_cast<ULONGLONG>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

std::wstring Image(HANDLE process) {
    std::wstring path(32768, L'\0');
    DWORD length = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(process, 0, path.data(), &length)) return {};
    path.resize(length);
    return path;
}

std::wstring ParentCommandLine(HANDLE parent) {
    using Query = NTSTATUS (NTAPI*)(HANDLE, PROCESSINFOCLASS, void*, ULONG, ULONG*);
    const auto address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    Query query = nullptr;
    std::memcpy(&query, &address, sizeof(query));
    if (!query) return {};
    const auto commandLineClass = static_cast<PROCESSINFOCLASS>(60);
    ULONG size = 0;
    query(parent, commandLineClass, nullptr, 0, &size);
    if (size < sizeof(UNICODE_STRING) || size > 128 * 1024) return {};
    std::vector<BYTE> buffer(size);
    if (query(parent, commandLineClass, buffer.data(), size, &size) < 0) return {};
    const auto& str = *reinterpret_cast<const UNICODE_STRING*>(buffer.data());
    const auto begin = reinterpret_cast<ULONG_PTR>(buffer.data());
    const auto ptr = reinterpret_cast<ULONG_PTR>(str.Buffer);
    if (str.Length % sizeof(wchar_t) || ptr < begin || ptr - begin > buffer.size() ||
        str.Length > buffer.size() - (ptr - begin)) return {};
    return {str.Buffer, str.Length / sizeof(wchar_t)};
}

ProcessInfo ProcessSnapshot() {
    ProcessInfo p;
    const auto current = GetCurrentProcess();
    const auto pid = GetCurrentProcessId();
    p.image = Image(current);
    p.commandLine = GetCommandLineW();
    ProcessIdToSessionId(pid, &p.windowsSession);
    USHORT machine = 0, native = 0;
    if (IsWow64Process2(current, &machine, &native)) {
        p.architecture = machine ? machine : native;
        p.nativeArchitecture = native;
    }
    FILETIME created{}, exit{}, kernel{}, user{};
    if (GetProcessTimes(current, &created, &exit, &kernel, &user)) p.created = Ticks(created);
    Handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    if (snapshot.value != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot.value, &entry)) {
            do {
                if (entry.th32ProcessID == pid) { p.ppid = entry.th32ParentProcessID; break; }
            } while (Process32NextW(snapshot.value, &entry));
        }
    }
    if (p.ppid && p.created) {
        Handle parent{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.ppid)};
        if (parent.value && GetProcessTimes(parent.value, &created, &exit, &kernel, &user) &&
            Ticks(created) <= p.created) {
            p.parentCreated = Ticks(created);
            p.parentImage = Image(parent.value);
            p.parentCommandLine = ParentCommandLine(parent.value);
        }
    }

    Handle token{nullptr};
    if (OpenProcessToken(current, TOKEN_QUERY, &token.value)) {
        TOKEN_ELEVATION elevation{};
        DWORD size = 0;
        if (GetTokenInformation(token.value, TokenElevation, &elevation, sizeof(elevation), &size))
            p.elevated = elevation.TokenIsElevated != 0;
        auto readToken = [&](TOKEN_INFORMATION_CLASS info) {
            DWORD required = 0;
            GetTokenInformation(token.value, info, nullptr, 0, &required);
            if (!required || required > 4096) return std::vector<BYTE>{};
            std::vector<BYTE> data(required);
            if (!GetTokenInformation(token.value, info, data.data(), required, &required)) data.clear();
            return data;
        };
        auto userData = readToken(TokenUser);
        if (!userData.empty()) {
            const auto sid = reinterpret_cast<const TOKEN_USER*>(userData.data())->User.Sid;
            LPWSTR text = nullptr;
            if (ConvertSidToStringSidW(sid, &text)) {
                const auto release = [](wchar_t* value) { LocalFree(value); };
                const std::unique_ptr<wchar_t, decltype(release)> owner(text, release);
                p.userSid = text;
            }
        }
        auto integrityData = readToken(TokenIntegrityLevel);
        if (!integrityData.empty()) {
            const auto sid = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(integrityData.data())->Label.Sid;
            const auto n = *GetSidSubAuthorityCount(sid);
            if (n) p.integrity = *GetSidSubAuthority(sid, n - 1);
        }
    }
    wchar_t userName[UNLEN + 1]{};
    DWORD nameSize = ARRAYSIZE(userName);
    if (GetUserNameW(userName, &nameSize) && nameSize) p.userName.assign(userName, nameSize - 1);
    return p;
}

struct Item {
    ProcessContext process;
    HMODULE reference = nullptr;
    ULONGLONG sequence, session, size, timestamp;
    DWORD flags, result;
    const char* reason;
    CaptureExtras extras;
    std::wstring app, source, content;
    std::string ast;
    ~Item() {
        for (auto* s : {&app, &source, &content}) {
            if (!s->empty()) SecureZeroMemory(s->data(), s->size() * sizeof(wchar_t));
        }
        if (!ast.empty()) SecureZeroMemory(ast.data(), ast.size());
    }
};

volatile LONG dropped = 0;

void JsonText(std::string& out, std::wstring_view value) {
    out += '"';
    if (!value.empty()) {
        const int bytes = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                                               nullptr, 0, nullptr, nullptr);
        std::string utf8(bytes > 0 ? bytes : 0, '\0');
        if (bytes > 0)
            WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), utf8.data(), bytes, nullptr, nullptr);
        constexpr char hex[] = "0123456789abcdef";
        for (unsigned char c : utf8) {
            if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
            else if (c < 0x20) { out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15]; }
            else out += static_cast<char>(c);
        }
        if (!utf8.empty()) SecureZeroMemory(utf8.data(), utf8.size());
    }
    out += '"';
}

struct Json {
    std::string bytes;
    ~Json() { if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size()); }
    void Key(const char* name) {
        if (bytes.back() != '{') bytes += ',';
        bytes += '"'; bytes += name; bytes += "\":";
    }
    void Text(const char* name, std::wstring_view text) {
        if (!text.empty()) { Key(name); JsonText(bytes, text); }
    }
    void Number(const char* name, ULONGLONG n) { Key(name); bytes += std::to_string(n); }
    void Boolean(const char* name, bool value) { Key(name); bytes += value ? "true" : "false"; }
    void Raw(const char* name, const char* value) { Key(name); bytes += value; }
    void Open(const char* name) { Raw(name, "{"); }
    void End() { bytes += '}'; }
};

std::wstring TimeText(ULONGLONG ticks) {
    if (!ticks) return {};
    const FILETIME ft{static_cast<DWORD>(ticks), static_cast<DWORD>(ticks >> 32)};
    SYSTEMTIME t{};
    if (!FileTimeToSystemTime(&ft, &t)) return {};
    wchar_t buf[40]{};
    swprintf_s(buf, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", t.wYear, t.wMonth, t.wDay,
               t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
    return buf;
}

void Serialize(Json& j, const Item& item, LONG lost) {
    const auto& info = item.process.fixed;
    j.bytes += '{';
    j.Number("schema", 1);
    j.Text("timestamp", TimeText(item.timestamp));
    const bool missing = std::strncmp(item.reason, "missing:", 8) == 0;
    j.Raw("decision", item.result == 0x4000 ? "\"Block\"" : "\"NotDetected\"");
    const bool warning = missing || std::strncmp(item.reason, "warn:", 5) == 0;
    j.Raw("severity", warning ? "\"Warning\"" : "\"Information\"");
    if (missing) j.Raw("message", "\"Information missing\"");
    j.Text("reason", std::wstring(item.reason, item.reason + std::strlen(item.reason)));
    j.Number("result", item.result);
    if (lost > 0) j.Number("dropped", lost);
    j.Open("process");
    j.Number("pid", item.process.pid); j.Number("tid", item.process.tid);
    j.Text("cwd", item.process.cwd);
    if (info) {
        if (info->ppid) j.Number("ppid", info->ppid);
        if (info->windowsSession != MAXDWORD) j.Number("windowsSession", info->windowsSession);
        if (info->elevated != MAXDWORD) j.Boolean("elevated", info->elevated != 0);
        if (info->integrity != MAXDWORD) j.Number("integrity", info->integrity);
        if (info->architecture) j.Number("architecture", info->architecture);
        if (info->nativeArchitecture) j.Number("nativeArchitecture", info->nativeArchitecture);
        j.Text("created", TimeText(info->created)); j.Text("parentCreated", TimeText(info->parentCreated));
        j.Text("image", info->image); j.Text("commandLine", info->commandLine); j.Text("userSid", info->userSid);
        j.Text("userName", info->userName); j.Text("parentImage", info->parentImage);
        j.Text("parentCommandLine", info->parentCommandLine);
    }
    j.End();
    j.Open("amsi");
    j.Text("appName", item.app); j.Text("contentName", item.source); j.Text("content", item.content);
    j.Number("appNameState", (item.flags >> 8) & 3); j.Number("contentNameState", (item.flags >> 10) & 3);
    if (item.flags & 1) j.Number("contentSize", item.size);
    if (item.flags & 16) j.Raw("contentInput", "\"memory\"");
    if (item.flags & 32) j.Raw("contentInput", "\"stream\"");
    if (item.flags & 4) j.Boolean("sessionPresent", (item.flags & 8) != 0);
    if (item.session) j.Number("session", item.session);
    j.Number("scanSequence", item.sequence);
    if (item.extras.known & 1) j.Number("redirectChainSize", item.extras.redirectChainSize);
    if (item.extras.known & 2) j.Number("allSize", item.extras.allSize);
    if (item.extras.known & 4) j.Boolean("redirectChainAddressPresent", (item.extras.values & 4) != 0);
    if (item.extras.known & 8) j.Boolean("allAddressPresent", (item.extras.values & 8) != 0);
    if (item.extras.known & 16) j.Boolean("quiet", (item.extras.values & 16) != 0);
    j.End();
    j.Raw("ast", item.ast.empty() ? "{\"status\":\"unavailable\"}" : item.ast.c_str());
    j.End();
    j.bytes += '\n';
}

bool RegularHandle(HANDLE h, bool directory) {
    BY_HANDLE_FILE_INFORMATION info{};
    return h != INVALID_HANDLE_VALUE && GetFileInformationByHandle(h, &info) &&
        !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
        ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == directory &&
        (directory || (info.nNumberOfLinks == 1 && GetFileType(h) == FILE_TYPE_DISK));
}

bool Seek(HANDLE file, LONGLONG pos) {
    LARGE_INTEGER where{};
    where.QuadPart = pos;
    return SetFilePointerEx(file, where, nullptr, FILE_BEGIN) != 0;
}

bool WriteBytes(HANDLE file, std::string_view bytes) {
    if (bytes.empty()) return true;
    DWORD written = 0;
    return WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
        written == bytes.size();
}

bool TrimIncompleteTail(HANDLE file, LONGLONG& size) {
    if (size == 0) return true;
    char last = 0;
    DWORD read = 0;
    if (!Seek(file, size - 1) || !ReadFile(file, &last, 1, &read, nullptr) || read != 1) return false;
    if (last == '\n') return true;

    // A failed or interrupted write may leave a fragment. Drop only that
    // fragment, and never search more than one maximum-size record.
    const LONGLONG floor = size > maxLogBytes / 2 ? size - maxLogBytes / 2 : 0;
    constexpr LONGLONG ChunkSize = 4096;
    char chunk[ChunkSize];
    for (LONGLONG end = size; end > floor;) {
        const auto count = static_cast<DWORD>(end - floor > ChunkSize ? ChunkSize : end - floor);
        const auto start = end - count;
        const bool readAll = Seek(file, start) && ReadFile(file, chunk, count, &read, nullptr) && read == count;
        const auto newline = readAll ? std::string_view(chunk, count).rfind('\n') : std::string_view::npos;
        SecureZeroMemory(chunk, sizeof(chunk));
        if (!readAll) return false;
        if (newline != std::string_view::npos) {
            size = start + static_cast<LONGLONG>(newline) + 1;
            return Seek(file, size) && SetEndOfFile(file);
        }
        end = start;
    }
    if (floor != 0) return false;
    size = 0;
    return Seek(file, size) && SetEndOfFile(file);
}

bool Append(std::string_view line) {
    if (line.size() > maxLogBytes / 2) return false;
    // Every host uses the same build-time project directory, regardless of
    // LocalAppData redirection or the host's current working directory.
    const std::wstring dir = JournalDirectory;
    if (!CreateDirectoryW(dir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return false;
    Handle directory{CreateFileW(dir.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    if (!RegularHandle(directory.value, true)) return false;
    const auto filename = dir + L"\\events.jsonl";
    Handle file{CreateFileW(filename.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    if (!RegularHandle(file.value, false)) return false;
    OVERLAPPED lock{};
    lock.Offset = maxLogBytes + 1; // serialize writers, without locking the bytes read by the viewer
    for (unsigned attempt = 0; ; ++attempt) {
        if (LockFileEx(file.value, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lock)) break;
        if (GetLastError() != ERROR_LOCK_VIOLATION || attempt == 9) return false;
        Sleep(2);
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.value, &size) || size.QuadPart < 0 || !TrimIncompleteTail(file.value, size.QuadPart))
        return false;
    if (size.QuadPart > maxLogBytes - static_cast<LONGLONG>(line.size())) {
        // Keep recent complete records, never create a second log or a rotation backup.
        const auto from = size.QuadPart > maxLogBytes / 2 ? size.QuadPart - maxLogBytes / 2 : 0;
        std::string tail(static_cast<size_t>(size.QuadPart - from), '\0');
        DWORD read = 0;
        if (!Seek(file.value, from) || !ReadFile(file.value, tail.data(), static_cast<DWORD>(tail.size()), &read, nullptr))
            return false;
        tail.resize(read);
        const auto first = from ? tail.find('\n') : 0;
        const auto last = tail.rfind('\n');
        const auto start = from ? first + 1 : 0;
        const auto keep = first == std::string::npos || last == std::string::npos || last < start
            ? std::string_view{} : std::string_view(tail).substr(start, last - start + 1);
        if (!Seek(file.value, 0) || !WriteBytes(file.value, keep) || !SetEndOfFile(file.value)) return false;
        if (!tail.empty()) SecureZeroMemory(tail.data(), tail.size());
    } else if (!Seek(file.value, size.QuadPart)) return false;
    return WriteBytes(file.value, line);
}

void CALLBACK Send(PTP_CALLBACK_INSTANCE callback, void* context) noexcept {
    std::unique_ptr<Item> item(static_cast<Item*>(context));
    FreeLibraryWhenCallbackReturns(callback, item->reference);
    const LONG lost = InterlockedExchange(&dropped, 0);
    bool saved = false;
    try {
        Json json;
        Serialize(json, *item, lost);
        saved = Append(json.bytes);
    } catch (...) {}
    if (!saved) InterlockedExchangeAdd(&dropped, lost + 1);
    item.reset();
    InterlockedDecrement(&pending);
}
}

ProcessContext SnapshotContext() noexcept {
    ProcessContext result{};
    result.pid = GetCurrentProcessId();
    result.tid = GetCurrentThreadId();
    try {
        static const ProcessInfo info = ProcessSnapshot();
        result.fixed = &info;
        const DWORD required = GetCurrentDirectoryW(0, nullptr);
        if (required && required <= 32768) {
            result.cwd.resize(required);
            const DWORD available = GetCurrentDirectoryW(required, result.cwd.data());
            result.cwd.resize(available < required ? available : 0);
        }
    } catch (...) {}
    return result;
}

void QueueCapture(ProcessContext&& process, ULONGLONG sequence, ULONGLONG session, ULONGLONG size,
                  DWORD flags, DWORD result, const char* reason, std::wstring_view app,
                  std::wstring_view source, std::wstring_view content, std::string&& ast,
                  CaptureExtras extras) noexcept {
    if (InterlockedIncrement(&pending) > maxQueued) {
        InterlockedIncrement(&dropped);
        InterlockedDecrement(&pending);
        return;
    }
    HMODULE reference = nullptr;
    try {
        auto item = std::make_unique<Item>();
        item->process = std::move(process);
        item->sequence = sequence; item->session = session; item->size = size;
        item->flags = flags; item->result = result; item->reason = reason; item->extras = extras;
        FILETIME now{};
        GetSystemTimePreciseAsFileTime(&now);
        item->timestamp = Ticks(now);
        item->app = app; item->source = source; item->content = content; item->ast = std::move(ast);
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                               reinterpret_cast<LPCWSTR>(&moduleMarker), &reference)) {
            item->reference = reference;
            auto* raw = item.release();
            if (TrySubmitThreadpoolCallback(Send, raw, nullptr)) return;
            item.reset(raw);
        }
    } catch (...) {}
    if (reference) FreeLibrary(reference);
    InterlockedIncrement(&dropped);
    InterlockedDecrement(&pending);
}
}
