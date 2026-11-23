#include "Policy.h"

namespace guard {
namespace {
using Text = std::wstring_view;
constexpr Text Horizontal = L" \t";

wchar_t Lower(wchar_t c) noexcept {
    return c >= L'A' && c <= L'Z' ? c + (L'a' - L'A') : c;
}

bool Equals(Text a, Text b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (Lower(a[i]) != Lower(b[i])) return false;
    return true;
}

bool StartsWith(Text s, Text prefix) noexcept {
    return Equals(s.substr(0, prefix.size()), prefix);
}

void TrimStart(Text& s) noexcept {
    const auto pos = s.find_first_not_of(Horizontal);
    s.remove_prefix(pos == Text::npos ? s.size() : pos);
}

Text Word(Text& s) noexcept {
    const auto word = s.substr(0, s.find_first_of(Horizontal));
    s.remove_prefix(word.size());
    TrimStart(s);
    return word;
}

// Only a standalone, ASCII-single-quoted literal is in scope.
bool Literal(Text& s, Text& out) noexcept {
    if (s.empty() || s.front() != L'\'') return false;
    const auto end = s.find(L'\'', 1);
    if (end == Text::npos) return false;
    out = s.substr(1, end - 1);
    if (out.find_first_of(L"\u2018\u2019\u201a\u201b") != Text::npos) return false;
    s.remove_prefix(end + 1);
    if (!s.empty() && Horizontal.find(s.front()) == Text::npos) return false;
    TrimStart(s);
    return true;
}

bool HttpUri(Text uri) noexcept {
    if (StartsWith(uri, L"https://")) uri.remove_prefix(8);
    else if (StartsWith(uri, L"http://")) uri.remove_prefix(7);
    else return false;
    const auto authority = uri.substr(0, uri.find_first_of(L"/?#"));
    if (authority.empty()) return false;
    for (auto c : authority) {
        c = Lower(c);
        if (!((c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') ||
              c == L'.' || c == L'-' || c == L':')) return false;
    }
    for (auto c : uri) if (c <= L' ' || c >= 127 || c == L'\\') return false;
    return true;
}
}

bool IsPowerShell7(std::wstring_view app) noexcept {
    constexpr Text prefix = L"PowerShell_";
    if (!StartsWith(app, prefix)) return false;
    app.remove_prefix(prefix.size());
    const auto slash = app.find_last_of(L"\\/");
    if (slash != Text::npos) app.remove_prefix(slash + 1);
    constexpr Text image = L"pwsh.exe_7.";
    return StartsWith(app, image) && app.size() > image.size() &&
        app[image.size()] >= L'0' && app[image.size()] <= L'9';
}

Decision Evaluate(std::wstring_view s) noexcept {
    const auto last = s.find_last_not_of(L" \t\r\n");
    if (last == Text::npos) return Decision::Uncovered;
    s = s.substr(0, last + 1);
    const auto first = s.find_first_not_of(L" \t\r\n");
    s.remove_prefix(first);
    for (const auto c : s) if (c < L' ' && c != L'\t') return Decision::Uncovered;

    const auto cmd = Word(s);
    if (Equals(cmd, L"curl") || Equals(cmd, L"curl.exe") || Equals(cmd, L"scp") || Equals(cmd, L"scp.exe") ||
        Equals(cmd, L"wget") || Equals(cmd, L"wget.exe") || Equals(cmd, L"ncat") || Equals(cmd, L"ncat.exe") ||
        Equals(cmd, L"sftp") || Equals(cmd, L"sftp.exe") || Equals(cmd, L"Start-BitsTransfer") ||
        Equals(cmd, L"robocopy") || Equals(cmd, L"robocopy.exe") || Equals(cmd, L"xcopy") || Equals(cmd, L"xcopy.exe") ||
        Equals(cmd, L"iwr") || Equals(cmd, L"irm") ||
        ((Equals(cmd, L"git") || Equals(cmd, L"git.exe")) && Equals(Word(s), L"push")))
        return Decision::InformationMissing;
    if (!Equals(cmd, L"Invoke-WebRequest") && !Equals(cmd, L"Invoke-RestMethod"))
        return Decision::Uncovered;

    Text method, uri, body;
    bool hasMethod = false, hasUri = false, hasBody = false;
    while (!s.empty()) {
        const auto key = Word(s);
        if (Equals(key, L"-Method") && !hasMethod) {
            hasMethod = true;
            if (!s.empty() && s.front() == L'\'') {
                if (!Literal(s, method)) return Decision::InformationMissing;
            } else {
                method = Word(s);
                if (method.empty() || method.find_first_of(L"$\x60\"") != Text::npos)
                    return Decision::InformationMissing;
            }
        } else if (Equals(key, L"-Uri") && !hasUri) {
            hasUri = true;
            if (!Literal(s, uri)) return Decision::InformationMissing;
        } else if (Equals(key, L"-Body") && !hasBody) {
            hasBody = true;
            if (!Literal(s, body)) return Decision::InformationMissing;
        } else return Decision::Uncovered;
    }
    if (!hasMethod || !hasUri || !hasBody) return Decision::InformationMissing;
    if (!HttpUri(uri) ||
        !(Equals(method, L"Post") || Equals(method, L"Put") || Equals(method, L"Patch")))
        return Decision::Uncovered;
    return Decision::InformationMissing; // the native fallback never applies policy
}
}
