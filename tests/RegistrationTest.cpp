#include <windows.h>
#include <cstring>
#include <iostream>
#include <string>

namespace {
struct Library {
    HMODULE handle;
    ~Library() { if (handle) FreeLibrary(handle); }
};
struct Registry {
    HKEY key{};
    ~Registry() { if (key) RegCloseKey(key); }
};
struct Override {
    bool active;
    ~Override() { if (active) RegOverridePredefKey(HKEY_LOCAL_MACHINE, nullptr); }
};

bool ValueIs(HKEY root, PCWSTR path, PCWSTR name, const std::wstring& expected)
{
    wchar_t value[32768]{};
    DWORD length = sizeof(value);
    return RegGetValueW(root, path, name, RRF_RT_REG_SZ, nullptr, value, &length) == ERROR_SUCCESS &&
        expected == value;
}
bool Missing(HKEY root, PCWSTR path)
{
    Registry sub;
    return RegOpenKeyExW(root, path, 0, KEY_READ, &sub.key) == ERROR_FILE_NOT_FOUND;
}
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 3) return 2;
    Library dll{LoadLibraryExW(argv[1], nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)};
    if (!dll.handle) { std::cerr << "LoadLibraryExW win32=" << GetLastError() << '\n'; return 2; }
    using Registration = HRESULT (WINAPI*)();
    Registration install{}, uninstall{};
    const auto installEntry = GetProcAddress(dll.handle, "DllRegisterServer");
    const auto uninstallEntry = GetProcAddress(dll.handle, "DllUnregisterServer");
    static_assert(sizeof(installEntry) == sizeof(install));
    std::memcpy(&install, &installEntry, sizeof(install));
    std::memcpy(&uninstall, &uninstallEntry, sizeof(uninstall));
    if (!install || !uninstall) return 2;
    Registry isolated;
    auto status = RegLoadAppKeyW(argv[2], &isolated.key, KEY_ALL_ACCESS, REG_PROCESS_APPKEY, 0);
    if (status != ERROR_SUCCESS) { std::cerr << "RegLoadAppKeyW win32=" << status << '\n'; return 2; }
    status = RegOverridePredefKey(HKEY_LOCAL_MACHINE, isolated.key);
    if (status != ERROR_SUCCESS) { std::cerr << "RegOverridePredefKey win32=" << status << '\n'; return 2; }
    Override mapped{true};
    constexpr wchar_t provider[] = L"SOFTWARE\\Microsoft\\AMSI\\Providers\\{B19A3622-9E37-46C6-9A76-D48332292DC7}";
    constexpr wchar_t clsid[] = L"SOFTWARE\\Classes\\CLSID\\{B19A3622-9E37-46C6-9A76-D48332292DC7}";
    const auto server = std::wstring(clsid) + L"\\InProcServer32";
    wchar_t image[32768]{};
    const auto length = GetModuleFileNameW(dll.handle, image, ARRAYSIZE(image));
    if (!length || length >= ARRAYSIZE(image)) return 2;
    const auto added = install();
    const bool keys = ValueIs(isolated.key, provider, nullptr, L"PowerShell7Guard") &&
        ValueIs(isolated.key, server.c_str(), nullptr, image) &&
        ValueIs(isolated.key, server.c_str(), L"ThreadingModel", L"Both");
    const auto removed = uninstall();
    const bool clean = Missing(isolated.key, provider) && Missing(isolated.key, clsid);
    std::cout << "DllRegisterServer HRESULT=0x" << std::hex << added << "; expected keys=" << keys << '\n'
              << "DllUnregisterServer HRESULT=0x" << removed << "; expected keys removed=" << clean << '\n';
    return added == S_OK && keys && removed == S_OK && clean ? 0 : 1;
}
