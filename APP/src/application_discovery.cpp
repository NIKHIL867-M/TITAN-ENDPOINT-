#include "titan_pch.h"
#include "application_discovery.h"

#include <filesystem>
#include <map>
#include <tlhelp32.h>
#include <wintrust.h>
#include <softpub.h>
#include <unordered_map>

namespace {
std::string WideToUtf8(const std::wstring& value)
{
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(),
        static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
    return result;
}

std::string Lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value;
}

std::wstring ReadStringValue(HKEY key, const wchar_t* name)
{
    DWORD type = 0;
    DWORD bytes = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes) !=
        ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) ||
        bytes < sizeof(wchar_t))
        return {};
    std::wstring value(bytes / sizeof(wchar_t), L'\0');
    if (RegQueryValueExW(key, name, nullptr, &type,
        reinterpret_cast<BYTE*>(value.data()), &bytes) != ERROR_SUCCESS)
        return {};
    while (!value.empty() && value.back() == L'\0') value.pop_back();
    if (type == REG_EXPAND_SZ && !value.empty()) {
        const DWORD required = ExpandEnvironmentStringsW(
            value.c_str(), nullptr, 0);
        if (required != 0) {
            std::wstring expanded(required, L'\0');
            ExpandEnvironmentStringsW(value.c_str(), expanded.data(), required);
            while (!expanded.empty() && expanded.back() == L'\0')
                expanded.pop_back();
            value = std::move(expanded);
        }
    }
    return value;
}

std::wstring ExecutableFromDisplayIcon(std::wstring value)
{
    if (value.empty()) return {};
    if (value.front() == L'"') {
        const size_t quote = value.find(L'"', 1);
        if (quote != std::wstring::npos) value = value.substr(1, quote - 1);
    } else {
        const size_t comma = value.rfind(L',');
        if (comma != std::wstring::npos) value.resize(comma);
    }
    while (!value.empty() && iswspace(value.back())) value.pop_back();
    std::filesystem::path path(value);
    if (_wcsicmp(path.extension().c_str(), L".exe") != 0) return {};
    return path.wstring();
}

std::string SignatureStatus(const std::wstring& path)
{
    if (path.empty() || !std::filesystem::is_regular_file(path)) return "unavailable";
    static std::unordered_map<std::wstring, std::string> cache;
    if (const auto found = cache.find(path); found != cache.end()) return found->second;

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_IGNORE;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG result = WinVerifyTrust(nullptr, &action, &trustData);
    std::string status;
    if (result == ERROR_SUCCESS) status = "trusted";
    else if (result == TRUST_E_NOSIGNATURE || result == TRUST_E_SUBJECT_FORM_UNKNOWN ||
             result == TRUST_E_PROVIDER_UNKNOWN) status = "unsigned";
    else status = "untrusted";

    if (cache.size() >= 512) cache.clear();
    cache.emplace(path, status);
    return status;
}

void AddInstalledFromUninstall(HKEY root, REGSAM view,
    std::map<std::string, DiscoveredApplication>& applications)
{
    constexpr wchar_t uninstall[] =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    HKEY parent = nullptr;
    if (RegOpenKeyExW(root, uninstall, 0, KEY_READ | view, &parent) !=
        ERROR_SUCCESS)
        return;
    DWORD index = 0;
    wchar_t subkeyName[512]{};
    DWORD nameLength = static_cast<DWORD>(std::size(subkeyName));
    while (RegEnumKeyExW(parent, index++, subkeyName, &nameLength, nullptr,
        nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        HKEY subkey = nullptr;
        if (RegOpenKeyExW(parent, subkeyName, 0, KEY_READ | view, &subkey) ==
            ERROR_SUCCESS) {
            const std::wstring display = ReadStringValue(subkey, L"DisplayName");
            const std::wstring publisher = ReadStringValue(subkey, L"Publisher");
            const std::wstring executable = ExecutableFromDisplayIcon(
                ReadStringValue(subkey, L"DisplayIcon"));
            if (!executable.empty()) {
                const std::filesystem::path path(executable);
                const std::string exe = Lower(WideToUtf8(
                    path.filename().wstring()));
                auto& app = applications[exe];
                app.executable = exe;
                app.display_name = display.empty() ? exe : WideToUtf8(display);
                app.publisher = WideToUtf8(publisher);
                app.path = executable;
                app.installed = true;
            }
            RegCloseKey(subkey);
        }
        nameLength = static_cast<DWORD>(std::size(subkeyName));
    }
    RegCloseKey(parent);
}

void AddRunning(std::map<std::string, DiscoveredApplication>& applications)
{
    DWORD currentSession = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &currentSession);
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == 0 || entry.th32ProcessID == 4 ||
                entry.th32ProcessID == GetCurrentProcessId())
                continue;
            DWORD processSession = 0;
            if (!ProcessIdToSessionId(entry.th32ProcessID, &processSession) ||
                processSession != currentSession)
                continue;
            const std::string exe = Lower(WideToUtf8(entry.szExeFile));
            if (exe.size() < 5 || exe.substr(exe.size() - 4) != ".exe")
                continue;
            auto& app = applications[exe];
            app.executable = exe;
            if (app.display_name.empty()) app.display_name = exe;
            app.pids.push_back(entry.th32ProcessID);
            if (app.path.empty()) {
                const HANDLE process = OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                    entry.th32ProcessID);
                if (process) {
                    std::wstring path(32768, L'\0');
                    DWORD length = static_cast<DWORD>(path.size());
                    if (QueryFullProcessImageNameW(
                        process, 0, path.data(), &length)) {
                        path.resize(length);
                        app.path = std::move(path);
                    }
                    CloseHandle(process);
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
}
}

std::vector<DiscoveredApplication> ApplicationDiscovery::Discover(
    const std::string& filter)
{
    std::map<std::string, DiscoveredApplication> applications;
    AddInstalledFromUninstall(HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, applications);
    AddInstalledFromUninstall(HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, applications);
    AddInstalledFromUninstall(HKEY_CURRENT_USER, KEY_WOW64_64KEY, applications);
    AddInstalledFromUninstall(HKEY_CURRENT_USER, KEY_WOW64_32KEY, applications);
    AddRunning(applications);

    const std::string loweredFilter = Lower(filter);
    std::vector<DiscoveredApplication> result;
    for (auto& [name, application] : applications) {
        const std::string searchable = Lower(application.display_name + " " +
            application.executable + " " + application.publisher + " " + WideToUtf8(application.path));
        if (!loweredFilter.empty() &&
            searchable.find(loweredFilter) == std::string::npos)
            continue;
        std::sort(application.pids.begin(), application.pids.end());
        application.signature_status = SignatureStatus(application.path);
        result.push_back(std::move(application));
    }
    std::stable_sort(result.begin(), result.end(),
        [](const auto& left, const auto& right) {
            if (left.IsRunning() != right.IsRunning())
                return left.IsRunning() > right.IsRunning();
            return left.display_name < right.display_name;
        });
    return result;
}
