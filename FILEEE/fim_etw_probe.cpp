#include <windows.h>

#include <filesystem>
#include <iostream>
#include <string>

namespace
{
    bool ExercisePath(const std::filesystem::path& original,
        const std::filesystem::path& renamed)
    {
        HANDLE file = CreateFileW(original.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        CloseHandle(file);
        Sleep(1500);

        file = CreateFileW(original.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;

        static constexpr char payload[] = "TITAN live ETW validation\n";
        DWORD written = 0;
        const BOOL write_ok = WriteFile(file, payload,
            static_cast<DWORD>(sizeof(payload) - 1), &written, nullptr);
        FlushFileBuffers(file);
        CloseHandle(file);
        if (!write_ok || written != static_cast<DWORD>(sizeof(payload) - 1))
            return false;
        Sleep(1500);

        if (!MoveFileExW(original.c_str(), renamed.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            return false;
        return DeleteFileW(renamed.c_str()) == TRUE;
    }
}

int wmain(int argc, wchar_t** argv)
{
    wchar_t exe_path[32768] = {};
    const DWORD exe_len = GetModuleFileNameW(nullptr, exe_path,
        static_cast<DWORD>(std::size(exe_path)));
    if (exe_len == 0 || exe_len >= static_cast<DWORD>(std::size(exe_path)))
        return 2;

    wchar_t temp_path[32768] = {};
    const DWORD temp_len = GetTempPathW(static_cast<DWORD>(std::size(temp_path)),
        temp_path);
    if (temp_len == 0 || temp_len >= static_cast<DWORD>(std::size(temp_path)))
        return 3;

    const auto exe_dir = std::filesystem::path(exe_path).parent_path();
    const auto temp_dir = std::filesystem::path(temp_path);
    const DWORD pid = GetCurrentProcessId();
    const std::wstring suffix = std::to_wstring(pid);

    if (argc == 3 && _wcsicmp(argv[1], L"--burst") == 0)
    {
        const unsigned long requested = wcstoul(argv[2], nullptr, 10);
        if (requested == 0 || requested > 100000) return 4;
        static constexpr char byte = 'X';
        for (unsigned long i = 0; i < requested; ++i)
        {
            const auto path = temp_dir / (L"titan_etw_burst_" + suffix +
                L"_" + std::to_wstring(i) + L".tmp");
            HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
            if (file == INVALID_HANDLE_VALUE) return 5;
            DWORD written = 0;
            WriteFile(file, &byte, 1, &written, nullptr);
            CloseHandle(file);
            DeleteFileW(path.c_str());
        }
        std::wcout << L"burst=" << requested << L" pid=" << pid << L"\n";
        return 0;
    }

    if (argc == 2 && _wcsicmp(argv[1], L"--correlation") == 0)
    {
        const auto temp_source = temp_dir /
            (L"titan_stage_a_" + suffix + L".tmp");
        const auto second_temp_source = temp_dir /
            (L"titan_stage_b_" + suffix + L".tmp");
        const auto dll_target = exe_dir /
            (L"titan_target_" + suffix + L".dll");
        const auto promoted_dll = exe_dir /
            (L"titan_promoted_" + suffix + L".dll");

        HANDLE temp = CreateFileW(temp_source.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (temp == INVALID_HANDLE_VALUE) return 6;
        static constexpr char staging[] = "short temp staging content";
        DWORD written = 0;
        WriteFile(temp, staging, static_cast<DWORD>(sizeof(staging) - 1),
            &written, nullptr);
        CloseHandle(temp);

        temp = CreateFileW(second_temp_source.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (temp == INVALID_HANDLE_VALUE) return 9;
        static constexpr char second_staging[] =
            "second simultaneous temp staging content";
        WriteFile(temp, second_staging,
            static_cast<DWORD>(sizeof(second_staging) - 1),
            &written, nullptr);
        CloseHandle(temp);
        Sleep(500);

        HANDLE dll = CreateFileW(dll_target.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (dll == INVALID_HANDLE_VALUE) return 7;
        static constexpr char dll_data[] = "MZ correlation test";
        WriteFile(dll, dll_data, static_cast<DWORD>(sizeof(dll_data) - 1),
            &written, nullptr);
        CloseHandle(dll);
        Sleep(500);

        if (!MoveFileExW(temp_source.c_str(), promoted_dll.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            return 8;
        Sleep(500);
        DeleteFileW(second_temp_source.c_str());
        DeleteFileW(dll_target.c_str());
        DeleteFileW(promoted_dll.c_str());
        std::wcout << L"correlation=2 pid=" << pid << L"\n";
        return 0;
    }

    const bool normal_ok = ExercisePath(
        exe_dir / (L"titan_etw_normal_" + suffix + L".txt"),
        exe_dir / (L"titan_etw_normal_" + suffix + L"_renamed.txt"));
    const bool temp_ok = ExercisePath(
        temp_dir / (L"titan_etw_temp_" + suffix + L".tmp"),
        temp_dir / (L"titan_etw_temp_" + suffix + L"_renamed.tmp"));

    std::wcout << L"normal=" << normal_ok << L" temp=" << temp_ok
        << L" pid=" << pid << L"\n";
    return normal_ok && temp_ok ? 0 : 1;
}
