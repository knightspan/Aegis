#include <windows.h>

#include <string>
#include <vector>

// AEGIS.exe: starts the NetBeans platform launcher bin\aegis64.exe with the
// bundled Java runtime and the AEGIS user profile. The platform launcher reads
// etc\<its own name>.conf, so the package ships etc\aegis.conf and
// etc\aegis.clusters beside it.

static bool file_exists(const std::wstring &path)
{
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

static bool is_jdk(const std::wstring &home)
{
    return !home.empty() && file_exists(home + L"\\bin\\java.exe");
}

// The runtime shipped beside the launcher first; JAVA_HOME only for a build without one.
static std::wstring jdk_home(const std::wstring &dir)
{
    if (is_jdk(dir + L"\\jre"))
    {
        return dir + L"\\jre";
    }
    wchar_t env[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"JAVA_HOME", env, MAX_PATH);
    if (n > 0 && n < MAX_PATH && is_jdk(env))
    {
        return env;
    }
    return L"";
}

static std::wstring env_dir(const wchar_t *name)
{
    wchar_t buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(name, buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH)
    {
        return buf;
    }
    return L"";
}

static std::wstring quote(const std::wstring &value)
{
    std::wstring out = L"\"";
    for (wchar_t ch : value)
    {
        if (ch == L'"')
        {
            out += L"\\\"";
        }
        else
        {
            out += ch;
        }
    }
    out += L"\"";
    return out;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    wchar_t self[MAX_PATH];
    DWORD self_len = GetModuleFileNameW(nullptr, self, MAX_PATH);
    if (self_len == 0 || self_len >= MAX_PATH)
    {
        return 1;
    }
    std::wstring dir(self, self_len);
    const auto slash = dir.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
    {
        return 1;
    }
    dir.resize(slash);

    std::wstring target = dir + L"\\bin\\aegis64.exe";
    std::wstring work = dir + L"\\bin";
    if (!file_exists(target))
    {
        // A package staged before the platform launcher was renamed.
        target = dir + L"\\bin\\autopsy64.exe";
    }
    if (!file_exists(target))
    {
        MessageBoxW(nullptr, L"AEGIS could not find bin\\aegis64.exe. Reinstall AEGIS.", L"AEGIS", MB_ICONERROR);
        return 1;
    }

    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    bool has_jdk = false;
    bool has_userdir = false;
    bool has_cachedir = false;
    std::wstring command = quote(target);
    if (argv != nullptr)
    {
        for (int i = 1; i < argc; ++i)
        {
            const std::wstring arg(argv[i]);
            if (arg == L"--jdkhome")
            {
                has_jdk = true;
            }
            else if (arg == L"--userdir")
            {
                has_userdir = true;
            }
            else if (arg == L"--cachedir")
            {
                has_cachedir = true;
            }
            command += L" ";
            command += quote(argv[i]);
        }
        LocalFree(argv);
    }
    if (!has_jdk)
    {
        const std::wstring home = jdk_home(dir);
        if (home.empty())
        {
            MessageBoxW(nullptr, L"AEGIS could not find its Java runtime (the jre folder). Reinstall AEGIS.", L"AEGIS", MB_ICONERROR);
            return 1;
        }
        command += L" --jdkhome ";
        command += quote(home);
    }
    // The AEGIS profile, never a stock Autopsy profile on the same machine.
    if (!has_userdir)
    {
        const std::wstring roaming = env_dir(L"APPDATA");
        if (!roaming.empty())
        {
            command += L" --userdir ";
            command += quote(roaming + L"\\AEGIS");
        }
    }
    if (!has_cachedir)
    {
        const std::wstring local = env_dir(L"LOCALAPPDATA");
        if (!local.empty())
        {
            command += L" --cachedir ";
            command += quote(local + L"\\AEGIS\\Cache");
        }
    }

    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(target.c_str(), mutable_command.data(), nullptr, nullptr, FALSE, 0, nullptr, work.c_str(), &startup, &process))
    {
        return static_cast<int>(GetLastError());
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return static_cast<int>(code);
}
