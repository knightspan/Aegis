#include "sanitizer/file_shredder.hpp"
#include "sanitizer/win_device_ops.hpp"
#include "audit/json_util.hpp"

#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <shellapi.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace {

void emit_event(const std::string& json_object) {
    std::cout << "AEGIS_EVENT " << json_object << "\n" << std::flush;
}

int exit_for_status(const std::string& status) {
    if (status == "SUCCESS" || status == "SUCCESS_WITH_WARNINGS") return 0;
    if (status == "PARTIAL_FAILURE") return 2;
    if (status == "CANCELLED") return 3;
    if (status == "UNSUPPORTED") return 4;
    if (status == "SKIPPED" || status == "SKIPPED_NOT_REGULAR_FILE") return 5;
    return 1;
}

std::string current_user() {
#if defined(_WIN32) || defined(_WIN64)
    char buffer[256];
    DWORD size = static_cast<DWORD>(sizeof(buffer));
    if (GetUserNameA(buffer, &size)) {
        return std::string(buffer);
    }
    return "";
#else
    const char* user = ::getenv("USER");
    return user ? user : "";
#endif
}

bool is_elevated_user() {
#if defined(_WIN32) || defined(_WIN64)
    BOOL elevated = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev;
        DWORD ret_len = 0;
        if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &ret_len)) {
            elevated = elev.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return elevated != 0;
#else
    return (::getuid() == 0);
#endif
}

bool is_device_path(const std::string& target) {
    return target.rfind("\\\\.\\", 0) == 0 || target.rfind("\\\\?\\", 0) == 0 ||
           target.rfind("/dev/", 0) == 0;
}

bool is_volume_root(const fs::path& path) {
    std::error_code ec;
    fs::path canonical = fs::weakly_canonical(path, ec);
    if (ec) {
        canonical = path;
    }
    if (!canonical.has_root_path()) {
        return false;
    }
    const fs::path relative = canonical.relative_path();
    return relative.empty() || relative == ".";
}

bool is_windows_directory(const fs::path& path) {
#if defined(_WIN32) || defined(_WIN64)
    wchar_t windows_dir[MAX_PATH];
    const UINT n = GetWindowsDirectoryW(windows_dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return false;
    }
    std::error_code ec;
    const fs::path windows = fs::weakly_canonical(fs::path(windows_dir), ec);
    const fs::path target = fs::weakly_canonical(path, ec);
    return !ec && target == windows;
#else
    (void)path;
    return false;
#endif
}

aegis::sanitizer::SanitizationMethod parse_method(const std::string& method) {
    if (method == "nist") return aegis::sanitizer::SanitizationMethod::NIST_800_88_CLEAR;
    if (method == "dod522022m") return aegis::sanitizer::SanitizationMethod::DOD_5220_22_M;
    if (method == "prng") return aegis::sanitizer::SanitizationMethod::PRNG_CUSTOM;
    if (method == "zero") return aegis::sanitizer::SanitizationMethod::ZERO_ONLY;
    if (method == "gutmann") return aegis::sanitizer::SanitizationMethod::GUTMANN;
    return aegis::sanitizer::SanitizationMethod::NIST_800_88_CLEAR;
}

void print_usage(const char* prog) {
    std::cerr << "Usage:\n";
    std::cerr << "  " << prog << " shred <path> [-r] [--method METHOD] [--passes N] [--no-zero]\n";
    std::cerr << "      [--audit file.json] [--report file.txt] [--case-id ID] [--operator NAME] [--cancel-file path]\n";
    std::cerr << "  " << prog << " wipe-disk <device> --force [--method METHOD] [--passes N]\n";
    std::cerr << "      [--audit file.json] [--report file.txt] [--case-id ID] [--operator NAME] [--cancel-file path]\n";
    std::cerr << "  " << prog << " acquire <source> <dest.img> [--size N] [--allow-non-removable-read]\n";
    std::cerr << "Methods: nist, zero, dod522022m, prng, gutmann\n";
    std::cerr << "wipe-disk: removable USB/SD volume (\\\\.\\E:) or PhysicalDriveN only. Requires --force.\n";
    std::cerr << "acquire: read-only RAW imaging; never writes the source.\n";
    std::cerr << "Stdout lines beginning with AEGIS_EVENT are JSON. Other text is on stderr.\n";
}

} // namespace

int handle_shred(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Missing target path.\n";
        return 1;
    }

    const std::string target_raw = argv[2];
    if (is_device_path(target_raw)) {
        emit_event("{\"type\":\"result\",\"status\":\"UNSUPPORTED\",\"message\":\"Device paths are not a file or directory sanitization target.\"}");
        return 4;
    }
    const fs::path target_path = aegis::audit::path_from_utf8(target_raw);
    if (!fs::exists(target_path)) {
        emit_event("{\"type\":\"result\",\"status\":\"FAILED\",\"message\":\"Target path was not found.\"}");
        return 1;
    }
    const bool directory = fs::is_directory(target_path);
    if (directory && (is_volume_root(target_path) || is_windows_directory(target_path))) {
        emit_event("{\"type\":\"result\",\"status\":\"UNSUPPORTED\",\"message\":\"Refusing to sanitize a volume root or the Windows directory.\"}");
        return 4;
    }

    aegis::sanitizer::ShredConfig cfg;
    cfg.method = aegis::sanitizer::SanitizationMethod::NIST_800_88_CLEAR;
    cfg.operator_name = current_user();
    std::string method_str = "nist";
    std::string audit_out = "aegis_audit.json";
    std::string report_out = "aegis_report.txt";
    bool method_known = true;

    for (int i = 3; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-r" || arg == "--recursive") {
            cfg.recursive = true;
        } else if (arg == "--method" && i + 1 < argc) {
            method_str = argv[++i];
            if (method_str != "nist" && method_str != "dod522022m" && method_str != "prng" &&
                method_str != "zero" && method_str != "gutmann") {
                method_known = false;
            }
            cfg.method = parse_method(method_str);
        } else if (arg == "--passes" && i + 1 < argc) {
            cfg.passes = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--no-zero") {
            cfg.zero_fill = false;
        } else if (arg == "--audit" && i + 1 < argc) {
            audit_out = argv[++i];
        } else if (arg == "--report" && i + 1 < argc) {
            report_out = argv[++i];
        } else if (arg == "--case-id" && i + 1 < argc) {
            cfg.case_id = argv[++i];
        } else if (arg == "--operator" && i + 1 < argc) {
            cfg.operator_name = argv[++i];
        } else if (arg == "--cancel-file" && i + 1 < argc) {
            cfg.cancel_file = aegis::audit::path_from_utf8(argv[++i]);
        }
    }

    if (!method_known) {
        emit_event("{\"type\":\"result\",\"status\":\"FAILED\",\"message\":\"Unknown sanitization method.\"}");
        return 1;
    }
    if (directory && !cfg.recursive) {
        emit_event("{\"type\":\"result\",\"status\":\"FAILED\",\"message\":\"Directory target requires --recursive.\"}");
        return 1;
    }

    cfg.on_progress = [](const aegis::sanitizer::ProgressUpdate& update) {
        std::ostringstream json;
        const double percent = (update.bytes_total == 0)
            ? 100.0
            : (100.0 * static_cast<double>(update.bytes_completed) / static_cast<double>(update.bytes_total));
        json << "{\"type\":\"progress\""
             << ",\"operation_id\":" << aegis::audit::json_string(update.operation_id)
             << ",\"target\":" << aegis::audit::json_string(update.target)
             << ",\"phase\":" << aegis::audit::json_string(update.phase)
             << ",\"current_pass\":" << update.current_pass
             << ",\"total_passes\":" << update.total_passes
             << ",\"bytes_total\":" << update.bytes_total
             << ",\"bytes_completed\":" << update.bytes_completed
             << ",\"percentage\":" << percent
             << ",\"bytes_per_second\":" << update.bytes_per_second
             << ",\"eta_seconds\":" << update.eta_seconds
             << ",\"status\":" << aegis::audit::json_string(update.status)
             << "}";
        emit_event(json.str());
    };

    std::cerr << "AEGIS sanitizer\n";
    std::cerr << "Target: " << target_raw << "\n";
    std::cerr << "Method: " << method_str << "\n";
    std::cerr << aegis::sanitizer::FileShredder::method_description(cfg.method) << "\n";

    aegis::sanitizer::FileShredder shredder(cfg);
    const bool ok = shredder.shred(target_path);
    const bool audit_ok = shredder.export_audit_json(aegis::audit::path_from_utf8(audit_out));
    const bool report_ok = shredder.export_report_text(aegis::audit::path_from_utf8(report_out));
    const std::string status = shredder.overall_status();
    const int code = exit_for_status(status);

    std::ostringstream result;
    result << "{\"type\":\"result\""
           << ",\"operation_id\":" << aegis::audit::json_string(shredder.operation_id())
           << ",\"status\":" << aegis::audit::json_string(status)
           << ",\"exit_code\":" << code
           << ",\"audit_written\":" << aegis::audit::json_bool(audit_ok)
           << ",\"report_written\":" << aegis::audit::json_bool(report_ok)
           << ",\"audit_path\":" << aegis::audit::json_string(audit_out)
           << ",\"report_path\":" << aegis::audit::json_string(report_out)
           << ",\"verified\":" << aegis::audit::json_bool(ok && (status == "SUCCESS" || status == "SUCCESS_WITH_WARNINGS"))
           << "}";
    emit_event(result.str());
    if (!ok && code == 0) {
        std::cerr << "Internal status mismatch. Refusing to return success.\n";
        return 1;
    }
    return code;
}

int handle_wipe_disk(int argc, char* argv[]) {
    if (argc < 3) {
        emit_event("{\"type\":\"result\",\"status\":\"FAILED\",\"message\":\"Missing device path.\"}");
        return 1;
    }
    const std::string device = argv[2];
    bool force = false;
    std::string method_str = "zero";
    uint32_t passes = 1;
    std::string audit_out = "aegis_audit.json";
    std::string report_out = "aegis_report.txt";
    std::string case_id;
    std::string operator_name = current_user();
    std::string cancel_file;

    for (int i = 3; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--force") {
            force = true;
        } else if (arg == "--method" && i + 1 < argc) {
            method_str = argv[++i];
        } else if (arg == "--passes" && i + 1 < argc) {
            passes = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--audit" && i + 1 < argc) {
            audit_out = argv[++i];
        } else if (arg == "--report" && i + 1 < argc) {
            report_out = argv[++i];
        } else if (arg == "--case-id" && i + 1 < argc) {
            case_id = argv[++i];
        } else if (arg == "--operator" && i + 1 < argc) {
            operator_name = argv[++i];
        } else if (arg == "--cancel-file" && i + 1 < argc) {
            cancel_file = argv[++i];
        }
    }

    if (!force) {
        emit_event("{\"type\":\"result\",\"status\":\"FAILED\",\"message\":\"wipe-disk requires --force after eligibility confirmation.\"}");
        return 1;
    }
    if (method_str != "zero" && method_str != "nist") {
        emit_event("{\"type\":\"result\",\"status\":\"UNSUPPORTED\",\"message\":\"wipe-disk currently supports zero/nist logical overwrite only.\"}");
        return 4;
    }
    if (!is_elevated_user()) {
        emit_event("{\"type\":\"result\",\"status\":\"FAILED\",\"message\":\"Administrator elevation is required for wipe-disk.\"}");
        return 1;
    }

#if defined(_WIN32) || defined(_WIN64)
    auto wipe = aegis::sanitizer::winops::wipe_removable_device(
            device, passes,
            [](const aegis::sanitizer::winops::Progress& update) {
                std::ostringstream json;
                const double percent = (update.bytes_total == 0)
                    ? 100.0
                    : (100.0 * static_cast<double>(update.bytes_completed) / static_cast<double>(update.bytes_total));
                json << "{\"type\":\"progress\""
                     << ",\"phase\":" << aegis::audit::json_string(update.phase)
                     << ",\"current_pass\":" << update.current_pass
                     << ",\"total_passes\":" << update.total_passes
                     << ",\"bytes_completed\":" << update.bytes_completed
                     << ",\"bytes_total\":" << update.bytes_total
                     << ",\"percentage\":" << percent
                     << "}";
                emit_event(json.str());
            },
            cancel_file);

    {
        std::ofstream audit(audit_out, std::ios::binary);
        if (audit) {
            audit << "{\"operation\":\"wipe-disk\",\"device\":" << aegis::audit::json_string(device)
                  << ",\"status\":" << aegis::audit::json_string(wipe.status)
                  << ",\"bytes\":" << wipe.bytes
                  << ",\"case_id\":" << aegis::audit::json_string(case_id)
                  << ",\"operator\":" << aegis::audit::json_string(operator_name)
                  << ",\"sample_verified\":" << aegis::audit::json_bool(wipe.sample_verified)
                  << "}\n";
        }
        std::ofstream report(report_out);
        if (report) {
            report << "AEGIS wipe-disk\n"
                   << "Device: " << device << "\n"
                   << "Status: " << wipe.status << "\n"
                   << "Message: " << wipe.message << "\n"
                   << "Bytes: " << wipe.bytes << "\n"
                   << "Sample verified: " << (wipe.sample_verified ? "yes" : "no") << "\n"
                   << "NAND/firmware remapping: NOT VERIFIED\n";
        }
    }

    std::ostringstream result;
    result << "{\"type\":\"result\""
           << ",\"status\":" << aegis::audit::json_string(wipe.status)
           << ",\"operation_id\":" << aegis::audit::json_string("wipe-" + std::to_string(GetTickCount64()))
           << ",\"message\":" << aegis::audit::json_string(wipe.message)
           << ",\"audit_written\":true"
           << ",\"report_written\":true"
           << ",\"bytes\":" << wipe.bytes
           << ",\"verified\":" << aegis::audit::json_bool(wipe.sample_verified)
           << "}";
    emit_event(result.str());
    return exit_for_status(wipe.status);
#else
    emit_event("{\"type\":\"result\",\"status\":\"UNSUPPORTED\",\"message\":\"Physical disk sanitization is not enabled.\"}");
    return 4;
#endif
}

int handle_acquire(int argc, char* argv[]) {
    if (argc < 4) {
        emit_event("{\"type\":\"result\",\"status\":\"FAILED\",\"message\":\"Usage: acquire <source> <dest>\"}");
        return 1;
    }
    const std::string source = argv[2];
    const std::string dest = argv[3];
    int64_t size = -1;
    bool allow_non_removable = false;
    for (int i = 4; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--size" && i + 1 < argc) {
            size = static_cast<int64_t>(std::stoll(argv[++i]));
        } else if (arg == "--allow-non-removable-read") {
            allow_non_removable = true;
        }
    }

#if defined(_WIN32) || defined(_WIN64)
    auto acq = aegis::sanitizer::winops::acquire_raw(
            source, dest, size, allow_non_removable,
            [](const aegis::sanitizer::winops::Progress& update) {
                std::ostringstream json;
                const double percent = (update.bytes_total == 0)
                    ? 100.0
                    : (100.0 * static_cast<double>(update.bytes_completed) / static_cast<double>(update.bytes_total));
                json << "{\"type\":\"progress\""
                     << ",\"phase\":" << aegis::audit::json_string(update.phase)
                     << ",\"bytes\":" << update.bytes_completed
                     << ",\"total\":" << update.bytes_total
                     << ",\"bytes_completed\":" << update.bytes_completed
                     << ",\"bytes_total\":" << update.bytes_total
                     << ",\"percentage\":" << percent
                     << "}";
                emit_event(json.str());
            });

    std::ostringstream result;
    result << "{\"type\":\"result\""
           << ",\"status\":" << aegis::audit::json_string(acq.status)
           << ",\"message\":" << aegis::audit::json_string(acq.message)
           << ",\"bytes\":" << acq.bytes
           << ",\"sha256\":" << aegis::audit::json_string(acq.sha256)
           << "}";
    emit_event(result.str());
    return exit_for_status(acq.status);
#else
    emit_event("{\"type\":\"result\",\"status\":\"UNSUPPORTED\",\"message\":\"acquire is Windows-only in this build.\"}");
    return 4;
#endif
}

int main_utf8(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    const std::string command = argv[1];
    try {
        if (command == "shred") return handle_shred(argc, argv);
        if (command == "wipe-disk") return handle_wipe_disk(argc, argv);
        if (command == "acquire") return handle_acquire(argc, argv);
    } catch (const std::exception& ex) {
        std::cerr << "Sanitizer exception: " << ex.what() << "\n";
        emit_event("{\"type\":\"result\",\"status\":\"FAILED\",\"message\":\"The sanitizer threw an exception.\"}");
        return 1;
    }
    std::cerr << "Unknown command: " << command << "\n";
    print_usage(argv[0]);
    return 1;
}

#if defined(_WIN32) || defined(_WIN64)
static std::string wide_to_utf8(const wchar_t* value) {
    if (value == nullptr || value[0] == L'\0') {
        return {};
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) {
        return {};
    }
    std::string out(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, out.data(), needed, nullptr, nullptr);
    return out;
}
#endif

int main(int argc, char* argv[]) {
#if defined(_WIN32) || defined(_WIN64)
    (void)argc;
    (void)argv;
    int wide_argc = 0;
    wchar_t** wide_argv = CommandLineToArgvW(GetCommandLineW(), &wide_argc);
    if (wide_argv == nullptr) {
        return 1;
    }
    std::vector<std::string> storage;
    storage.reserve(static_cast<size_t>(wide_argc));
    std::vector<char*> utf8_argv;
    utf8_argv.reserve(static_cast<size_t>(wide_argc));
    for (int i = 0; i < wide_argc; ++i) {
        storage.push_back(wide_to_utf8(wide_argv[i]));
        utf8_argv.push_back(storage.back().data());
    }
    LocalFree(wide_argv);
    return main_utf8(wide_argc, utf8_argv.data());
#else
    return main_utf8(argc, argv);
#endif
}
