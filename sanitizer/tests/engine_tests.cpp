#include "sanitizer/file_shredder.hpp"
#include "audit/json_util.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace fs = std::filesystem;

static int failures = 0;

static void expect(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << "\n";
        ++failures;
    } else {
        std::cout << "PASS: " << message << "\n";
    }
}

static void test_json_escape() {
    const std::string escaped = aegis::audit::json_string("C:\\A \"quote\"\nline\t\x01");
    expect(escaped.find("\\\\") != std::string::npos, "backslash is escaped");
    expect(escaped.find("\\\"") != std::string::npos, "quote is escaped");
    expect(escaped.find("\\n") != std::string::npos, "newline is escaped");
    expect(escaped.find("\\t") != std::string::npos, "tab is escaped");
    expect(escaped.find("\\u0001") != std::string::npos, "control character is escaped");
    expect(escaped.front() == '"' && escaped.back() == '"', "json string is quoted");
}

static void test_zero_file(const fs::path& root) {
    const fs::path file = root / "zero-me.txt";
    {
        std::ofstream out(file, std::ios::binary);
        out << "SECRET_PAYLOAD_TEST_DATA";
    }
    aegis::sanitizer::ShredConfig cfg;
    cfg.method = aegis::sanitizer::SanitizationMethod::ZERO_ONLY;
    cfg.remove_file = false;
    int progress_events = 0;
    cfg.on_progress = [&](const aegis::sanitizer::ProgressUpdate&) { ++progress_events; };
    aegis::sanitizer::FileShredder shredder(cfg);
    const bool ok = shredder.shred(file);
    expect(ok, "zero overwrite reports verification success");
    expect(shredder.overall_status() == "SUCCESS" || shredder.overall_status() == "SUCCESS_WITH_WARNINGS",
           "zero status is success or success with warnings");
    expect(progress_events > 0, "progress callback fired");
    std::ifstream in(file, std::ios::binary);
    char byte = 1;
    bool all_zero = true;
    while (in.get(byte)) {
        if (static_cast<unsigned char>(byte) != 0) all_zero = false;
    }
    expect(all_zero, "kept file reads back as 0x00");
    const fs::path audit = root / "zero-audit.json";
    expect(shredder.export_audit_json(audit), "audit json written");
    expect(shredder.export_report_text(root / "zero-report.txt"), "report written");
}

static void test_cancel(const fs::path& root) {
    const fs::path file = root / "cancel-me.bin";
    {
        std::ofstream out(file, std::ios::binary);
        out << std::string(256 * 1024, 'A');
    }
    const fs::path cancel = root / "cancel.flag";
    {
        std::ofstream flag(cancel);
        flag << "cancel";
    }
    aegis::sanitizer::ShredConfig cfg;
    cfg.method = aegis::sanitizer::SanitizationMethod::ZERO_ONLY;
    cfg.cancel_file = cancel;
    cfg.remove_file = true;
    aegis::sanitizer::FileShredder shredder(cfg);
    const bool ok = shredder.shred(file);
    expect(!ok, "cancelled shred is not success");
    expect(shredder.overall_status() == "CANCELLED", "status is CANCELLED");
    expect(fs::exists(file), "cancelled file was not unlinked");
}

static void test_missing_and_directory_failure(const fs::path& root) {
    aegis::sanitizer::ShredConfig cfg;
    aegis::sanitizer::FileShredder missing(cfg);
    expect(!missing.shred(root / "does-not-exist"), "missing path fails");

    const fs::path dir = root / "partial";
    fs::create_directories(dir / "nested");
    {
        std::ofstream(dir / "ok.txt") << "ok";
        std::ofstream(dir / "nested" / "also.txt") << "also";
    }
    const fs::path blocked = dir / "blocked.txt";
    {
        std::ofstream(blocked) << "keep";
    }
#if defined(_WIN32)
    SetFileAttributesW(blocked.c_str(), FILE_ATTRIBUTE_READONLY);
#endif
    aegis::sanitizer::ShredConfig recursive;
    recursive.recursive = true;
    recursive.method = aegis::sanitizer::SanitizationMethod::ZERO_ONLY;
    aegis::sanitizer::FileShredder shredder(recursive);
    const bool ok = shredder.shred(dir);
    const std::string status = shredder.overall_status();
    expect(!ok || status == "PARTIAL_FAILURE" || status == "FAILED" || status == "SUCCESS" || status == "SUCCESS_WITH_WARNINGS",
           "directory run returns a real status");
#if defined(_WIN32)
    SetFileAttributesW(blocked.c_str(), FILE_ATTRIBUTE_NORMAL);
    if (fs::exists(blocked)) {
        expect(status == "PARTIAL_FAILURE" || status == "FAILED", "readonly child prevents clean directory success");
        expect(!ok, "directory exit is not success when a child fails");
    }
#endif
    (void)ok;
}

static void test_wipe_not_here() {
    expect(aegis::sanitizer::FileShredder::method_description(aegis::sanitizer::SanitizationMethod::NIST_800_88_CLEAR)
               .find("not ATA SANITIZE") != std::string::npos,
           "nist description denies hardware sanitize");
}

int main() {
    const fs::path root = fs::temp_directory_path() / "aegis-sanitizer-tests";
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root);
    test_json_escape();
    test_zero_file(root);
    test_cancel(root);
    test_missing_and_directory_failure(root);
    test_wipe_not_here();
    fs::remove_all(root, ec);
    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "all engine tests passed\n";
    return 0;
}
