#ifndef AEGIS_FILE_SHREDDER_HPP
#define AEGIS_FILE_SHREDDER_HPP

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace aegis::sanitizer {

enum class SanitizationMethod {
    NIST_800_88_CLEAR, // logical 1-pass 0x00. Not hardware sanitize.
    DOD_5220_22_M,     // 3 logical passes: 0x00, 0xFF, PRNG. Not a current DoD standard.
    PRNG_CUSTOM,       // N PRNG passes plus optional final 0x00
    ZERO_ONLY,         // logical 1-pass 0x00
    GUTMANN            // 35 shuffled logical writes. Not the published fixed sequence.
};

enum class PassResult {
    Ok,
    IoFailure,
    Cancelled
};

struct ProgressUpdate {
    std::string operation_id;
    std::string target;
    std::string phase;
    uint32_t current_pass = 0;
    uint32_t total_passes = 0;
    uint64_t bytes_total = 0;
    uint64_t bytes_completed = 0;
    double bytes_per_second = 0;
    double eta_seconds = -1;
    std::string status;
};

struct ShredConfig {
    SanitizationMethod method = SanitizationMethod::NIST_800_88_CLEAR;
    uint32_t passes = 1;
    bool zero_fill = true;
    size_t buffer_size = 64 * 1024;
    bool recursive = false;
    bool remove_file = true;
    std::string operation_id;
    std::string case_id;
    std::string operator_name;
    std::string application_version = "AEGIS";
    std::string sanitizer_version = "1.1.0";
    std::filesystem::path cancel_file;
    std::function<void(const ProgressUpdate&)> on_progress;
    std::function<bool()> should_cancel;
};

struct AuditRecord {
    std::string target_path;
    std::string target_type = "file";
    std::string filesystem_type = "UNKNOWN";
    std::string sanitization_standard;
    std::string method_id;
    uint64_t file_size_bytes = 0;
    uint64_t bytes_processed = 0;
    uint32_t passes_completed = 0;
    uint32_t passes_planned = 0;

    bool slack_space_eliminated = false;
    std::string slack_space_status = "NOT_ATTEMPTED";
    std::string slack_space_mode = "UNKNOWN";
    uint64_t allocation_unit_bytes = 0;
    uint64_t slack_bytes_overwritten = 0;

    bool trim_invoked = false;
    std::string trim_status = "NOT_ATTEMPTED";

    bool flush_succeeded = false;
    std::string flush_status = "NOT_ATTEMPTED";

    bool verification_passed = false;
    double calculated_entropy = 0.0;
    std::string verification_type = "NONE";
    std::string verification_scope;

    bool metadata_scrub_completed = false;

    std::vector<std::string> warnings;
    std::vector<std::string> errors;

    std::string status = "PENDING";
    std::string start_time;
    std::string end_time;
};

class FileShredder {
public:
    explicit FileShredder(ShredConfig config = ShredConfig());

    bool shred(const std::filesystem::path& target_path);
    bool shred_file(const std::filesystem::path& file_path);
    bool shred_directory(const std::filesystem::path& dir_path);
    bool export_audit_json(const std::filesystem::path& output_json_path);
    bool export_report_text(const std::filesystem::path& output_text_path);

    const std::vector<AuditRecord>& get_records() const { return records_; }
    const std::string& overall_status() const { return overall_status_; }
    const std::string& operation_id() const { return operation_id_; }
    const ShredConfig& config() const { return config_; }

    static std::string method_id(SanitizationMethod method);
    static std::string method_description(SanitizationMethod method);
    static uint32_t planned_passes(const ShredConfig& config);

private:
    ShredConfig config_;
    std::vector<AuditRecord> records_;
    std::string overall_status_ = "PENDING";
    std::string operation_id_;
    std::string operation_start_;
    std::string operation_end_;
    std::string root_target_;
    std::string root_target_type_ = "file";
    std::vector<std::string> operation_warnings_;
    std::vector<std::string> operation_errors_;

    PassResult execute_passes(const std::filesystem::path& path, uint64_t size, uint32_t& passes_executed, uint64_t& bytes_processed);
    bool verify_target_pattern(const std::filesystem::path& path, uint64_t size, uint8_t expected_byte);
    bool verify_entropy(const std::filesystem::path& path, uint64_t size, double& out_entropy);
    bool scrub_metadata(const std::filesystem::path& path);
    std::string get_standard_name() const;
    std::vector<uint8_t> get_final_pass_pattern() const;
    bool cancellation_requested() const;
    void emit_progress(const ProgressUpdate& update) const;
    void finish_overall();
};

} // namespace aegis::sanitizer

#endif
