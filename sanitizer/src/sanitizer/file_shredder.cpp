#include "sanitizer/file_shredder.hpp"
#include "sanitizer/platform_fs.hpp"
#include "audit/json_util.hpp"

#include <iostream>
#include <fstream>
#include <random>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <cmath>
#include <array>
#include <filesystem>

namespace aegis::sanitizer
{

    static std::string get_iso_timestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%dT%H:%M:%SZ");
        return ss.str();
    }

    FileShredder::FileShredder(ShredConfig config) : config_(std::move(config))
    {
        if (config_.operation_id.empty())
        {
            std::random_device rd;
            std::ostringstream id;
            id << std::hex << rd() << rd();
            operation_id_ = id.str();
            config_.operation_id = operation_id_;
        }
        else
        {
            operation_id_ = config_.operation_id;
        }
        operation_start_ = get_iso_timestamp();
    }

    std::string FileShredder::method_id(SanitizationMethod method)
    {
        switch (method)
        {
        case SanitizationMethod::NIST_800_88_CLEAR:
            return "logical-zero-nist-label";
        case SanitizationMethod::DOD_5220_22_M:
            return "logical-3pass-00-ff-prng";
        case SanitizationMethod::PRNG_CUSTOM:
            return "logical-prng";
        case SanitizationMethod::ZERO_ONLY:
            return "logical-zero";
        case SanitizationMethod::GUTMANN:
            return "logical-35pass-shuffled";
        }
        return "unknown";
    }

    std::string FileShredder::method_description(SanitizationMethod method)
    {
        switch (method)
        {
        case SanitizationMethod::NIST_800_88_CLEAR:
            return "One logical pass of 0x00. This is not ATA SANITIZE, NVMe Sanitize, TCG Opal erase, or cryptographic erase.";
        case SanitizationMethod::ZERO_ONLY:
            return "One logical pass of 0x00. This does not guarantee destruction of SSD or flash remapped data.";
        case SanitizationMethod::DOD_5220_22_M:
            return "Three logical passes: 0x00, then 0xFF, then pseudorandom. This is the commonly circulated 3-pass pattern. It is not a current DoD sanitization standard.";
        case SanitizationMethod::PRNG_CUSTOM:
            return "The configured number of pseudorandom logical passes, then an optional final 0x00 pass. Entropy verification is not a cryptographic proof.";
        case SanitizationMethod::GUTMANN:
            return "Thirty-five logical writes: four pseudorandom, twenty-seven patterns in shuffled order, then four pseudorandom. This is not Peter Gutmann's published fixed sequence.";
        }
        return "Unknown method.";
    }

    uint32_t FileShredder::planned_passes(const ShredConfig& config)
    {
        switch (config.method)
        {
        case SanitizationMethod::NIST_800_88_CLEAR:
        case SanitizationMethod::ZERO_ONLY:
            return 1;
        case SanitizationMethod::DOD_5220_22_M:
            return 3;
        case SanitizationMethod::PRNG_CUSTOM:
            return config.passes + (config.zero_fill ? 1u : 0u);
        case SanitizationMethod::GUTMANN:
            return 35;
        }
        return 0;
    }

    bool FileShredder::cancellation_requested() const
    {
        if (config_.should_cancel && config_.should_cancel())
        {
            return true;
        }
        if (!config_.cancel_file.empty())
        {
            std::error_code ec;
            if (std::filesystem::exists(config_.cancel_file, ec) && !ec)
            {
                return true;
            }
        }
        return false;
    }

    void FileShredder::emit_progress(const ProgressUpdate& update) const
    {
        if (config_.on_progress)
        {
            config_.on_progress(update);
        }
    }

    std::string FileShredder::get_standard_name() const
    {
        switch (config_.method)
        {
        case SanitizationMethod::NIST_800_88_CLEAR:
            return "Logical 0x00 overwrite (engine label nist). Not hardware sanitize.";
        case SanitizationMethod::DOD_5220_22_M:
            return "Logical 3-pass pattern 0x00, 0xFF, pseudorandom. Not a current DoD standard.";
        case SanitizationMethod::PRNG_CUSTOM:
            return "Logical pseudorandom passes. Entropy is not a cryptographic proof.";
        case SanitizationMethod::ZERO_ONLY:
            return "Logical single-pass 0x00 overwrite.";
        case SanitizationMethod::GUTMANN:
            return "35 shuffled logical writes. Not the published fixed Gutmann sequence.";
        }
        return "Unknown Standard";
    }

    // The pattern the slack-space overwrite should use, so the tail of the last
    // block/cluster matches whatever the final content pass wrote.
    std::vector<uint8_t> FileShredder::get_final_pass_pattern() const
    {
        auto random_block = []() -> std::vector<uint8_t>
        {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<uint16_t> dist(0, 255);
            std::vector<uint8_t> rnd_pattern(512);
            for (auto &b : rnd_pattern)
            {
                b = static_cast<uint8_t>(dist(gen));
            }
            return rnd_pattern;
        };

        switch (config_.method)
        {
        case SanitizationMethod::NIST_800_88_CLEAR:
        case SanitizationMethod::ZERO_ONLY:
            return {0x00};

        case SanitizationMethod::DOD_5220_22_M:
            // DoD final pass (Pass 3) is PRNG random noise
            return random_block();

        case SanitizationMethod::PRNG_CUSTOM:
            if (config_.zero_fill)
            {
                return {0x00};
            }
            return random_block();

        case SanitizationMethod::GUTMANN:
            // Gutmann final passes (32-35) are pseudo-random noise
            return random_block();
        }
        return {0x00};
    }

    bool FileShredder::verify_target_pattern(const std::filesystem::path &path, uint64_t size, uint8_t expected_byte)
    {
        if (size == 0)
            return true;

        std::ifstream in(path, std::ios::binary);
        if (!in.is_open())
            return false;

        std::vector<char> buffer(config_.buffer_size, 0);
        uint64_t bytes_checked = 0;

        while (bytes_checked < size)
        {
            size_t to_read = std::min(static_cast<uint64_t>(buffer.size()), size - bytes_checked);
            in.read(buffer.data(), to_read);
            std::streamsize bytes_read = in.gcount();
            if (bytes_read <= 0)
                break;

            for (std::streamsize i = 0; i < bytes_read; ++i)
            {
                if (static_cast<uint8_t>(buffer[i]) != expected_byte)
                {
                    return false;
                }
            }
            bytes_checked += bytes_read;
        }

        return bytes_checked == size;
    }

    bool FileShredder::verify_entropy(const std::filesystem::path &path, uint64_t size, double &out_entropy)
    {
        out_entropy = 0.0;
        if (size == 0)
        {
            out_entropy = 0.0;
            return true;
        }

        std::ifstream in(path, std::ios::binary);
        if (!in.is_open())
            return false;

        std::array<uint64_t, 256> frequencies{};
        frequencies.fill(0);

        std::vector<char> buffer(config_.buffer_size, 0);
        uint64_t total_read = 0;

        while (total_read < size)
        {
            size_t to_read = std::min(static_cast<uint64_t>(buffer.size()), size - total_read);
            in.read(buffer.data(), to_read);
            std::streamsize bytes_read = in.gcount();
            if (bytes_read <= 0)
                break;

            for (std::streamsize i = 0; i < bytes_read; ++i)
            {
                frequencies[static_cast<uint8_t>(buffer[i])]++;
            }
            total_read += bytes_read;
        }

        if (total_read == 0)
            return false;

        double entropy = 0.0;
        for (int i = 0; i < 256; ++i)
        {
            if (frequencies[i] > 0)
            {
                double p = static_cast<double>(frequencies[i]) / static_cast<double>(total_read);
                entropy -= p * std::log2(p);
            }
        }

        out_entropy = entropy;
        double threshold = (size < 1024) ? 7.0 : 7.80;
        return (out_entropy >= threshold);
    }

    PassResult FileShredder::execute_passes(const std::filesystem::path &path, uint64_t size, uint32_t &passes_executed, uint64_t &bytes_processed)
    {
        passes_executed = 0;
        bytes_processed = 0;
        if (size == 0)
            return PassResult::Ok;
        if (cancellation_requested())
            return PassResult::Cancelled;

        std::fstream stream(path, std::ios::in | std::ios::out | std::ios::binary);
        if (!stream.is_open())
        {
            std::cerr << "[-] Failed to open file for overwrite: " << path << "\n";
            return PassResult::IoFailure;
        }

        std::vector<char> buffer(config_.buffer_size);
        std::random_device rd;
        std::mt19937_64 prng(rd());
        std::uniform_int_distribution<uint64_t> dist;
        const uint32_t total_passes = planned_passes(config_);
        const auto started = std::chrono::steady_clock::now();
        const std::string target_utf8 = audit::path_to_utf8(path);

        auto publish = [&](uint64_t written_this_pass)
        {
            const uint64_t completed = (static_cast<uint64_t>(passes_executed) * size) + written_this_pass;
            bytes_processed = completed;
            const uint64_t total_bytes = static_cast<uint64_t>(total_passes) * size;
            const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
            ProgressUpdate update;
            update.operation_id = operation_id_;
            update.target = target_utf8;
            update.phase = "overwrite";
            update.current_pass = passes_executed + (written_this_pass > 0 && written_this_pass < size ? 1 : 0);
            if (written_this_pass == 0)
            {
                update.current_pass = passes_executed;
            }
            update.total_passes = total_passes;
            update.bytes_total = total_bytes;
            update.bytes_completed = completed;
            update.bytes_per_second = (elapsed > 0.0) ? (static_cast<double>(completed) / elapsed) : 0;
            if (update.bytes_per_second > 0 && completed < total_bytes)
            {
                update.eta_seconds = static_cast<double>(total_bytes - completed) / update.bytes_per_second;
            }
            update.status = "RUNNING";
            emit_progress(update);
        };

        auto write_pass_internal = [&](const auto &fill_chunk) -> PassResult
        {
            if (cancellation_requested())
                return PassResult::Cancelled;
            stream.clear();
            stream.seekp(0, std::ios::beg);
            if (stream.fail())
                return PassResult::IoFailure;

            uint64_t written = 0;
            while (written < size)
            {
                if (cancellation_requested())
                    return PassResult::Cancelled;
                size_t chunk = std::min(static_cast<uint64_t>(buffer.size()), size - written);
                fill_chunk(buffer.data(), chunk);

                stream.write(buffer.data(), chunk);
                if (stream.bad() || stream.fail())
                {
                    std::cerr << "[-] I/O write failure on target: " << path << "\n";
                    return PassResult::IoFailure;
                }
                written += chunk;
                publish(written);
            }
            stream.flush();
            if (stream.bad() || stream.fail())
                return PassResult::IoFailure;

            passes_executed++;
            publish(0);
            return PassResult::Ok;
        };

        auto write_constant_pass = [&](uint8_t byte_val) -> PassResult
        {
            return write_pass_internal([&](char *buf, size_t chunk)
                                       { std::fill_n(buf, chunk, static_cast<char>(byte_val)); });
        };

        auto write_random_pass = [&]() -> PassResult
        {
            return write_pass_internal([&](char *buf, size_t chunk)
                                       {
            for (size_t i = 0; i < chunk; i += sizeof(uint64_t)) {
                uint64_t r = dist(prng);
                size_t copy_bytes = std::min(sizeof(uint64_t), chunk - i);
                std::memcpy(buf + i, &r, copy_bytes);
            } });
        };

        auto write_pattern_pass = [&](const std::vector<uint8_t> &pat) -> PassResult
        {
            return write_pass_internal([&](char *buf, size_t chunk)
                                       {
            for (size_t i = 0; i < chunk; ++i) {
                buf[i] = static_cast<char>(pat[i % pat.size()]);
            } });
        };

        PassResult result = PassResult::Ok;
        switch (config_.method)
        {
        case SanitizationMethod::NIST_800_88_CLEAR:
        case SanitizationMethod::ZERO_ONLY:
            result = write_constant_pass(0x00);
            break;

        case SanitizationMethod::DOD_5220_22_M:
            result = write_constant_pass(0x00);
            if (result == PassResult::Ok)
                result = write_constant_pass(0xFF);
            if (result == PassResult::Ok)
                result = write_random_pass();
            break;

        case SanitizationMethod::PRNG_CUSTOM:
            for (uint32_t i = 0; i < config_.passes && result == PassResult::Ok; ++i)
            {
                result = write_random_pass();
            }
            if (result == PassResult::Ok && config_.zero_fill)
            {
                result = write_constant_pass(0x00);
            }
            break;

        case SanitizationMethod::GUTMANN:
        {
            for (int i = 0; i < 4 && result == PassResult::Ok; ++i)
            {
                result = write_random_pass();
            }

            std::vector<std::vector<uint8_t>> patterns = {
                {0x55}, {0xAA}, {0x92, 0x49, 0x24}, {0x49, 0x24, 0x92}, {0x24, 0x92, 0x49}, {0x00}, {0x11}, {0x22}, {0x33}, {0x44}, {0x55}, {0x66}, {0x77}, {0x88}, {0x99}, {0xAA}, {0xBB}, {0xCC}, {0xDD}, {0xEE}, {0xFF}, {0x92, 0x49, 0x24}, {0x49, 0x24, 0x92}, {0x24, 0x92, 0x49}, {0x6D, 0xB6, 0xDB}, {0xB6, 0xDB, 0x6D}, {0xDB, 0x6D, 0xB6}};
            std::shuffle(patterns.begin(), patterns.end(), prng);

            for (const auto &pat : patterns)
            {
                if (result != PassResult::Ok)
                    break;
                result = write_pattern_pass(pat);
            }

            for (int i = 0; i < 4 && result == PassResult::Ok; ++i)
            {
                result = write_random_pass();
            }
            break;
        }
        }

        stream.close();
        return result;
    }

    // ---------------------------------------------------------------------------
    // Directory-entry slack cleansing.
    //
    // Renames through an equal-length mask first so the full original name slot in
    // the directory record is overwritten, then shrinks the name to force record
    // consolidation, then unlinks. Rename failures are surfaced, not swallowed.
    //
    // Effectiveness is filesystem-dependent: this is modelled on ext4's
    // ext4_dir_entry_2 layout. NTFS index records ($INDEX_ROOT/$INDEX_ALLOCATION
    // B-trees), exFAT directory entry sets and FAT32 LFN chains lay names out
    // differently, and NTFS additionally records renames in the USN journal. The
    // final unlink always runs regardless.
    // ---------------------------------------------------------------------------
    bool FileShredder::scrub_metadata(const std::filesystem::path &path)
    {
        namespace fs = std::filesystem;
        std::error_code ec;

        fs::path parent = path.parent_path();
        std::string original_name = path.filename().string();
        size_t len = original_name.length();

        fs::path current_path = path;

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dist(100000, 999999);
        std::string nonce = std::to_string(dist(gen));

        bool all_renames_succeeded = true;

        auto try_rename = [&](const fs::path &target)
        {
            fs::rename(current_path, target, ec);
            if (ec)
            {
                std::cerr << "[-] Metadata scrub: rename failed (" << current_path
                          << " -> " << target << "): " << ec.message() << "\n";
                all_renames_succeeded = false;
                return;
            }
            current_path = target;
        };

        // 1. Full-length zero mask
        try_rename(parent / (std::string(len, '0') + "_" + nonce));

        // 2. Full-length complement mask
        try_rename(parent / (std::string(len, 'A') + "_" + nonce));

        // 3. Shrink the name to force directory record consolidation
        try_rename(parent / ("0_" + nonce));

        // 4. Physical unlink - always attempted, even if masking was incomplete
        fs::remove(current_path, ec);
        if (ec)
        {
            std::cerr << "[-] Metadata scrub: final unlink failed for " << current_path
                      << ": " << ec.message() << "\n";
            return false;
        }

        return all_renames_succeeded;
    }

    bool FileShredder::shred_file(const std::filesystem::path &file_path)
    {
        namespace fs = std::filesystem;
        AuditRecord record;
        record.target_path = audit::path_to_utf8(file_path);
        record.target_type = "file";
        record.method_id = method_id(config_.method);
        record.sanitization_standard = get_standard_name();
        record.passes_planned = planned_passes(config_);
        record.verification_scope = "logical file bytes only; not slack, not unallocated space, not NAND";
        record.start_time = get_iso_timestamp();

        std::error_code ec;
        if (!fs::is_regular_file(file_path, ec))
        {
            record.status = "SKIPPED_NOT_REGULAR_FILE";
            record.end_time = get_iso_timestamp();
            records_.push_back(record);
            return false;
        }

        uint64_t file_size = fs::file_size(file_path, ec);
        record.file_size_bytes = file_size;
        record.filesystem_type = platform::detect_filesystem_name(file_path);

        // 1. OVERWRITE PASSES
        uint32_t passes_executed = 0;
        uint64_t bytes_processed = 0;
        const PassResult pass_result = execute_passes(file_path, file_size, passes_executed, bytes_processed);
        record.passes_completed = passes_executed;
        record.bytes_processed = bytes_processed;
        if (pass_result == PassResult::Cancelled)
        {
            record.status = "CANCELLED";
            record.errors.push_back("Cancelled before overwrite and verification completed. The file was not reported as sanitized.");
            record.end_time = get_iso_timestamp();
            records_.push_back(record);
            overall_status_ = "CANCELLED";
            return false;
        }
        if (pass_result != PassResult::Ok)
        {
            record.status = "FAILED";
            record.errors.push_back("FAILED_OVERWRITE: the logical overwrite did not complete.");
            record.end_time = get_iso_timestamp();
            records_.push_back(record);
            overall_status_ = "FAILED";
            return false;
        }

        // 2. FLUSH TO MEDIA
        // Must happen before verification, otherwise the read-back can be served
        // from the OS page cache and "verify" a write that never reached the disk.
        record.flush_succeeded = platform::flush_file_to_media(file_path);
        record.flush_status = record.flush_succeeded ? "SUCCESS" : "FAILED";
        if (!record.flush_succeeded)
        {
            record.warnings.push_back("Media flush failed. A later read-back may have been served from the OS cache.");
        }

        // 3. FILE SLACK SPACE ELIMINATION (extent mode on ext4/XFS, cluster mode
        //    on FAT/exFAT/NTFS). Runs before TRIM so discard cannot disturb it.
        {
            const platform::SlackResult slack =
                platform::eliminate_slack_space(file_path, file_size, get_final_pass_pattern());

            record.slack_space_eliminated = slack.eliminated;
            record.slack_space_status = slack.status;
            record.slack_space_mode = slack.mode;
            record.allocation_unit_bytes = slack.unit_size;
            record.slack_bytes_overwritten = slack.bytes_overwritten;
            if (record.filesystem_type == "UNKNOWN" && slack.fs_name != "UNKNOWN")
            {
                record.filesystem_type = slack.fs_name;
            }
        }

        // 4. VERIFICATION PASS (MUST PRECEDE TRIM TO PREVENT FALSE DISCARD READS)
        {
            ProgressUpdate verification;
            verification.operation_id = operation_id_;
            verification.target = record.target_path;
            verification.phase = "verification";
            verification.current_pass = record.passes_completed;
            verification.total_passes = record.passes_planned;
            verification.bytes_total = file_size;
            verification.bytes_completed = 0;
            verification.status = "RUNNING";
            emit_progress(verification);
        }
        bool is_final_pass_zero = (config_.method == SanitizationMethod::NIST_800_88_CLEAR ||
                                   config_.method == SanitizationMethod::ZERO_ONLY ||
                                   (config_.method == SanitizationMethod::PRNG_CUSTOM && config_.zero_fill));

        if (is_final_pass_zero)
        {
            record.verification_type = "BYTE_ZERO_CHECK";
            record.verification_passed = verify_target_pattern(file_path, file_size, 0x00);
            record.calculated_entropy = 0.0;
            if (!record.verification_passed)
            {
                record.errors.push_back("FAILED_VERIFICATION: expected every logical byte to be 0x00.");
            }
        }
        else
        {
            record.verification_type = "SHANNON_ENTROPY_CHECK";
            record.verification_passed = verify_entropy(file_path, file_size, record.calculated_entropy);
            record.warnings.push_back("Entropy verification is a statistical check. It is not a cryptographic proof and does not prove which tool wrote the bytes.");
            if (!record.verification_passed)
            {
                record.errors.push_back("FAILED_VERIFICATION: measured Shannon entropy was below the threshold for this file size.");
            }
        }
        {
            ProgressUpdate verification;
            verification.operation_id = operation_id_;
            verification.target = record.target_path;
            verification.phase = "verification";
            verification.current_pass = record.passes_completed;
            verification.total_passes = record.passes_planned;
            verification.bytes_total = file_size;
            verification.bytes_completed = record.verification_passed ? file_size : 0;
            verification.status = record.verification_passed ? "VERIFIED" : "FAILED_VERIFICATION";
            emit_progress(verification);
        }

        // 5. DISCARD / TRIM
        {
            const platform::DiscardResult discard =
                platform::discard_file_blocks(file_path, file_size);
            record.trim_invoked = discard.invoked;
            record.trim_status = discard.status;
        }

        // 6. EQUAL-LENGTH METADATA SCRUB & REMOVAL
        if (record.verification_passed && config_.remove_file)
        {
            record.metadata_scrub_completed = scrub_metadata(file_path);
            if (!record.metadata_scrub_completed)
            {
                record.warnings.push_back("Directory-entry rename scrub did not fully succeed. The final unlink result is in the log.");
            }
        }
        else if (!config_.remove_file)
        {
            record.metadata_scrub_completed = false;
            record.warnings.push_back("Unlink was not requested. The overwritten file remains at the target path.");
        }

        const bool slack_ok = record.slack_space_eliminated ||
                              record.slack_space_status.rfind("SKIPPED", 0) == 0;
        if (!slack_ok)
        {
            record.warnings.push_back("Slack overwrite did not complete: " + record.slack_space_status);
        }
        if (record.trim_status.rfind("FAILED", 0) == 0)
        {
            record.warnings.push_back("Discard/TRIM was not accepted: " + record.trim_status + ". This is not evidence that NAND was erased.");
        }

        if (!record.verification_passed)
        {
            record.status = "FAILED_VERIFICATION";
        }
        else if (!record.flush_succeeded || !record.metadata_scrub_completed || !slack_ok)
        {
            record.status = "SUCCESS_WITH_WARNINGS";
        }
        else
        {
            record.status = "SUCCESS";
        }

        record.end_time = get_iso_timestamp();
        records_.push_back(record);

        overall_status_ = record.status;
        return record.verification_passed;
    }

    bool FileShredder::shred_directory(const std::filesystem::path &dir_path)
    {
        namespace fs = std::filesystem;
        std::error_code ec;
        root_target_type_ = "directory";

        if (!fs::is_directory(dir_path, ec))
        {
            overall_status_ = "FAILED";
            operation_errors_.push_back("Target is not a directory.");
            return false;
        }

        std::vector<fs::path> files_to_shred;
        std::vector<fs::path> dirs_to_remove;

        for (auto it = fs::recursive_directory_iterator(dir_path, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); ++it)
        {
            if (cancellation_requested())
            {
                overall_status_ = "CANCELLED";
                operation_errors_.push_back("Cancelled while enumerating the directory.");
                return false;
            }
            if (it->is_regular_file())
            {
                files_to_shred.push_back(it->path());
            }
            else if (it->is_directory())
            {
                dirs_to_remove.push_back(it->path());
            }
            else
            {
                AuditRecord skipped;
                skipped.target_path = audit::path_to_utf8(it->path());
                skipped.target_type = "non-regular";
                skipped.status = "SKIPPED_NOT_REGULAR_FILE";
                skipped.errors.push_back("Skipped a non-regular filesystem entry. It was not overwritten.");
                skipped.end_time = get_iso_timestamp();
                records_.push_back(skipped);
                operation_warnings_.push_back("Skipped non-regular path: " + skipped.target_path);
            }
        }
        if (ec)
        {
            operation_warnings_.push_back("Directory enumeration stopped early: " + ec.message());
        }

        bool any_fail = false;
        bool any_ok = false;
        bool any_warn = false;
        bool cancelled = false;

        for (const auto &file : files_to_shred)
        {
            if (cancellation_requested())
            {
                cancelled = true;
                break;
            }
            const size_t before = records_.size();
            shred_file(file);
            if (records_.size() == before)
            {
                any_fail = true;
                continue;
            }
            const std::string &status = records_.back().status;
            if (status == "CANCELLED")
            {
                cancelled = true;
                break;
            }
            if (status == "SUCCESS")
            {
                any_ok = true;
            }
            else if (status == "SUCCESS_WITH_WARNINGS")
            {
                any_ok = true;
                any_warn = true;
            }
            else
            {
                any_fail = true;
            }
        }

        if (cancelled)
        {
            overall_status_ = "CANCELLED";
            operation_errors_.push_back("Directory sanitization was cancelled. Remaining files were not treated as sanitized.");
            return false;
        }
        if (any_fail && any_ok)
        {
            overall_status_ = "PARTIAL_FAILURE";
        }
        else if (any_fail)
        {
            overall_status_ = "FAILED";
        }
        else if (!any_ok && !operation_warnings_.empty())
        {
            overall_status_ = "SKIPPED";
        }
        else if (any_warn || !operation_warnings_.empty())
        {
            overall_status_ = "SUCCESS_WITH_WARNINGS";
        }
        else
        {
            overall_status_ = "SUCCESS";
        }

        if (overall_status_ == "SUCCESS" || overall_status_ == "SUCCESS_WITH_WARNINGS")
        {
            for (auto it = dirs_to_remove.rbegin(); it != dirs_to_remove.rend(); ++it)
            {
                fs::remove(*it, ec);
            }
            fs::remove(dir_path, ec);
            if (ec)
            {
                operation_warnings_.push_back("Could not remove an emptied directory: " + ec.message());
                if (overall_status_ == "SUCCESS")
                {
                    overall_status_ = "SUCCESS_WITH_WARNINGS";
                }
            }
        }
        return overall_status_ == "SUCCESS" || overall_status_ == "SUCCESS_WITH_WARNINGS";
    }

    bool FileShredder::shred(const std::filesystem::path &target_path)
    {
        namespace fs = std::filesystem;
        std::error_code ec;
        root_target_ = audit::path_to_utf8(target_path);
        if (fs::is_directory(target_path, ec))
        {
            root_target_type_ = "directory";
            if (!config_.recursive)
            {
                std::cerr << "[-] Target is a directory. Use -r / --recursive to shred directories.\n";
                overall_status_ = "FAILED";
                operation_errors_.push_back("Directory target requires an explicit recursive request.");
                return false;
            }
            return shred_directory(target_path);
        }
        root_target_type_ = "file";
        const bool ok = shred_file(target_path);
        if (overall_status_ == "PENDING" && !records_.empty())
        {
            overall_status_ = records_.back().status;
        }
        return ok;
    }

    static void write_string_array(std::ostream& out, const std::vector<std::string>& values, int indent)
    {
        const std::string pad(indent, ' ');
        if (values.empty())
        {
            out << "[]";
            return;
        }
        out << "[\n";
        for (size_t i = 0; i < values.size(); ++i)
        {
            out << pad << "  " << audit::json_string(values[i]);
            if (i + 1 < values.size())
                out << ",";
            out << "\n";
        }
        out << pad << "]";
    }

    bool FileShredder::export_audit_json(const std::filesystem::path &output_json_path)
    {
        operation_end_ = get_iso_timestamp();
        std::ofstream out(output_json_path, std::ios::binary);
        if (!out.is_open())
            return false;

        uint64_t bytes = 0;
        bool verification_passed = !records_.empty();
        std::string verification_type = "NONE";
        for (const auto& record : records_)
        {
            bytes += record.bytes_processed;
            if (!record.verification_passed && record.status != "SKIPPED_NOT_REGULAR_FILE")
            {
                verification_passed = false;
            }
            if (record.verification_type != "NONE")
            {
                verification_type = record.verification_type;
            }
        }
        if (records_.empty())
        {
            verification_passed = false;
        }
        if (overall_status_ != "SUCCESS" && overall_status_ != "SUCCESS_WITH_WARNINGS")
        {
            verification_passed = false;
        }

        std::vector<std::string> warnings = operation_warnings_;
        std::vector<std::string> errors = operation_errors_;
        for (const auto& record : records_)
        {
            warnings.insert(warnings.end(), record.warnings.begin(), record.warnings.end());
            errors.insert(errors.end(), record.errors.begin(), record.errors.end());
        }
        warnings.push_back("Logical overwrite does not guarantee destruction on SSD or flash storage, snapshots, journals, cloud copies, or NTFS metadata such as the MFT and USN journal.");

#if defined(_WIN32)
        const char* platform_name = "windows";
#else
        const char* platform_name = "posix";
#endif

        out << "{\n";
        out << "  \"application\": " << audit::json_string(config_.application_version) << ",\n";
        out << "  \"application_version\": " << audit::json_string(config_.application_version) << ",\n";
        out << "  \"sanitizer_version\": " << audit::json_string(config_.sanitizer_version) << ",\n";
        out << "  \"platform\": " << audit::json_string(platform_name) << ",\n";
        out << "  \"operation_id\": " << audit::json_string(operation_id_) << ",\n";
        out << "  \"case_id\": " << audit::json_string(config_.case_id) << ",\n";
        out << "  \"operator\": " << audit::json_string(config_.operator_name) << ",\n";
        out << "  \"timestamp_start\": " << audit::json_string(operation_start_) << ",\n";
        out << "  \"timestamp_end\": " << audit::json_string(operation_end_) << ",\n";
        out << "  \"target\": " << audit::json_string(root_target_) << ",\n";
        out << "  \"target_type\": " << audit::json_string(root_target_type_) << ",\n";
        out << "  \"method\": " << audit::json_string(method_id(config_.method)) << ",\n";
        out << "  \"method_description\": " << audit::json_string(method_description(config_.method)) << ",\n";
        out << "  \"passes\": " << planned_passes(config_) << ",\n";
        out << "  \"bytes_processed\": " << bytes << ",\n";
        out << "  \"status\": " << audit::json_string(overall_status_) << ",\n";
        out << "  \"verification\": {\n";
        out << "    \"passed\": " << audit::json_bool(verification_passed) << ",\n";
        out << "    \"type\": " << audit::json_string(verification_type) << ",\n";
        out << "    \"scope\": " << audit::json_string("logical file contents that were overwritten and read back before discard") << "\n";
        out << "  },\n";
        out << "  \"warnings\": ";
        write_string_array(out, warnings, 2);
        out << ",\n";
        out << "  \"errors\": ";
        write_string_array(out, errors, 2);
        out << ",\n";
        out << "  \"device_identity\": {\n";
        out << "    \"serial\": \"NOT_AVAILABLE\",\n";
        out << "    \"model\": \"NOT_AVAILABLE\"\n";
        out << "  },\n";
        out << "  \"records\": [\n";
        for (size_t i = 0; i < records_.size(); ++i)
        {
            const auto &r = records_[i];
            out << "    {\n";
            out << "      \"target_path\": " << audit::json_string(r.target_path) << ",\n";
            out << "      \"target_type\": " << audit::json_string(r.target_type) << ",\n";
            out << "      \"filesystem_type\": " << audit::json_string(r.filesystem_type) << ",\n";
            out << "      \"method\": " << audit::json_string(r.method_id) << ",\n";
            out << "      \"sanitization_standard\": " << audit::json_string(r.sanitization_standard) << ",\n";
            out << "      \"file_size_bytes\": " << r.file_size_bytes << ",\n";
            out << "      \"bytes_processed\": " << r.bytes_processed << ",\n";
            out << "      \"passes_planned\": " << r.passes_planned << ",\n";
            out << "      \"passes_completed\": " << r.passes_completed << ",\n";
            out << "      \"slack_space_eliminated\": " << audit::json_bool(r.slack_space_eliminated) << ",\n";
            out << "      \"slack_space_status\": " << audit::json_string(r.slack_space_status) << ",\n";
            out << "      \"slack_space_mode\": " << audit::json_string(r.slack_space_mode) << ",\n";
            out << "      \"allocation_unit_bytes\": " << r.allocation_unit_bytes << ",\n";
            out << "      \"slack_bytes_overwritten\": " << r.slack_bytes_overwritten << ",\n";
            out << "      \"trim_invoked\": " << audit::json_bool(r.trim_invoked) << ",\n";
            out << "      \"trim_status\": " << audit::json_string(r.trim_status) << ",\n";
            out << "      \"flush_succeeded\": " << audit::json_bool(r.flush_succeeded) << ",\n";
            out << "      \"flush_status\": " << audit::json_string(r.flush_status) << ",\n";
            out << "      \"verification_type\": " << audit::json_string(r.verification_type) << ",\n";
            out << "      \"verification_scope\": " << audit::json_string(r.verification_scope) << ",\n";
            out << "      \"calculated_entropy\": " << std::fixed << std::setprecision(4) << r.calculated_entropy << ",\n";
            out << "      \"verification_passed\": " << audit::json_bool(r.verification_passed) << ",\n";
            out << "      \"metadata_scrub_completed\": " << audit::json_bool(r.metadata_scrub_completed) << ",\n";
            out << "      \"warnings\": ";
            write_string_array(out, r.warnings, 6);
            out << ",\n";
            out << "      \"errors\": ";
            write_string_array(out, r.errors, 6);
            out << ",\n";
            out << "      \"status\": " << audit::json_string(r.status) << ",\n";
            out << "      \"start_time\": " << audit::json_string(r.start_time) << ",\n";
            out << "      \"end_time\": " << audit::json_string(r.end_time) << "\n";
            out << "    }" << (i + 1 < records_.size() ? "," : "") << "\n";
        }
        out << "  ]\n";
        out << "}\n";
        return static_cast<bool>(out);
    }

    bool FileShredder::export_report_text(const std::filesystem::path &output_text_path)
    {
        if (operation_end_.empty())
        {
            operation_end_ = get_iso_timestamp();
        }
        std::ofstream out(output_text_path, std::ios::binary);
        if (!out.is_open())
            return false;

        uint64_t bytes = 0;
        for (const auto& record : records_)
        {
            bytes += record.bytes_processed;
        }

        out << "AEGIS SANITIZATION REPORT\n";
        out << "=========================\n\n";
        out << "Application version: " << config_.application_version << "\n";
        out << "Sanitizer version: " << config_.sanitizer_version << "\n";
        out << "Operation ID: " << operation_id_ << "\n";
        out << "Case ID: " << (config_.case_id.empty() ? "(none)" : config_.case_id) << "\n";
        out << "Operator: " << (config_.operator_name.empty() ? "(not recorded)" : config_.operator_name) << "\n";
        out << "Start: " << operation_start_ << "\n";
        out << "End: " << operation_end_ << "\n";
        out << "Target: " << root_target_ << "\n";
        out << "Target type: " << root_target_type_ << "\n";
        out << "Method: " << method_id(config_.method) << "\n";
        out << "Method description: " << method_description(config_.method) << "\n";
        out << "Configured passes: " << planned_passes(config_) << "\n";
        out << "Bytes processed: " << bytes << "\n";
        out << "Final status: " << overall_status_ << "\n\n";
        out << "LIMITATIONS\n";
        out << "Logical overwrite does not guarantee destruction on SSD or flash storage, snapshots, journals, cloud copies, or NTFS metadata.\n";
        out << "A discard/TRIM request is not cryptographic erase and is not proof that NAND cells were cleared.\n";
        out << "Entropy verification is not a cryptographic proof.\n\n";
        out << "FILE RESULTS\n";
        for (const auto& record : records_)
        {
            out << "- " << record.target_path << "\n";
            out << "  status: " << record.status << "\n";
            out << "  filesystem: " << record.filesystem_type << "\n";
            out << "  size: " << record.file_size_bytes << "\n";
            out << "  passes completed: " << record.passes_completed << " of " << record.passes_planned << "\n";
            out << "  verification: " << record.verification_type
                << (record.verification_passed ? " passed" : " failed") << "\n";
            out << "  verification scope: " << record.verification_scope << "\n";
            out << "  flush: " << record.flush_status << "\n";
            out << "  slack: " << record.slack_space_status << "\n";
            out << "  trim: " << record.trim_status << "\n";
            for (const auto& warning : record.warnings)
            {
                out << "  warning: " << warning << "\n";
            }
            for (const auto& error : record.errors)
            {
                out << "  error: " << error << "\n";
            }
        }
        if (overall_status_ != "SUCCESS" && overall_status_ != "SUCCESS_WITH_WARNINGS")
        {
            out << "\nThis report does not certify a successful sanitization.\n";
        }
        return static_cast<bool>(out);
    }

} // namespace aegis::sanitizer
