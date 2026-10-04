#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace aegis::sanitizer::winops {

struct Progress {
    std::string phase;
    uint64_t bytes_completed = 0;
    uint64_t bytes_total = 0;
    uint32_t current_pass = 0;
    uint32_t total_passes = 0;
};

using ProgressFn = std::function<void(const Progress&)>;

struct WipeResult {
    bool ok = false;
    std::string status = "FAILED";
    std::string message;
    uint64_t bytes = 0;
    bool sample_verified = false;
};

struct AcquireResult {
    bool ok = false;
    std::string status = "FAILED";
    std::string message;
    uint64_t bytes = 0;
    std::string sha256;
};

/** Removable USB/SD volume or physical disk zero-fill. Requires elevated process. */
WipeResult wipe_removable_device(const std::string& device_utf8,
                                 uint32_t passes,
                                 ProgressFn on_progress,
                                 const std::string& cancel_file_utf8);

/** Read-only RAW acquire of a device or file into destination. Never writes source. */
AcquireResult acquire_raw(const std::string& source_utf8,
                          const std::string& dest_utf8,
                          int64_t max_bytes,
                          bool allow_non_removable_read,
                          ProgressFn on_progress);

} // namespace aegis::sanitizer::winops
