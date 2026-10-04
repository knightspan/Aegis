#include "sanitizer/win_device_ops.hpp"

#if defined(_WIN32) || defined(_WIN64)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#include <windows.h>
#include <winioctl.h>
#include <bcrypt.h>

#include <algorithm>
#include <fstream>
#include <sstream>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace aegis::sanitizer::winops {
namespace {

std::wstring utf8_to_wide(const std::string& utf8) {
    if (utf8.empty()) {
        return {};
    }
    const int needed = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (needed <= 1) {
        return {};
    }
    std::wstring out(static_cast<size_t>(needed - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, out.data(), needed);
    return out;
}

std::string wide_to_utf8(const std::wstring& wide) {
    if (wide.empty()) {
        return {};
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) {
        return {};
    }
    std::string out(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, out.data(), needed, nullptr, nullptr);
    return out;
}

std::string last_error_message(DWORD err) {
    std::ostringstream ss;
    ss << "Win32 error " << err;
    return ss.str();
}

class Handle {
public:
    explicit Handle(HANDLE h = INVALID_HANDLE_VALUE) : h_(h) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : h_(other.h_) { other.h_ = INVALID_HANDLE_VALUE; }
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            reset();
            h_ = other.h_;
            other.h_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    HANDLE get() const { return h_; }
    bool valid() const { return h_ != INVALID_HANDLE_VALUE && h_ != nullptr; }
    void reset(HANDLE h = INVALID_HANDLE_VALUE) {
        if (valid()) {
            CloseHandle(h_);
        }
        h_ = h;
    }
private:
    HANDLE h_;
};

bool cancel_requested(const std::string& cancel_file_utf8) {
    if (cancel_file_utf8.empty()) {
        return false;
    }
    const std::wstring path = utf8_to_wide(cancel_file_utf8);
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool is_system_volume_letter(wchar_t letter) {
    wchar_t windows_dir[MAX_PATH] = {};
    if (GetWindowsDirectoryW(windows_dir, MAX_PATH) == 0) {
        return letter == L'C';
    }
    return towupper(windows_dir[0]) == towupper(letter);
}

bool query_bus_usb_or_sd(HANDLE device, bool* out_ok_bus, std::string* detail) {
    *out_ok_bus = false;
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    std::vector<BYTE> buffer(4096);
    DWORD returned = 0;
    if (!DeviceIoControl(device, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                         buffer.data(), static_cast<DWORD>(buffer.size()), &returned, nullptr)) {
        if (detail) {
            *detail = "IOCTL_STORAGE_QUERY_PROPERTY failed: " + last_error_message(GetLastError());
        }
        return false;
    }
    auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
    const BYTE bus = desc->BusType;
    // BusTypeUsb=7, BusTypeSd=14, BusTypeMultiMediaCard=15 (winioctl)
    *out_ok_bus = (bus == BusTypeUsb || bus == 14 || bus == 15);
    if (detail) {
        std::ostringstream ss;
        ss << "busType=" << static_cast<unsigned>(bus);
        *detail = ss.str();
    }
    return true;
}

uint64_t device_length(HANDLE device) {
    GET_LENGTH_INFORMATION length_info{};
    DWORD returned = 0;
    if (DeviceIoControl(device, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0,
                        &length_info, sizeof(length_info), &returned, nullptr)) {
        return static_cast<uint64_t>(length_info.Length.QuadPart);
    }
    LARGE_INTEGER size{};
    if (GetFileSizeEx(device, &size)) {
        return static_cast<uint64_t>(size.QuadPart);
    }
    return 0;
}

bool is_removable_target(const std::wstring& wide_path, HANDLE device, std::string* reason) {
    // Volume form: \\.\E:
    if (wide_path.size() >= 6 && wide_path[0] == L'\\' && wide_path[1] == L'\\' &&
        wide_path[2] == L'.' && wide_path[3] == L'\\' &&
        iswalpha(wide_path[4]) && wide_path[5] == L':') {
        const wchar_t letter = towupper(wide_path[4]);
        if (is_system_volume_letter(letter)) {
            if (reason) {
                *reason = "Refusing system volume.";
            }
            return false;
        }
        std::wstring root;
        root.push_back(letter);
        root.append(L":\\");
        const UINT drive_type = GetDriveTypeW(root.c_str());
        if (drive_type != DRIVE_REMOVABLE) {
            if (reason) {
                *reason = "Volume is not DRIVE_REMOVABLE.";
            }
            return false;
        }
        bool ok_bus = false;
        std::string bus_detail;
        if (query_bus_usb_or_sd(device, &ok_bus, &bus_detail) && !ok_bus) {
            if (reason) {
                *reason = "Volume bus is not USB/SD (" + bus_detail + ").";
            }
            return false;
        }
        return true;
    }

    // PhysicalDriveN
    std::wstring lower = wide_path;
    for (auto& c : lower) {
        c = towlower(c);
    }
    const auto pos = lower.find(L"physicaldrive");
    if (pos == std::wstring::npos) {
        if (reason) {
            *reason = "Target is neither a volume device path nor PhysicalDriveN.";
        }
        return false;
    }
    int disk_number = -1;
    try {
        disk_number = std::stoi(wide_to_utf8(lower.substr(pos + 13)));
    } catch (...) {
        disk_number = -1;
    }
    if (disk_number < 0) {
        if (reason) {
            *reason = "Could not parse PhysicalDrive number.";
        }
        return false;
    }
    if (disk_number == 0) {
        // Fail closed: disk 0 is almost always the system disk on Windows installs.
        if (reason) {
            *reason = "Refusing PhysicalDrive0 (system disk fail-closed).";
        }
        return false;
    }
    bool ok_bus = false;
    std::string bus_detail;
    if (!query_bus_usb_or_sd(device, &ok_bus, &bus_detail)) {
        if (reason) {
            *reason = "Could not confirm bus type; refusing wipe. " + bus_detail;
        }
        return false;
    }
    if (!ok_bus) {
        if (reason) {
            *reason = "Physical disk bus is not USB/SD (" + bus_detail + ").";
        }
        return false;
    }
    return true;
}

bool sample_verify_zeros(HANDLE device, uint64_t length) {
    if (length == 0) {
        return false;
    }
    const uint64_t offsets[] = {
        0,
        length / 2,
        length > 4096 ? length - 4096 : 0
    };
    std::vector<BYTE> buf(4096);
    for (uint64_t offset : offsets) {
        LARGE_INTEGER li{};
        li.QuadPart = static_cast<LONGLONG>(offset);
        if (!SetFilePointerEx(device, li, nullptr, FILE_BEGIN)) {
            return false;
        }
        DWORD read = 0;
        if (!ReadFile(device, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr) || read == 0) {
            return false;
        }
        for (DWORD i = 0; i < read; ++i) {
            if (buf[i] != 0) {
                return false;
            }
        }
    }
    return true;
}

std::string sha256_hex(BCRYPT_HASH_HANDLE hash) {
    DWORD hash_len = 0;
    DWORD cb = 0;
    if (BCryptGetProperty(hash, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len),
                          sizeof(hash_len), &cb, 0) != 0) {
        return {};
    }
    std::vector<BYTE> digest(hash_len);
    if (BCryptFinishHash(hash, digest.data(), hash_len, 0) != 0) {
        return {};
    }
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(digest.size() * 2);
    for (BYTE b : digest) {
        out.push_back(hex[(b >> 4) & 0xF]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

} // namespace

WipeResult wipe_removable_device(const std::string& device_utf8,
                                 uint32_t passes,
                                 ProgressFn on_progress,
                                 const std::string& cancel_file_utf8) {
    WipeResult result;
    if (device_utf8.empty()) {
        result.message = "Missing device path.";
        return result;
    }
    if (passes == 0) {
        passes = 1;
    }
    const std::wstring wide = utf8_to_wide(device_utf8);
    Handle device(CreateFileW(wide.c_str(),
                              GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr,
                              OPEN_EXISTING,
                              FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
                              nullptr));
    if (!device.valid()) {
        // Retry without NO_BUFFERING (volume handles sometimes reject it).
        device.reset(CreateFileW(wide.c_str(),
                                 GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 nullptr,
                                 OPEN_EXISTING,
                                 0,
                                 nullptr));
    }
    if (!device.valid()) {
        result.status = "FAILED";
        result.message = "Could not open device for write: " + last_error_message(GetLastError());
        return result;
    }

    std::string reason;
    if (!is_removable_target(wide, device.get(), &reason)) {
        result.status = "UNSUPPORTED";
        result.message = reason.empty()
                ? "Target is not an eligible removable USB/SD device. No sectors were written."
                : reason + " No sectors were written.";
        return result;
    }

    const uint64_t length = device_length(device.get());
    if (length == 0) {
        result.status = "FAILED";
        result.message = "Could not determine device length.";
        return result;
    }

    const size_t chunk = 1024 * 1024;
    std::vector<BYTE> zeros(chunk, 0);
    uint64_t written_total = 0;

    for (uint32_t pass = 1; pass <= passes; ++pass) {
        LARGE_INTEGER zero{};
        if (!SetFilePointerEx(device.get(), zero, nullptr, FILE_BEGIN)) {
            result.status = "FAILED";
            result.message = "Seek failed: " + last_error_message(GetLastError());
            return result;
        }
        uint64_t remaining = length;
        uint64_t pass_written = 0;
        while (remaining > 0) {
            if (cancel_requested(cancel_file_utf8)) {
                result.status = "CANCELLED";
                result.message = "Cancellation requested. Wipe is not a successful sanitization.";
                result.bytes = written_total;
                return result;
            }
            const DWORD to_write = static_cast<DWORD>(std::min<uint64_t>(remaining, chunk));
            DWORD wrote = 0;
            if (!WriteFile(device.get(), zeros.data(), to_write, &wrote, nullptr) || wrote != to_write) {
                result.status = "FAILED";
                result.message = "Write failed at offset " + std::to_string(pass_written)
                        + ": " + last_error_message(GetLastError());
                result.bytes = written_total;
                return result;
            }
            remaining -= wrote;
            pass_written += wrote;
            written_total += wrote;
            if (on_progress) {
                Progress p;
                p.phase = "overwrite";
                p.bytes_completed = pass_written;
                p.bytes_total = length;
                p.current_pass = pass;
                p.total_passes = passes;
                on_progress(p);
            }
        }
        FlushFileBuffers(device.get());
    }

    result.sample_verified = sample_verify_zeros(device.get(), length);
    result.ok = true;
    result.bytes = length * passes;
    result.status = result.sample_verified ? "SUCCESS" : "SUCCESS_WITH_WARNINGS";
    result.message = result.sample_verified
            ? "Removable device zero-fill completed; sample read-back verified zeros."
            : "Removable device zero-fill completed; sample read-back did not fully verify.";
    return result;
}

AcquireResult acquire_raw(const std::string& source_utf8,
                          const std::string& dest_utf8,
                          int64_t max_bytes,
                          bool allow_non_removable_read,
                          ProgressFn on_progress) {
    AcquireResult result;
    if (source_utf8.empty() || dest_utf8.empty()) {
        result.message = "Missing source or destination.";
        return result;
    }
    const std::wstring source_w = utf8_to_wide(source_utf8);
    const std::wstring dest_w = utf8_to_wide(dest_utf8);

    Handle source(CreateFileW(source_w.c_str(),
                              GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr,
                              OPEN_EXISTING,
                              FILE_FLAG_SEQUENTIAL_SCAN,
                              nullptr));
    if (!source.valid()) {
        result.message = "Could not open source for read: " + last_error_message(GetLastError());
        return result;
    }

    if (!allow_non_removable_read) {
        std::string reason;
        // Re-open briefly with write share only for bus query; source stays read-only.
        if (!is_removable_target(source_w, source.get(), &reason)) {
            // For imaging, allow non-removable if explicitly flagged; otherwise require removable.
            // is_removable_target rejects system — still refuse system/boot style targets.
            if (reason.find("system") != std::string::npos || reason.find("PhysicalDrive0") != std::string::npos) {
                result.status = "UNSUPPORTED";
                result.message = reason;
                return result;
            }
            result.status = "UNSUPPORTED";
            result.message = "Source is not confirmed removable USB/SD. Pass --allow-non-removable-read for imaging fixed disks. "
                    + reason;
            return result;
        }
    } else {
        // Still refuse obvious system volume letters.
        if (source_w.size() >= 6 && iswalpha(source_w[4]) && source_w[5] == L':' &&
            is_system_volume_letter(source_w[4])) {
            result.status = "UNSUPPORTED";
            result.message = "Refusing to acquire the Windows system volume.";
            return result;
        }
        std::wstring lower = source_w;
        for (auto& c : lower) {
            c = towlower(c);
        }
        if (lower.find(L"physicaldrive0") != std::wstring::npos) {
            result.status = "UNSUPPORTED";
            result.message = "Refusing PhysicalDrive0 in this acquire path (fail-closed).";
            return result;
        }
    }

    uint64_t length = device_length(source.get());
    if (max_bytes > 0 && (length == 0 || static_cast<uint64_t>(max_bytes) < length)) {
        length = static_cast<uint64_t>(max_bytes);
    }
    if (length == 0) {
        result.message = "Could not determine source size.";
        return result;
    }

    Handle dest(CreateFileW(dest_w.c_str(),
                            GENERIC_WRITE,
                            0,
                            nullptr,
                            CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                            nullptr));
    if (!dest.valid()) {
        result.message = "Could not create destination: " + last_error_message(GetLastError());
        return result;
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        result.message = "BCrypt SHA-256 provider unavailable.";
        return result;
    }
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        result.message = "BCryptCreateHash failed.";
        return result;
    }

    const size_t chunk = 1024 * 1024;
    std::vector<BYTE> buf(chunk);
    uint64_t remaining = length;
    uint64_t copied = 0;
    LARGE_INTEGER zero{};
    SetFilePointerEx(source.get(), zero, nullptr, FILE_BEGIN);

    while (remaining > 0) {
        const DWORD to_read = static_cast<DWORD>(std::min<uint64_t>(remaining, chunk));
        DWORD got = 0;
        if (!ReadFile(source.get(), buf.data(), to_read, &got, nullptr) || got == 0) {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            result.message = "Read failed at offset " + std::to_string(copied) + ": "
                    + last_error_message(GetLastError());
            return result;
        }
        DWORD wrote = 0;
        if (!WriteFile(dest.get(), buf.data(), got, &wrote, nullptr) || wrote != got) {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            result.message = "Write to image failed: " + last_error_message(GetLastError());
            return result;
        }
        BCryptHashData(hash, buf.data(), got, 0);
        remaining -= got;
        copied += got;
        if (on_progress) {
            Progress p;
            p.phase = "acquire";
            p.bytes_completed = copied;
            p.bytes_total = length;
            p.current_pass = 1;
            p.total_passes = 1;
            on_progress(p);
        }
    }

    result.sha256 = sha256_hex(hash);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    FlushFileBuffers(dest.get());

    result.ok = true;
    result.bytes = copied;
    result.status = "SUCCESS";
    result.message = "RAW acquisition completed.";
    return result;
}

} // namespace aegis::sanitizer::winops

#else

namespace aegis::sanitizer::winops {

WipeResult wipe_removable_device(const std::string&, uint32_t, ProgressFn, const std::string&) {
    WipeResult r;
    r.status = "UNSUPPORTED";
    r.message = "Windows device wipe is not available on this platform.";
    return r;
}

AcquireResult acquire_raw(const std::string&, const std::string&, int64_t, bool, ProgressFn) {
    AcquireResult r;
    r.status = "UNSUPPORTED";
    r.message = "Windows acquire is not available on this platform.";
    return r;
}

} // namespace aegis::sanitizer::winops

#endif
