#ifndef MEMORY_MAPPED_FILE_HPP
#define MEMORY_MAPPED_FILE_HPP

#include <string>
#include <string_view>
#include <cstdint>
#include <cstddef>
#include <system_error>
#include <stdexcept>

namespace io {

enum class OpenMode {
    ReadOnly,
    ReadWrite,
    CreateOrResize
};

enum class AccessAdvice {
    Normal,
    Sequential,
    Random,
    WillNeed
};

class MemoryMappedException : public std::runtime_error {
public:
    explicit MemoryMappedException(const std::string& msg) : std::runtime_error(msg) {}
};

class MemoryMappedFile {
public:
    MemoryMappedFile();
    ~MemoryMappedFile();

    // Disable copying to enforce strict unique RAII ownership
    MemoryMappedFile(const MemoryMappedFile&) = delete;
    MemoryMappedFile& operator=(const MemoryMappedFile&) = delete;

    // Enable moving
    MemoryMappedFile(MemoryMappedFile&& other) noexcept;
    MemoryMappedFile& operator=(MemoryMappedFile&& other) noexcept;

    // Opens and memory-maps a file at the specified path
    void open(const std::string& path, OpenMode mode, size_t newSize = 0);

    // Unmaps and closes the file descriptor/handle
    void close();

    // Flushes modified memory pages back to disk storage asynchronously or synchronously
    void sync(bool async = false);

    // Provides page cache readahead/caching advice to the OS kernel
    void advise(AccessAdvice advice);

    // Raw pointer access to mapped virtual memory (Zero-Copy)
    uint8_t* data() noexcept { return mappedData_; }
    const uint8_t* data() const noexcept { return mappedData_; }

    // Mapped size in bytes
    size_t size() const noexcept { return size_; }

    // Is the file currently mapped
    bool isMapped() const noexcept { return mappedData_ != nullptr; }

    const std::string& path() const noexcept { return path_; }

private:
    std::string path_;
    uint8_t* mappedData_ = nullptr;
    size_t size_ = 0;
    OpenMode mode_ = OpenMode::ReadOnly;

#if defined(_WIN32) || defined(_WIN64)
    void* fileHandle_ = (void*)-1;    // INVALID_HANDLE_VALUE
    void* mappingHandle_ = nullptr;
#else
    int fd_ = -1;
#endif
};

} // namespace io

#endif // MEMORY_MAPPED_FILE_HPP
