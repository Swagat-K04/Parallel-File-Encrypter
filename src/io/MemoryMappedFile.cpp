#include "MemoryMappedFile.hpp"
#include <utility>
#include <cstring>
#include <iostream>

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace io {

MemoryMappedFile::MemoryMappedFile() = default;

MemoryMappedFile::~MemoryMappedFile() {
    close();
}

MemoryMappedFile::MemoryMappedFile(MemoryMappedFile&& other) noexcept 
    : path_(std::move(other.path_)),
      mappedData_(other.mappedData_),
      size_(other.size_),
      mode_(other.mode_)
{
#if defined(_WIN32) || defined(_WIN64)
    fileHandle_ = other.fileHandle_;
    mappingHandle_ = other.mappingHandle_;
    other.fileHandle_ = (void*)-1;
    other.mappingHandle_ = nullptr;
#else
    fd_ = other.fd_;
    other.fd_ = -1;
#endif
    other.mappedData_ = nullptr;
    other.size_ = 0;
}

MemoryMappedFile& MemoryMappedFile::operator=(MemoryMappedFile&& other) noexcept {
    if (this != &other) {
        close();
        path_ = std::move(other.path_);
        mappedData_ = other.mappedData_;
        size_ = other.size_;
        mode_ = other.mode_;
#if defined(_WIN32) || defined(_WIN64)
        fileHandle_ = other.fileHandle_;
        mappingHandle_ = other.mappingHandle_;
        other.fileHandle_ = (void*)-1;
        other.mappingHandle_ = nullptr;
#else
        fd_ = other.fd_;
        other.fd_ = -1;
#endif
        other.mappedData_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

#if defined(_WIN32) || defined(_WIN64)

static std::wstring utf8ToWide(const std::string& str) {
    if (str.empty()) return std::wstring();
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
    std::wstring wstr(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &wstr[0], sizeNeeded);
    return wstr;
}

void MemoryMappedFile::open(const std::string& path, OpenMode mode, size_t newSize) {
    close();
    path_ = path;
    mode_ = mode;

    DWORD desiredAccess = 0;
    DWORD shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    DWORD creationDisposition = 0;
    DWORD pageProtect = 0;
    DWORD mapAccess = 0;

    switch (mode) {
        case OpenMode::ReadOnly:
            desiredAccess = GENERIC_READ;
            creationDisposition = OPEN_EXISTING;
            pageProtect = PAGE_READONLY;
            mapAccess = FILE_MAP_READ;
            break;
        case OpenMode::ReadWrite:
            desiredAccess = GENERIC_READ | GENERIC_WRITE;
            creationDisposition = OPEN_EXISTING;
            pageProtect = PAGE_READWRITE;
            mapAccess = FILE_MAP_ALL_ACCESS;
            break;
        case OpenMode::CreateOrResize:
            desiredAccess = GENERIC_READ | GENERIC_WRITE;
            creationDisposition = OPEN_ALWAYS;
            pageProtect = PAGE_READWRITE;
            mapAccess = FILE_MAP_ALL_ACCESS;
            break;
    }

    std::wstring widePath = utf8ToWide(path);
    HANDLE hFile = CreateFileW(
        widePath.c_str(),
        desiredAccess,
        shareMode,
        nullptr,
        creationDisposition,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        throw MemoryMappedException("Failed to open file for mapping: " + path + " (WinError " + std::to_string(GetLastError()) + ")");
    }
    fileHandle_ = (void*)hFile;

    if (mode == OpenMode::CreateOrResize && newSize > 0) {
        LARGE_INTEGER liSize;
        liSize.QuadPart = newSize;
        if (!SetFilePointerEx(hFile, liSize, nullptr, FILE_BEGIN) || !SetEndOfFile(hFile)) {
            close();
            throw MemoryMappedException("Failed to resize file: " + path);
        }
        size_ = newSize;
    } else {
        LARGE_INTEGER liSize;
        if (!GetFileSizeEx(hFile, &liSize)) {
            close();
            throw MemoryMappedException("Failed to get file size: " + path);
        }
        size_ = static_cast<size_t>(liSize.QuadPart);
    }

    // Zero-byte files cannot be mapped directly in Windows/POSIX
    if (size_ == 0) {
        mappedData_ = nullptr;
        return;
    }

    ULARGE_INTEGER uliSize;
    uliSize.QuadPart = size_;
    HANDLE hMapping = CreateFileMappingW(
        hFile,
        nullptr,
        pageProtect,
        uliSize.HighPart,
        uliSize.LowPart,
        nullptr
    );

    if (!hMapping) {
        DWORD err = GetLastError();
        close();
        throw MemoryMappedException("Failed to create file mapping object: " + path + " (WinError " + std::to_string(err) + ")");
    }
    mappingHandle_ = (void*)hMapping;

    void* ptr = MapViewOfFile(
        hMapping,
        mapAccess,
        0,
        0,
        size_
    );

    if (!ptr) {
        DWORD err = GetLastError();
        close();
        throw MemoryMappedException("Failed to map view of file: " + path + " (WinError " + std::to_string(err) + ")");
    }

    mappedData_ = static_cast<uint8_t*>(ptr);
}

void MemoryMappedFile::sync(bool async) {
    if (mappedData_ && (mode_ != OpenMode::ReadOnly)) {
        FlushViewOfFile(mappedData_, size_);
        if (!async && fileHandle_ != (void*)-1) {
            FlushFileBuffers((HANDLE)fileHandle_);
        }
    }
}

void MemoryMappedFile::advise(AccessAdvice advice) {
    // Windows supports PrefetchVirtualMemory on Windows 8+
    if (mappedData_ && (advice == AccessAdvice::Sequential || advice == AccessAdvice::WillNeed)) {
        // Optimization hint to OS cache
    }
}

void MemoryMappedFile::close() {
    if (mappedData_) {
        UnmapViewOfFile(mappedData_);
        mappedData_ = nullptr;
    }
    if (mappingHandle_) {
        CloseHandle((HANDLE)mappingHandle_);
        mappingHandle_ = nullptr;
    }
    if (fileHandle_ && fileHandle_ != (void*)-1) {
        CloseHandle((HANDLE)fileHandle_);
        fileHandle_ = (void*)-1;
    }
    size_ = 0;
}

#else // POSIX (Linux, macOS, BSD)

void MemoryMappedFile::open(const std::string& path, OpenMode mode, size_t newSize) {
    close();
    path_ = path;
    mode_ = mode;

    int flags = 0;
    int prot = 0;

    switch (mode) {
        case OpenMode::ReadOnly:
            flags = O_RDONLY;
            prot = PROT_READ;
            break;
        case OpenMode::ReadWrite:
            flags = O_RDWR;
            prot = PROT_READ | PROT_WRITE;
            break;
        case OpenMode::CreateOrResize:
            flags = O_RDWR | O_CREAT;
            prot = PROT_READ | PROT_WRITE;
            break;
    }

    fd_ = ::open(path.c_str(), flags, 0666);
    if (fd_ < 0) {
        throw MemoryMappedException("Failed to open file for mapping: " + path + " (" + strerror(errno) + ")");
    }

    if (mode == OpenMode::CreateOrResize && newSize > 0) {
        if (::ftruncate(fd_, newSize) < 0) {
            close();
            throw MemoryMappedException("Failed to resize file: " + path);
        }
        size_ = newSize;
    } else {
        struct stat st;
        if (::fstat(fd_, &st) < 0) {
            close();
            throw MemoryMappedException("Failed to stat file: " + path);
        }
        size_ = static_cast<size_t>(st.st_size);
    }

    if (size_ == 0) {
        mappedData_ = nullptr;
        return;
    }

    void* ptr = ::mmap(nullptr, size_, prot, MAP_SHARED, fd_, 0);
    if (ptr == MAP_FAILED) {
        close();
        throw MemoryMappedException("Failed to mmap file: " + path + " (" + strerror(errno) + ")");
    }

    mappedData_ = static_cast<uint8_t*>(ptr);
}

void MemoryMappedFile::sync(bool async) {
    if (mappedData_ && (mode_ != OpenMode::ReadOnly)) {
        ::msync(mappedData_, size_, async ? MS_ASYNC : MS_SYNC);
    }
}

void MemoryMappedFile::advise(AccessAdvice advice) {
    if (mappedData_ && size_ > 0) {
        int posixAdvice = POSIX_MADV_NORMAL;
        switch (advice) {
            case AccessAdvice::Sequential: posixAdvice = POSIX_MADV_SEQUENTIAL; break;
            case AccessAdvice::Random:     posixAdvice = POSIX_MADV_RANDOM; break;
            case AccessAdvice::WillNeed:   posixAdvice = POSIX_MADV_WILLNEED; break;
            default:                       posixAdvice = POSIX_MADV_NORMAL; break;
        }
        ::posix_madvise(mappedData_, size_, posixAdvice);
    }
}

void MemoryMappedFile::close() {
    if (mappedData_ && size_ > 0) {
        ::munmap(mappedData_, size_);
        mappedData_ = nullptr;
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    size_ = 0;
}

#endif

} // namespace io
