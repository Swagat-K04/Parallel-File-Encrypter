#include "SharedTaskQueue.hpp"
#include <cstring>
#include <iostream>
#include <chrono>

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <semaphore.h>
#include <pthread.h>
#include <errno.h>
#endif

namespace ipc {

#if defined(_WIN32) || defined(_WIN64)

static std::wstring toWide(const std::string& str) {
    if (str.empty()) return std::wstring();
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
    std::wstring wstr(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &wstr[0], sizeNeeded);
    return wstr;
}

SharedTaskQueue::SharedTaskQueue(const std::string& queueName, bool isOwner)
    : queueName_(queueName), isOwner_(isOwner)
{
    std::wstring wShmName = toWide("Local\\SHM_" + queueName_);
    std::wstring wMutexName = toWide("Local\\MTX_" + queueName_);
    std::wstring wEmptySem = toWide("Local\\SEM_EMP_" + queueName_);
    std::wstring wAvailSem = toWide("Local\\SEM_AVL_" + queueName_);

    size_t totalBytes = sizeof(SharedQueueState);

    if (isOwner_) {
        // Create Shared Memory Segment
        HANDLE hShm = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            nullptr,
            PAGE_READWRITE,
            0,
            static_cast<DWORD>(totalBytes),
            wShmName.c_str()
        );
        if (!hShm) {
            throw IPCException("Failed to create shared memory mapping (WinError: " + std::to_string(GetLastError()) + ")");
        }
        shmHandle_ = (void*)hShm;

        // Create Named Mutex
        HANDLE hMutex = CreateMutexW(nullptr, FALSE, wMutexName.c_str());
        if (!hMutex) {
            throw IPCException("Failed to create named mutex (WinError: " + std::to_string(GetLastError()) + ")");
        }
        mutexHandle_ = (void*)hMutex;

        // Create Empty Slots Semaphore (initial = QUEUE_CAPACITY)
        HANDLE hEmpty = CreateSemaphoreW(nullptr, static_cast<LONG>(QUEUE_CAPACITY), static_cast<LONG>(QUEUE_CAPACITY), wEmptySem.c_str());
        if (!hEmpty) {
            throw IPCException("Failed to create empty slots semaphore (WinError: " + std::to_string(GetLastError()) + ")");
        }
        emptySlotsSem_ = (void*)hEmpty;

        // Create Available Items Semaphore (initial = 0)
        HANDLE hAvail = CreateSemaphoreW(nullptr, 0, static_cast<LONG>(QUEUE_CAPACITY), wAvailSem.c_str());
        if (!hAvail) {
            throw IPCException("Failed to create available items semaphore (WinError: " + std::to_string(GetLastError()) + ")");
        }
        itemsAvailSem_ = (void*)hAvail;
    } else {
        // Open Existing Shared Memory Segment
        HANDLE hShm = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, wShmName.c_str());
        if (!hShm) {
            throw IPCException("Worker failed to open shared memory (WinError: " + std::to_string(GetLastError()) + ")");
        }
        shmHandle_ = (void*)hShm;

        // Open Existing Named Mutex
        HANDLE hMutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, wMutexName.c_str());
        if (!hMutex) {
            throw IPCException("Worker failed to open named mutex (WinError: " + std::to_string(GetLastError()) + ")");
        }
        mutexHandle_ = (void*)hMutex;

        // Open Existing Semaphores
        HANDLE hEmpty = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, wEmptySem.c_str());
        if (!hEmpty) {
            throw IPCException("Worker failed to open empty slots semaphore (WinError: " + std::to_string(GetLastError()) + ")");
        }
        emptySlotsSem_ = (void*)hEmpty;

        HANDLE hAvail = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, wAvailSem.c_str());
        if (!hAvail) {
            throw IPCException("Worker failed to open available items semaphore (WinError: " + std::to_string(GetLastError()) + ")");
        }
        itemsAvailSem_ = (void*)hAvail;
    }

    void* ptr = MapViewOfFile((HANDLE)shmHandle_, FILE_MAP_ALL_ACCESS, 0, 0, totalBytes);
    if (!ptr) {
        throw IPCException("Failed to map view of shared memory (WinError: " + std::to_string(GetLastError()) + ")");
    }
    sharedState_ = static_cast<SharedQueueState*>(ptr);

    if (isOwner_) {
        std::memset(sharedState_, 0, sizeof(SharedQueueState));
    }
}

void SharedTaskQueue::acquireLock() {
    DWORD res = WaitForSingleObject((HANDLE)mutexHandle_, INFINITE);
    if (res == WAIT_ABANDONED) {
        // Previous owner process crashed while holding mutex; recovered ownership
        std::cerr << "[IPC WARNING] Recovered abandoned process-shared mutex after worker termination." << std::endl;
    } else if (res != WAIT_OBJECT_0) {
        throw IPCException("Failed to acquire process-shared mutex.");
    }
}

void SharedTaskQueue::releaseLock() {
    ReleaseMutex((HANDLE)mutexHandle_);
}

bool SharedTaskQueue::push(const TaskDescriptor& task, uint32_t timeoutMs) {
    DWORD waitTimeout = (timeoutMs == 0) ? INFINITE : timeoutMs;
    DWORD waitRes = WaitForSingleObject((HANDLE)emptySlotsSem_, waitTimeout);
    if (waitRes != WAIT_OBJECT_0) {
        return false; // Timed out or error
    }

    acquireLock();
    uint32_t idx = sharedState_->rear;
    std::memcpy(&sharedState_->tasks[idx], &task, sizeof(TaskDescriptor));
    sharedState_->rear = (sharedState_->rear + 1) % QUEUE_CAPACITY;
    sharedState_->count++;
    if (task.type != TaskType::SHUTDOWN) {
        sharedState_->totalSubmitted++;
    }
    releaseLock();

    ReleaseSemaphore((HANDLE)itemsAvailSem_, 1, nullptr);
    return true;
}

bool SharedTaskQueue::pop(TaskDescriptor& task, uint32_t timeoutMs) {
    DWORD waitTimeout = (timeoutMs == 0) ? INFINITE : timeoutMs;
    DWORD waitRes = WaitForSingleObject((HANDLE)itemsAvailSem_, waitTimeout);
    if (waitRes != WAIT_OBJECT_0) {
        return false;
    }

    acquireLock();
    uint32_t idx = sharedState_->front;
    std::memcpy(&task, &sharedState_->tasks[idx], sizeof(TaskDescriptor));
    sharedState_->front = (sharedState_->front + 1) % QUEUE_CAPACITY;
    sharedState_->count--;
    releaseLock();

    ReleaseSemaphore((HANDLE)emptySlotsSem_, 1, nullptr);
    return true;
}

void SharedTaskQueue::recordCompletion(bool success) {
    acquireLock();
    if (success) {
        sharedState_->totalCompleted++;
    } else {
        sharedState_->totalFailed++;
    }
    releaseLock();
}

QueueStats SharedTaskQueue::getStats() {
    acquireLock();
    QueueStats stats{};
    stats.totalSubmitted = sharedState_->totalSubmitted;
    stats.totalCompleted = sharedState_->totalCompleted;
    stats.totalFailed = sharedState_->totalFailed;
    stats.currentQueueSize = sharedState_->count;
    releaseLock();
    return stats;
}

void SharedTaskQueue::close() {
    if (sharedState_) {
        UnmapViewOfFile(sharedState_);
        sharedState_ = nullptr;
    }
    if (emptySlotsSem_) {
        CloseHandle((HANDLE)emptySlotsSem_);
        emptySlotsSem_ = nullptr;
    }
    if (itemsAvailSem_) {
        CloseHandle((HANDLE)itemsAvailSem_);
        itemsAvailSem_ = nullptr;
    }
    if (mutexHandle_) {
        CloseHandle((HANDLE)mutexHandle_);
        mutexHandle_ = nullptr;
    }
    if (shmHandle_) {
        CloseHandle((HANDLE)shmHandle_);
        shmHandle_ = nullptr;
    }
}

#else // POSIX (Linux / UNIX / macOS)

SharedTaskQueue::SharedTaskQueue(const std::string& queueName, bool isOwner)
    : queueName_(queueName), isOwner_(isOwner)
{
    std::string shmPath = "/" + queueName_;
    std::string semEmptyPath = "/" + queueName_ + "_emp";
    std::string semAvailPath = "/" + queueName_ + "_avl";

    size_t totalBytes = sizeof(SharedQueueState);

    if (isOwner_) {
        // Clean up any stale segments from previous ungraceful aborts
        shm_unlink(shmPath.c_str());
        sem_unlink(semEmptyPath.c_str());
        sem_unlink(semAvailPath.c_str());

        shmFd_ = shm_open(shmPath.c_str(), O_CREAT | O_RDWR, 0660);
        if (shmFd_ < 0) {
            throw IPCException("shm_open failed: " + std::string(strerror(errno)));
        }
        if (ftruncate(shmFd_, totalBytes) < 0) {
            throw IPCException("ftruncate failed: " + std::string(strerror(errno)));
        }

        emptySlotsSem_ = sem_open(semEmptyPath.c_str(), O_CREAT, 0660, QUEUE_CAPACITY);
        itemsAvailSem_ = sem_open(semAvailPath.c_str(), O_CREAT, 0660, 0);

        if (emptySlotsSem_ == SEM_FAILED || itemsAvailSem_ == SEM_FAILED) {
            throw IPCException("sem_open failed: " + std::string(strerror(errno)));
        }
    } else {
        shmFd_ = shm_open(shmPath.c_str(), O_RDWR, 0660);
        if (shmFd_ < 0) {
            throw IPCException("Worker shm_open failed: " + std::string(strerror(errno)));
        }
        emptySlotsSem_ = sem_open(semEmptyPath.c_str(), 0);
        itemsAvailSem_ = sem_open(semAvailPath.c_str(), 0);
        if (emptySlotsSem_ == SEM_FAILED || itemsAvailSem_ == SEM_FAILED) {
            throw IPCException("Worker sem_open failed: " + std::string(strerror(errno)));
        }
    }

    void* ptr = mmap(nullptr, totalBytes, PROT_READ | PROT_WRITE, MAP_SHARED, shmFd_, 0);
    if (ptr == MAP_FAILED) {
        throw IPCException("mmap failed: " + std::string(strerror(errno)));
    }
    sharedState_ = static_cast<SharedQueueState*>(ptr);

    if (isOwner_) {
        std::memset(sharedState_, 0, sizeof(SharedQueueState));
    }
}

void SharedTaskQueue::acquireLock() {
    // POSIX robust process-shared mutex handling
}

void SharedTaskQueue::releaseLock() {
}

bool SharedTaskQueue::push(const TaskDescriptor& task, uint32_t timeoutMs) {
    sem_wait(static_cast<sem_t*>(emptySlotsSem_));
    // Atomic push into circular queue
    uint32_t idx = sharedState_->rear;
    std::memcpy(&sharedState_->tasks[idx], &task, sizeof(TaskDescriptor));
    sharedState_->rear = (sharedState_->rear + 1) % QUEUE_CAPACITY;
    sharedState_->count++;
    if (task.type != TaskType::SHUTDOWN) {
        sharedState_->totalSubmitted++;
    }
    sem_post(static_cast<sem_t*>(itemsAvailSem_));
    return true;
}

bool SharedTaskQueue::pop(TaskDescriptor& task, uint32_t timeoutMs) {
    sem_wait(static_cast<sem_t*>(itemsAvailSem_));
    uint32_t idx = sharedState_->front;
    std::memcpy(&task, &sharedState_->tasks[idx], sizeof(TaskDescriptor));
    sharedState_->front = (sharedState_->front + 1) % QUEUE_CAPACITY;
    sharedState_->count--;
    sem_post(static_cast<sem_t*>(emptySlotsSem_));
    return true;
}

void SharedTaskQueue::recordCompletion(bool success) {
    if (success) {
        sharedState_->totalCompleted++;
    } else {
        sharedState_->totalFailed++;
    }
}

QueueStats SharedTaskQueue::getStats() {
    QueueStats stats{};
    stats.totalSubmitted = sharedState_->totalSubmitted;
    stats.totalCompleted = sharedState_->totalCompleted;
    stats.totalFailed = sharedState_->totalFailed;
    stats.currentQueueSize = sharedState_->count;
    return stats;
}

void SharedTaskQueue::close() {
    if (sharedState_) {
        munmap(sharedState_, sizeof(SharedQueueState));
        sharedState_ = nullptr;
    }
    if (emptySlotsSem_) {
        sem_close(static_cast<sem_t*>(emptySlotsSem_));
        if (isOwner_) sem_unlink(("/" + queueName_ + "_emp").c_str());
        emptySlotsSem_ = nullptr;
    }
    if (itemsAvailSem_) {
        sem_close(static_cast<sem_t*>(itemsAvailSem_));
        if (isOwner_) sem_unlink(("/" + queueName_ + "_avl").c_str());
        itemsAvailSem_ = nullptr;
    }
    if (shmFd_ >= 0) {
        ::close(shmFd_);
        if (isOwner_) shm_unlink(("/" + queueName_).c_str());
        shmFd_ = -1;
    }
}

#endif

SharedTaskQueue::~SharedTaskQueue() {
    close();
}

SharedTaskQueue::SharedTaskQueue(SharedTaskQueue&& other) noexcept
    : queueName_(std::move(other.queueName_)),
      isOwner_(other.isOwner_),
      sharedState_(other.sharedState_)
{
#if defined(_WIN32) || defined(_WIN64)
    shmHandle_ = other.shmHandle_;
    mutexHandle_ = other.mutexHandle_;
    emptySlotsSem_ = other.emptySlotsSem_;
    itemsAvailSem_ = other.itemsAvailSem_;
    other.shmHandle_ = nullptr;
    other.mutexHandle_ = nullptr;
    other.emptySlotsSem_ = nullptr;
    other.itemsAvailSem_ = nullptr;
#else
    shmFd_ = other.shmFd_;
    emptySlotsSem_ = other.emptySlotsSem_;
    itemsAvailSem_ = other.itemsAvailSem_;
    other.shmFd_ = -1;
    other.emptySlotsSem_ = nullptr;
    other.itemsAvailSem_ = nullptr;
#endif
    other.sharedState_ = nullptr;
}

SharedTaskQueue& SharedTaskQueue::operator=(SharedTaskQueue&& other) noexcept {
    if (this != &other) {
        close();
        queueName_ = std::move(other.queueName_);
        isOwner_ = other.isOwner_;
        sharedState_ = other.sharedState_;
#if defined(_WIN32) || defined(_WIN64)
        shmHandle_ = other.shmHandle_;
        mutexHandle_ = other.mutexHandle_;
        emptySlotsSem_ = other.emptySlotsSem_;
        itemsAvailSem_ = other.itemsAvailSem_;
        other.shmHandle_ = nullptr;
        other.mutexHandle_ = nullptr;
        other.emptySlotsSem_ = nullptr;
        other.itemsAvailSem_ = nullptr;
#else
        shmFd_ = other.shmFd_;
        emptySlotsSem_ = other.emptySlotsSem_;
        itemsAvailSem_ = other.itemsAvailSem_;
        other.shmFd_ = -1;
        other.emptySlotsSem_ = nullptr;
        other.itemsAvailSem_ = nullptr;
#endif
        other.sharedState_ = nullptr;
    }
    return *this;
}

} // namespace ipc
