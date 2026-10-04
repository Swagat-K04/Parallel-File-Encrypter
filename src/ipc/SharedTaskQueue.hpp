#ifndef SHARED_TASK_QUEUE_HPP
#define SHARED_TASK_QUEUE_HPP

#include <string>
#include <string_view>
#include <cstdint>
#include <cstddef>
#include <atomic>
#include <stdexcept>

namespace ipc {

constexpr size_t MAX_PATH_LEN = 4096; // Full POSIX PATH_MAX support
constexpr size_t MAX_PASS_LEN = 256;
constexpr size_t QUEUE_CAPACITY = 256;

enum class TaskType : uint32_t {
    ENCRYPT = 1,
    DECRYPT = 2,
    SHUTDOWN = 3 // Poison Pill Sentinel
};

#pragma pack(push, 1)
struct TaskDescriptor {
    TaskType type;
    uint64_t taskId;
    char filePath[MAX_PATH_LEN];
    char passphrase[MAX_PASS_LEN];
};

struct QueueStats {
    uint64_t totalSubmitted;
    uint64_t totalCompleted;
    uint64_t totalFailed;
    uint32_t currentQueueSize;
};

struct alignas(64) SharedQueueState {
    uint32_t front;
    uint32_t rear;
    uint32_t count;
    uint64_t totalSubmitted;
    uint64_t totalCompleted;
    uint64_t totalFailed;
    bool isShutdown;

    TaskDescriptor tasks[QUEUE_CAPACITY];
};
#pragma pack(pop)

class IPCException : public std::runtime_error {
public:
    explicit IPCException(const std::string& msg) : std::runtime_error(msg) {}
};

class SharedTaskQueue {
public:
    // isOwner: True for Producer/Supervisor (creates shm & semaphores), False for Worker (attaches)
    SharedTaskQueue(const std::string& queueName, bool isOwner);
    ~SharedTaskQueue();

    // Disable copy, allow move
    SharedTaskQueue(const SharedTaskQueue&) = delete;
    SharedTaskQueue& operator=(const SharedTaskQueue&) = delete;
    SharedTaskQueue(SharedTaskQueue&& other) noexcept;
    SharedTaskQueue& operator=(SharedTaskQueue&& other) noexcept;

    // Enqueue task into process-shared ring buffer (blocks if full)
    bool push(const TaskDescriptor& task, uint32_t timeoutMs = 0);

    // Dequeue task from process-shared ring buffer (blocks if empty)
    bool pop(TaskDescriptor& task, uint32_t timeoutMs = 0);

    // Atomic telemetry updates across processes
    void recordCompletion(bool success);

    // Reads queue telemetry
    QueueStats getStats();

    // Closes and unlinks shared memory segments and semaphores
    void close();

    const std::string& name() const noexcept { return queueName_; }
    bool isOwner() const noexcept { return isOwner_; }

private:
    std::string queueName_;
    bool isOwner_ = false;
    SharedQueueState* sharedState_ = nullptr;

#if defined(_WIN32) || defined(_WIN64)
    void* shmHandle_ = nullptr;
    void* mutexHandle_ = nullptr;
    void* emptySlotsSem_ = nullptr;
    void* itemsAvailSem_ = nullptr;
#else
    int shmFd_ = -1;
    void* emptySlotsSem_ = nullptr;
    void* itemsAvailSem_ = nullptr;
    void* psharedMutex_ = nullptr; // pthread_mutex_t in shared memory
#endif

    void initSyncPrimitives();
    void acquireLock();
    void releaseLock();
};

} // namespace ipc

#endif // SHARED_TASK_QUEUE_HPP
