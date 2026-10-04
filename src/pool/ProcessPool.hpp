#ifndef PROCESS_POOL_HPP
#define PROCESS_POOL_HPP

#include <string>
#include <vector>
#include <thread>
#include <memory>
#include <atomic>
#include "../ipc/SharedTaskQueue.hpp"
#include "../io/FileProcessor.hpp"

namespace pool {

class ProcessPool {
public:
    // numWorkers: 0 = std::thread::hardware_concurrency()
    explicit ProcessPool(
        const std::string& queueName = "parallel_encrypter_queue", 
        size_t numWorkers = 0
    );
    ~ProcessPool();

    // Disable copy
    ProcessPool(const ProcessPool&) = delete;
    ProcessPool& operator=(const ProcessPool&) = delete;

    // Submits a single file task to the shared queue
    bool submitTask(ipc::TaskType type, const std::string& filePath, const std::string& passphrase);

    // Enqueues poison pills for all workers, joins worker handles, and reaps processes
    void shutdown();

    // Telemetry and status
    ipc::QueueStats getStats();
    size_t workerCount() const noexcept { return numWorkers_; }

    // Static worker entrypoint executed by worker processes or threads
    static void workerLoop(const std::string& queueName);

private:
    std::string queueName_;
    size_t numWorkers_;
    std::unique_ptr<ipc::SharedTaskQueue> taskQueue_;
    std::vector<std::thread> workerThreads_;
    std::atomic<bool> isShutdown_{false};
    uint64_t nextTaskId_{1};
    ipc::QueueStats cachedStats_{};
};

} // namespace pool

#endif // PROCESS_POOL_HPP
