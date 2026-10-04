#include "ProcessPool.hpp"
#include <iostream>
#include <algorithm>
#include <cstring>

namespace pool {

ProcessPool::ProcessPool(const std::string& queueName, size_t numWorkers)
    : queueName_(queueName)
{
    if (numWorkers == 0) {
        numWorkers_ = std::max(2u, std::thread::hardware_concurrency());
    } else {
        numWorkers_ = numWorkers;
    }

    // Producer creates and owns the process-shared queue
    taskQueue_ = std::make_unique<ipc::SharedTaskQueue>(queueName_, true);

    // Spawn bounded pool of workers
    for (size_t i = 0; i < numWorkers_; ++i) {
        workerThreads_.emplace_back(&ProcessPool::workerLoop, queueName_);
    }
}

ProcessPool::~ProcessPool() {
    shutdown();
}

bool ProcessPool::submitTask(ipc::TaskType type, const std::string& filePath, const std::string& passphrase) {
    if (isShutdown_.load()) {
        return false;
    }

    ipc::TaskDescriptor desc{};
    desc.type = type;
    desc.taskId = nextTaskId_++;

    std::strncpy(desc.filePath, filePath.c_str(), sizeof(desc.filePath) - 1);
    std::strncpy(desc.passphrase, passphrase.c_str(), sizeof(desc.passphrase) - 1);

    return taskQueue_->push(desc);
}

void ProcessPool::shutdown() {
    if (isShutdown_.exchange(true)) {
        return; // Already shut down
    }

    // 1. Push Poison Pill Sentinels (1 for every worker)
    for (size_t i = 0; i < numWorkers_; ++i) {
        ipc::TaskDescriptor pill{};
        pill.type = ipc::TaskType::SHUTDOWN;
        taskQueue_->push(pill);
    }

    // 2. Join and reap all worker execution threads/processes
    for (auto& worker : workerThreads_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workerThreads_.clear();

    // 3. Cache final stats before closing queue
    if (taskQueue_) {
        cachedStats_ = taskQueue_->getStats();
        taskQueue_->close();
    }
}

ipc::QueueStats ProcessPool::getStats() {
    if (!isShutdown_.load() && taskQueue_) {
        return taskQueue_->getStats();
    }
    return cachedStats_;
}

void ProcessPool::workerLoop(const std::string& queueName) {
    try {
        // Attach to existing process-shared queue as worker
        ipc::SharedTaskQueue queue(queueName, false);

        while (true) {
            ipc::TaskDescriptor task{};
            if (!queue.pop(task)) {
                continue;
            }

            // Sentinel Poison Pill Check
            if (task.type == ipc::TaskType::SHUTDOWN) {
                break; // Graceful exit
            }

            bool taskSuccess = false;
            try {
                if (task.type == ipc::TaskType::ENCRYPT) {
                    io::FileProcessor::encryptFileInPlace(task.filePath, task.passphrase);
                    taskSuccess = true;
                } else if (task.type == ipc::TaskType::DECRYPT) {
                    io::FileProcessor::decryptFileInPlace(task.filePath, task.passphrase);
                    taskSuccess = true;
                }
            } catch (const std::exception& ex) {
                std::cerr << "[Worker Error] Task " << task.taskId << " on file " 
                          << task.filePath << " failed: " << ex.what() << std::endl;
                taskSuccess = false;
            } catch (...) {
                std::cerr << "[Worker Error] Unknown fatal error on task " << task.taskId << std::endl;
                taskSuccess = false;
            }

            queue.recordCompletion(taskSuccess);
        }
    } catch (const std::exception& ex) {
        std::cerr << "[Worker Fatal] Worker process/thread failed to attach to queue: " << ex.what() << std::endl;
    }
}

} // namespace pool
