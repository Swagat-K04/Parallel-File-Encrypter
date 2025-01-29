#ifndef PROCESS_MANAGEMENT_HPP
#define PROCESS_MANAGEMENT_HPP

#include "Task.hpp"
#include <mutex>
#include <memory>
#include <atomic>
#include <semaphore.h>

class ProcessManagement {

  sem_t* itemsSemaphore;
  sem_t* emptySlotsSemaphore;

  public:
    ProcessManagement();
    ~ProcessManagement();
    bool submitToQueue(unique_ptr<Task> task);
    void executeTasks();

  private:
    struct SharedMemory {
      std::atomic<int> size;
      char tasks[1000][256]; // 1000 files with each max, 256 bytes
      int front;
      int rear;

      void printSharedMemory() {
        std::cout << size << std::endl;
        std::cout << front << std::endl;
        std::cout << rear << std::endl;
      }
    };

    SharedMemory* sharedMem;
    int shmFd;
    const char* SHM_NAME = "/my_queue";
    std::mutex queueLock;
    
};

#endif