#ifndef PROCESS_MANAGEMENT_HPP
#define PROCESS_MANAGEMENT_HPP

#include "Task.hpp"
#include <queue>
#include <memory>
#include <atomic>

class ProcessManagement {

  public:
    ProcessManagement();
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
      }
    };

    SharedMemory* sharedMem;
    int shmFd;
    const char* SHM_NAME = "/my_queue";
    
};

#endif