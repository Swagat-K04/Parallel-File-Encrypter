#include "ProcessManagement.hpp"
#include <iostream>
#include <cstring>
#include <sys/wait.h>
#include "../encryptDecrypt/Cryption.hpp"

ProcessManagement::ProcessManagement(){}

bool ProcessManagement::submitToQueue(unique_ptr<Task> task) {
  taskQueue.push(move(task));
  return true;
}

void ProcessManagement::executeTasks() {
  while(!taskQueue.empty()) {
    unique_ptr<Task> taskToExecute = move(taskQueue.front());
    taskQueue.pop();
    cout << "Executing task: " << taskToExecute->toString() << endl;
    executeCryption(taskToExecute->toString());
  }
}