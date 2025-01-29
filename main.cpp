#include <iostream>
#include <filesystem>
#include <algorithm>
#include "./src/app/processes/ProcessManagement.hpp"
#include "./src/app/processes/Task.hpp"

using namespace std;
namespace fs = std::filesystem;

string toUpper(const string & str) {
  string upperStr = str;
  transform(upperStr.begin(), upperStr.end(), upperStr.begin(), ::toupper);
  return upperStr;
}

int main(int argc, char *argv[]) {
  string directory;
  string action;
  
  cout << "Enter the directory path: " << endl;
  getline(cin, directory);

  cout << "Enter the action (encrypt/decrypt):" << endl;
  getline(cin, action);

  action = toUpper(action);

  try {
    if(fs::exists(directory) && fs::is_directory(directory)) {
      ProcessManagement processManagement;
      for(const auto &entry : fs::recursive_directory_iterator(directory)) {
        if(entry.is_regular_file()) {
          string filePath = entry.path().string();
          IO io(filePath);
          fstream f_stream = move(io.getFileStream());

          if(f_stream.is_open()) {
            Action taskAction = (action == "ENCRYPT" ? Action::ENCRYPT : Action::DECRYPT);
            auto task = make_unique<Task>(move(f_stream), taskAction, filePath);
            processManagement.submitToQueue(move(task));
          }
          else {
            cout << "Unable to open the file: " << filePath << endl;
          }
        }
      }
      processManagement.executeTasks();
    }
    else {
      cout << "Invalid directory path: " << endl;
    }
  }
  catch(const fs::filesystem_error &ex) {
    cout << "Filesystem error: " << ex.what() << endl;
  }
}
