#include <iostream>
#include <filesystem>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <cstring>

#if defined(_WIN32) || defined(_WIN64)
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include "src/crypto/AES256GCM.hpp"
#include "src/io/MemoryMappedFile.hpp"
#include "src/io/FileProcessor.hpp"
#include "src/ipc/SharedTaskQueue.hpp"
#include "src/pool/ProcessPool.hpp"

namespace fs = std::filesystem;

// Secure password prompt without console echo
std::string getHiddenPassphrase(const std::string& prompt) {
    std::cout << prompt;
    std::string passphrase;

#if defined(_WIN32) || defined(_WIN64)
    char ch;
    while ((ch = static_cast<char>(_getch())) != '\r' && ch != '\n') {
        if (ch == '\b') {
            if (!passphrase.empty()) {
                passphrase.pop_back();
                std::cout << "\b \b";
            }
        } else if (ch >= 32 && ch <= 126) {
            passphrase.push_back(ch);
            std::cout << '*';
        }
    }
    std::cout << std::endl;
#else
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, passphrase);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
#endif

    return passphrase;
}

void printBanner() {
    std::cout << R"(
=============================================================================
  PARALLEL FILE ENCRYPTER (v2.0 Production Engine)
  Zero-Copy Memory-Mapped I/O | AES-256-GCM AEAD | Bounded Process Pool IPC
=============================================================================
)" << std::endl;
}

void renderProgressBar(uint64_t completed, uint64_t total, double mbPerSec) {
    const int barWidth = 40;
    float progress = (total == 0) ? 1.0f : static_cast<float>(completed) / static_cast<float>(total);
    int pos = static_cast<int>(barWidth * progress);

    std::cout << "\r[";
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << std::fixed << std::setprecision(1) << (progress * 100.0) << "% "
              << "(" << completed << "/" << total << " files, " 
              << std::setprecision(2) << mbPerSec << " MB/s)" << std::flush;
}

int runBenchmark() {
    std::cout << "\n>>> RUNNING HARDWARE & SYSTEM BENCHMARK <<<\n" << std::endl;
    bool hasAES = crypto::AES256GCM::hasHardwareAESNI();
    std::cout << "[Hardware Detection] CPU AES-NI + PCLMULQDQ: " 
              << (hasAES ? "ENABLED (Hardware Vectorized)" : "DISABLED") << std::endl;
    std::cout << "[Hardware Detection] CPU Hardware Concurrency: " 
              << std::thread::hardware_concurrency() << " logical cores\n" << std::endl;

    const size_t benchSize = 64 * 1024 * 1024; // 64 MB in-memory
    std::vector<uint8_t> plain(benchSize, 0x55);
    std::vector<uint8_t> cipher(benchSize);
    uint8_t tag[16];
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 12> iv{};

    auto start = std::chrono::high_resolution_clock::now();
    crypto::AES256GCM::encrypt(key.data(), iv.data(), plain.data(), benchSize, cipher.data(), tag);
    auto end = std::chrono::high_resolution_clock::now();

    double sec = std::chrono::duration<double>(end - start).count();
    double gbs = (benchSize / (1024.0 * 1024.0 * 1024.0)) / sec;
    double mbs = (benchSize / (1024.0 * 1024.0)) / sec;

    std::cout << "[Memory AES-256-GCM] Throughput: " << std::fixed << std::setprecision(2) 
              << mbs << " MB/s (" << gbs << " GB/s)" << std::endl;

    // Test zero-copy file I/O
    std::string testFile = "tmp_bench_io.dat";
    {
        io::MemoryMappedFile mfile;
        mfile.open(testFile, io::OpenMode::CreateOrResize, 32 * 1024 * 1024);
        std::memset(mfile.data(), 0xAA, mfile.size());
        mfile.sync();
    }
    std::string pass = "BenchPass123";
    auto startIO = std::chrono::high_resolution_clock::now();
    io::FileProcessor::encryptFileInPlace(testFile, pass);
    auto endIO = std::chrono::high_resolution_clock::now();
    double secIO = std::chrono::duration<double>(endIO - startIO).count();
    double mbsIO = (32.0) / secIO;

    std::cout << "[Zero-Copy Disk I/O] Throughput: " << mbsIO << " MB/s" << std::endl;
    fs::remove(testFile);
    std::cout << "\nBenchmark complete.\n" << std::endl;
    return 0;
}

int main(int argc, char* argv[]) {
    printBanner();

    std::string targetDir;
    std::string actionStr;
    std::string passphrase;
    size_t workerCount = 0; // auto-detect

    // Parse command line arguments if provided
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--benchmark" || arg == "-b") {
            return runBenchmark();
        } else if ((arg == "-d" || arg == "--dir") && i + 1 < argc) {
            targetDir = argv[++i];
        } else if ((arg == "-a" || arg == "--action") && i + 1 < argc) {
            actionStr = argv[++i];
        } else if ((arg == "-p" || arg == "--pass") && i + 1 < argc) {
            passphrase = argv[++i];
        } else if ((arg == "-w" || arg == "--workers") && i + 1 < argc) {
            workerCount = static_cast<size_t>(std::stoul(argv[++i]));
        }
    }

    // Interactive CLI prompts if not supplied via arguments
    if (targetDir.empty()) {
        std::cout << "Enter target directory path: ";
        std::getline(std::cin, targetDir);
    }

    if (!fs::exists(targetDir) || !fs::is_directory(targetDir)) {
        std::cerr << "[Error] Target directory does not exist: " << targetDir << std::endl;
        return 1;
    }

    if (actionStr.empty()) {
        std::cout << "Select action [E]ncrypt / [D]ecrypt: ";
        std::getline(std::cin, actionStr);
    }

    std::transform(actionStr.begin(), actionStr.end(), actionStr.begin(), ::toupper);
    bool isEncrypt = (actionStr == "E" || actionStr == "ENCRYPT");
    bool isDecrypt = (actionStr == "D" || actionStr == "DECRYPT");

    if (!isEncrypt && !isDecrypt) {
        std::cerr << "[Error] Invalid action selected. Please choose ENCRYPT or DECRYPT." << std::endl;
        return 1;
    }

    if (passphrase.empty()) {
        passphrase = getHiddenPassphrase("Enter secret encryption passphrase: ");
        if (passphrase.empty()) {
            std::cerr << "[Error] Passphrase cannot be empty." << std::endl;
            return 1;
        }
    }

    // 1. Recursive Directory Discovery
    std::cout << "\n[1/3] Scanning directory tree: " << targetDir << "..." << std::endl;
    std::vector<std::string> fileList;
    uintmax_t totalBytes = 0;

    for (const auto& entry : fs::recursive_directory_iterator(targetDir)) {
        if (entry.is_regular_file()) {
            fileList.push_back(entry.path().string());
            totalBytes += entry.file_size();
        }
    }

    if (fileList.empty()) {
        std::cout << "[Notice] No regular files found in target directory." << std::endl;
        return 0;
    }

    double totalMB = static_cast<double>(totalBytes) / (1024.0 * 1024.0);
    std::cout << "  -> Discovered " << fileList.size() << " files (" 
              << std::fixed << std::setprecision(2) << totalMB << " MB total).\n" << std::endl;

    // 2. Initialize Bounded Worker Pool & Process-Shared IPC
    std::cout << "[2/3] Initializing bounded worker pool and process-shared IPC queue..." << std::endl;
    pool::ProcessPool processPool("pfe_shared_queue", workerCount);
    std::cout << "  -> Active Worker Threads/Processes: " << processPool.workerCount() << std::endl;

    ipc::TaskType taskType = isEncrypt ? ipc::TaskType::ENCRYPT : ipc::TaskType::DECRYPT;

    // 3. Dispatch Tasks to Shared Queue
    std::cout << "\n[3/3] Executing parallel " << (isEncrypt ? "encryption" : "decryption") << " pipeline..." << std::endl;
    auto startTime = std::chrono::high_resolution_clock::now();

    for (const auto& file : fileList) {
        processPool.submitTask(taskType, file, passphrase);
    }

    // Dynamic Progress Monitor
    while (true) {
        auto stats = processPool.getStats();
        auto now = std::chrono::high_resolution_clock::now();
        double elapsedSec = std::chrono::duration<double>(now - startTime).count();
        double currentMBs = (elapsedSec > 0) ? (totalMB * (static_cast<double>(stats.totalCompleted) / fileList.size())) / elapsedSec : 0.0;

        renderProgressBar(stats.totalCompleted, fileList.size(), currentMBs);

        if (stats.totalCompleted + stats.totalFailed >= fileList.size()) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    processPool.shutdown();
    auto endTime = std::chrono::high_resolution_clock::now();

    renderProgressBar(fileList.size(), fileList.size(), 0.0);
    std::cout << std::endl;

    double totalSec = std::chrono::duration<double>(endTime - startTime).count();
    double aggregateThroughput = (totalSec > 0) ? (totalMB / totalSec) : 0.0;
    auto finalStats = processPool.getStats();

    std::cout << R"(
=============================================================================
  EXECUTION SUMMARY & PERFORMANCE REPORT
=============================================================================
)" << std::endl;
    std::cout << "  - Operation:            " << (isEncrypt ? "AES-256-GCM Encryption" : "AES-256-GCM Decryption & Verification") << std::endl;
    std::cout << "  - Files Processed:      " << finalStats.totalCompleted << " / " << fileList.size() << " files" << std::endl;
    std::cout << "  - Failures / Tampered:  " << finalStats.totalFailed << std::endl;
    std::cout << "  - Total Data Volume:    " << std::fixed << std::setprecision(2) << totalMB << " MB" << std::endl;
    std::cout << "  - Total Duration:       " << std::setprecision(3) << (totalSec * 1000.0) << " ms (" << totalSec << " s)" << std::endl;
    std::cout << "  - Aggregate Throughput: " << std::setprecision(2) << aggregateThroughput << " MB/s (" 
              << (aggregateThroughput / 1024.0) << " GB/s)" << std::endl;
    std::cout << "  - Worker Pool:          " << processPool.workerCount() << " parallel cores" << std::endl;
    std::cout << "=============================================================================\n" << std::endl;

    return (finalStats.totalFailed == 0) ? 0 : 1;
}
