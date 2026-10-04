#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <cassert>
#include <filesystem>
#include "../src/pool/ProcessPool.hpp"
#include "../src/io/MemoryMappedFile.hpp"

namespace fs = std::filesystem;

void generateBatchFiles(const std::string& directory, size_t fileCount, size_t sizePerFile) {
    fs::create_directories(directory);
    for (size_t i = 0; i < fileCount; ++i) {
        std::string filePath = directory + "/data_file_" + std::to_string(i) + ".bin";
        std::ofstream ofs(filePath, std::ios::binary);
        std::vector<uint8_t> buffer(sizePerFile, static_cast<uint8_t>(i % 256));
        ofs.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    }
}

void testBatchParallelEncryptionDecryption() {
    std::cout << "[TEST 1] Testing Bounded Process Pool: 100 Files Concurrent Batch Encryption..." << std::endl;
    std::string testDir = "test_batch_dataset";
    size_t fileCount = 100;
    size_t fileSize = 256 * 1024; // 256 KB per file -> 25.6 MB total batch
    std::string passphrase = "FAANG_Parallel_Systems_Passphrase_2026!";

    generateBatchFiles(testDir, fileCount, fileSize);

    // 1. Parallel Batch Encryption
    {
        auto startEnc = std::chrono::high_resolution_clock::now();
        pool::ProcessPool pool("test_parallel_enc_queue", 0); // 0 = hardware concurrency
        std::cout << "  -> Initialized bounded pool with " << pool.workerCount() << " worker threads/processes." << std::endl;

        for (size_t i = 0; i < fileCount; ++i) {
            std::string filePath = testDir + "/data_file_" + std::to_string(i) + ".bin";
            bool ok = pool.submitTask(ipc::TaskType::ENCRYPT, filePath, passphrase);
            assert(ok);
        }

        // Graceful shutdown via Poison Pills
        pool.shutdown();
        auto endEnc = std::chrono::high_resolution_clock::now();

        auto stats = pool.getStats();
        assert(stats.totalSubmitted == fileCount);
        assert(stats.totalCompleted == fileCount);
        assert(stats.totalFailed == 0);

        double sec = std::chrono::duration<double>(endEnc - startEnc).count();
        double mbTotal = (fileCount * fileSize) / (1024.0 * 1024.0);
        std::cout << "  -> PASS: Encrypted " << fileCount << " files (" << mbTotal << " MB) in " 
                  << (sec * 1000.0) << " ms (" << (mbTotal / sec) << " MB/s aggregate throughput)." << std::endl;
    }

    // 2. Parallel Batch Decryption
    {
        auto startDec = std::chrono::high_resolution_clock::now();
        pool::ProcessPool pool("test_parallel_dec_queue", 0);

        for (size_t i = 0; i < fileCount; ++i) {
            std::string filePath = testDir + "/data_file_" + std::to_string(i) + ".bin";
            bool ok = pool.submitTask(ipc::TaskType::DECRYPT, filePath, passphrase);
            assert(ok);
        }

        pool.shutdown();
        auto endDec = std::chrono::high_resolution_clock::now();

        auto stats = pool.getStats();
        assert(stats.totalSubmitted == fileCount);
        assert(stats.totalCompleted == fileCount);
        assert(stats.totalFailed == 0);

        double sec = std::chrono::duration<double>(endDec - startDec).count();
        double mbTotal = (fileCount * fileSize) / (1024.0 * 1024.0);
        std::cout << "  -> PASS: Decrypted & Verified " << fileCount << " files in " 
                  << (sec * 1000.0) << " ms (" << (mbTotal / sec) << " MB/s aggregate throughput)." << std::endl;
    }

    // 3. Verify data integrity across all 100 files
    for (size_t i = 0; i < fileCount; ++i) {
        std::string filePath = testDir + "/data_file_" + std::to_string(i) + ".bin";
        assert(fs::file_size(filePath) == fileSize);

        io::MemoryMappedFile mfile;
        mfile.open(filePath, io::OpenMode::ReadOnly);
        uint8_t expectedVal = static_cast<uint8_t>(i % 256);
        for (size_t b = 0; b < fileSize; ++b) {
            assert(mfile.data()[b] == expectedVal);
        }
    }

    fs::remove_all(testDir);
    std::cout << "  -> PASS: All 100 files bit-perfect and verified." << std::endl;
}

int main() {
    std::cout << "=========================================================" << std::endl;
    std::cout << "  Parallel File Encrypter: Concurrency Pool Test Suite   " << std::endl;
    std::cout << "=========================================================" << std::endl;

    testBatchParallelEncryptionDecryption();

    std::cout << "\n>>> ALL PROCESS POOL & CONCURRENCY TESTS PASSED! <<<" << std::endl;
    return 0;
}
