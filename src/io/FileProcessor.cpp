#include "FileProcessor.hpp"
#include <filesystem>
#include <cstring>
#include <iostream>

namespace fs = std::filesystem;

namespace io {

crypto::EncryptedContainerHeader FileProcessor::readContainerHeader(const std::string& filePath) {
    if (!fs::exists(filePath)) {
        throw crypto::CryptoException("File does not exist: " + filePath);
    }
    uintmax_t fileSize = fs::file_size(filePath);
    if (fileSize < sizeof(crypto::EncryptedContainerHeader)) {
        throw crypto::CryptoException("File too small to be a valid encrypted container: " + filePath);
    }

    MemoryMappedFile mappedFile;
    mappedFile.open(filePath, OpenMode::ReadOnly);
    if (!mappedFile.isMapped() || mappedFile.size() < sizeof(crypto::EncryptedContainerHeader)) {
        throw crypto::CryptoException("Failed to read header from mapped file: " + filePath);
    }

    crypto::EncryptedContainerHeader header;
    std::memcpy(&header, mappedFile.data(), sizeof(crypto::EncryptedContainerHeader));

    if (header.magic != crypto::MAGIC_HEADER) {
        throw crypto::CryptoException("Invalid container magic header in file: " + filePath);
    }
    return header;
}

void FileProcessor::encryptFile(
    const std::string& inputPath, 
    const std::string& outputPath, 
    std::string_view passphrase
) {
    if (!fs::exists(inputPath)) {
        throw crypto::CryptoException("Input file does not exist: " + inputPath);
    }

    uintmax_t inFileSize = fs::file_size(inputPath);
    size_t headerSize = sizeof(crypto::EncryptedContainerHeader);
    size_t outFileSize = headerSize + static_cast<size_t>(inFileSize);

    // 1. Generate Salt and derive 256-bit Key
    std::array<uint8_t, crypto::SALT_SIZE> salt{};
    crypto::AES256GCM::generateRandomBytes(salt.data(), salt.size());
    auto key = crypto::AES256GCM::deriveKey(passphrase, salt, 100000);

    // 2. Generate random 96-bit Nonce/IV
    std::array<uint8_t, crypto::IV_SIZE> iv{};
    crypto::AES256GCM::generateRandomBytes(iv.data(), iv.size());

    // 3. Open Input file with Memory Mapping
    MemoryMappedFile inMapped;
    if (inFileSize > 0) {
        inMapped.open(inputPath, OpenMode::ReadOnly);
        inMapped.advise(AccessAdvice::Sequential);
    }

    // 4. Open Output file with Memory Mapping (Pre-allocated size)
    MemoryMappedFile outMapped;
    outMapped.open(outputPath, OpenMode::CreateOrResize, outFileSize);
    outMapped.advise(AccessAdvice::Sequential);

    // 5. Zero-Copy Encrypt payload directly into output mapped memory
    uint8_t tag[crypto::TAG_SIZE] = {0};
    uint8_t* outPayloadPtr = outMapped.data() + headerSize;

    if (inFileSize > 0) {
        crypto::AES256GCM::encrypt(
            key.data(),
            iv.data(),
            inMapped.data(),
            inMapped.size(),
            outPayloadPtr,
            tag
        );
    } else {
        // Zero-byte file encryption
        crypto::AES256GCM::encrypt(
            key.data(),
            iv.data(),
            nullptr,
            0,
            outPayloadPtr,
            tag
        );
    }

    // 6. Populate and write Container Header
    crypto::EncryptedContainerHeader header{};
    header.magic = crypto::MAGIC_HEADER;
    std::memcpy(header.salt, salt.data(), crypto::SALT_SIZE);
    std::memcpy(header.iv, iv.data(), crypto::IV_SIZE);
    std::memcpy(header.tag, tag, crypto::TAG_SIZE);
    header.plaintext_size = inFileSize;

    std::memcpy(outMapped.data(), &header, sizeof(header));

    // 7. Sync memory pages to storage controller
    outMapped.sync();
}

void FileProcessor::decryptFile(
    const std::string& inputPath, 
    const std::string& outputPath, 
    std::string_view passphrase
) {
    if (!fs::exists(inputPath)) {
        throw crypto::CryptoException("Input file does not exist: " + inputPath);
    }

    uintmax_t inFileSize = fs::file_size(inputPath);
    size_t headerSize = sizeof(crypto::EncryptedContainerHeader);
    if (inFileSize < headerSize) {
        throw crypto::CryptoException("File too small to be a valid encrypted container: " + inputPath);
    }

    // 1. Open Encrypted Container via Memory Mapping
    MemoryMappedFile inMapped;
    inMapped.open(inputPath, OpenMode::ReadOnly);
    inMapped.advise(AccessAdvice::Sequential);

    crypto::EncryptedContainerHeader header;
    std::memcpy(&header, inMapped.data(), sizeof(header));

    if (header.magic != crypto::MAGIC_HEADER) {
        throw crypto::CryptoException("Invalid file magic: Not a recognized encrypted container.");
    }

    size_t ciphertextSize = inMapped.size() - headerSize;
    if (ciphertextSize != header.plaintext_size) {
        throw crypto::CryptoException("Container length mismatch against recorded plaintext size.");
    }

    // 2. Derive Key from Passphrase + Salt from Header
    std::array<uint8_t, crypto::SALT_SIZE> salt{};
    std::memcpy(salt.data(), header.salt, crypto::SALT_SIZE);
    auto key = crypto::AES256GCM::deriveKey(passphrase, salt, 100000);

    // 3. Open Output file via Memory Mapping
    MemoryMappedFile outMapped;
    if (header.plaintext_size > 0) {
        outMapped.open(outputPath, OpenMode::CreateOrResize, header.plaintext_size);
        outMapped.advise(AccessAdvice::Sequential);
    } else {
        // Create an empty file
        outMapped.open(outputPath, OpenMode::CreateOrResize, 0);
    }

    // 4. Decrypt and Verify AEAD Authentication Tag
    const uint8_t* inPayloadPtr = inMapped.data() + headerSize;
    try {
        if (header.plaintext_size > 0) {
            crypto::AES256GCM::decrypt(
                key.data(),
                header.iv,
                inPayloadPtr,
                ciphertextSize,
                header.tag,
                outMapped.data()
            );
            outMapped.sync();
        } else {
            // Verify empty payload tag
            crypto::AES256GCM::decrypt(
                key.data(),
                header.iv,
                nullptr,
                0,
                header.tag,
                nullptr
            );
        }
    } catch (...) {
        outMapped.close();
        if (fs::exists(outputPath)) {
            fs::remove(outputPath);
        }
        throw; // Re-throw authentication or crypto exception
    }
}

void FileProcessor::encryptFileInPlace(const std::string& filePath, std::string_view passphrase) {
    std::string tmpPath = filePath + ".tmp_enc";
    try {
        encryptFile(filePath, tmpPath, passphrase);
        fs::rename(tmpPath, filePath);
    } catch (...) {
        if (fs::exists(tmpPath)) {
            fs::remove(tmpPath);
        }
        throw;
    }
}

void FileProcessor::decryptFileInPlace(const std::string& filePath, std::string_view passphrase) {
    std::string tmpPath = filePath + ".tmp_dec";
    try {
        decryptFile(filePath, tmpPath, passphrase);
        fs::rename(tmpPath, filePath);
    } catch (...) {
        if (fs::exists(tmpPath)) {
            fs::remove(tmpPath);
        }
        throw;
    }
}

} // namespace io
