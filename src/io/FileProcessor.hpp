#ifndef FILE_PROCESSOR_HPP
#define FILE_PROCESSOR_HPP

#include <string>
#include <string_view>
#include <cstdint>
#include <cstddef>
#include "../crypto/AES256GCM.hpp"
#include "MemoryMappedFile.hpp"

namespace io {

class FileProcessor {
public:
    // Encrypts an input file to a target output path using zero-copy memory-mapping and AES-256-GCM
    static void encryptFile(
        const std::string& inputPath, 
        const std::string& outputPath, 
        std::string_view passphrase
    );

    // Decrypts an encrypted container file and validates AEAD authentication tag
    static void decryptFile(
        const std::string& inputPath, 
        const std::string& outputPath, 
        std::string_view passphrase
    );

    // In-place atomic encryption (safely handles interruptions via atomic rename)
    static void encryptFileInPlace(
        const std::string& filePath, 
        std::string_view passphrase
    );

    // In-place atomic decryption (safely handles interruptions and authentication failures)
    static void decryptFileInPlace(
        const std::string& filePath, 
        std::string_view passphrase
    );

    // Inspects container metadata without decrypting payload
    static crypto::EncryptedContainerHeader readContainerHeader(const std::string& filePath);
};

} // namespace io

#endif // FILE_PROCESSOR_HPP
