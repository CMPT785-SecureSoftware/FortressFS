#ifndef FILE_OPS_H
#define FILE_OPS_H

#include <string>

namespace Ops
{
    // Abstraction for reading, writing, and listing files
    class FileOps {
    public:
        // Writes plain text data to a file (no encryption in this method).
        static bool writePlain(const std::string& path, const std::string& data);

        // Reads plain text data from a file.
        static std::string readPlain(const std::string& path);

        // Writes AES-encrypted data to a file.
        static bool writeEncrypted(const std::string& path, const std::string& encryptedData);

        // Read raw file content (used to get encrypted content).
        static std::string readRaw(const std::string& path);

        // Directory operations
        static bool makeDirectory(const std::string& path);

        // Utility
        static bool fileExists(const std::string& path);
        static bool directoryExists(const std::string& path);
    };
}

#endif
