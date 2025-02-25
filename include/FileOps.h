#ifndef FILE_OPS_H
#define FILE_OPS_H

#include <string>

namespace Ops {
    // This module wraps basic file and directory operations using the C++17 STL.
    class FileOps {
    public:
        // Writes data (in binary mode) to the specified file.
        static bool writeFile(const std::string &path, const std::string &data);

        // Reads and returns the entire content of the file as a string.
        static std::string readFile(const std::string &path);

        // Creates a directory and all its parent directories (if they don't exist).
        static bool makeDirectory(const std::string &path);

        // Returns true if the specified file exists.
        static bool fileExists(const std::string &path);

        // Returns true if the specified directory exists.
        static bool directoryExists(const std::string &path);
    };
}

#endif
