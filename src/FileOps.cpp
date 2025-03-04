#include "FileOps.h"
#include <fstream>
#include <sstream>
#include <filesystem>

namespace Ops {

    // writeFile: Opens a file in binary mode and writes the provided data.
    bool FileOps::writeFile(const std::string &path, const std::string &data) {
        std::ofstream ofs(path, std::ios::binary);
        if (!ofs) return false;
        ofs.write(data.data(), data.size());
        return ofs.good();
    }

    // readFile: Opens a file in binary mode, reads its entire content, and returns it as a string.
    std::string FileOps::readFile(const std::string &path) {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs) return "";
        std::stringstream buffer;
        buffer << ifs.rdbuf();
        return buffer.str();
    }

    // makeDirectory: Attempts to create the directory (and any required parent directories) using the filesystem API.
    bool FileOps::makeDirectory(const std::string &path) {
        try {
            std::filesystem::create_directories(path);
            return true;
        } catch (...) {
            return false;
        }
    }

    // fileExists: Checks if the given path exists and is a regular file.
    bool FileOps::fileExists(const std::string &path) {
        return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
    }

    // directoryExists: Checks if the given path exists and is a directory.
    bool FileOps::directoryExists(const std::string &path) {
        return std::filesystem::exists(path) && std::filesystem::is_directory(path);
    }

} // namespace Ops