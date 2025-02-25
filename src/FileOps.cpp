#include "FileOps.h"
#include <fstream>
#include <filesystem>

namespace Ops {

bool FileOps::writeFile(const std::string &path, const std::string &data) {
    // Open the file in binary mode for writing.
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs)
        return false;
    ofs.write(data.data(), data.size());
    return true;
}

std::string FileOps::readFile(const std::string &path) {
    // Open the file in binary mode for reading.
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs)
        return "";
    // Read the entire file into a string.
    return std::string((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
}

bool FileOps::makeDirectory(const std::string &path) {
    try {
        // Uses C++17 filesystem to create directories recursively.
        std::filesystem::create_directories(path);
        return true;
    } catch (...) {
        return false;
    }
}

bool FileOps::fileExists(const std::string &path) {
    // Check if the path exists and is a regular file.
    return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
}

bool FileOps::directoryExists(const std::string &path) {
    // Check if the path exists and is a directory.
    return std::filesystem::exists(path) && std::filesystem::is_directory(path);
}

} // namespace Ops