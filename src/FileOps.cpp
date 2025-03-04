#include "FileOps.h"
#include <fstream>
#include <sstream>
#include <filesystem>

namespace Ops {

bool FileOps::writeFile(const std::string &path, const std::string &data) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    ofs.write(data.data(), data.size());
    return ofs.good();
}

std::string FileOps::readFile(const std::string &path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return "";
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    return buffer.str();
}

bool FileOps::makeDirectory(const std::string &path) {
    try {
        std::filesystem::create_directories(path);
        return true;
    } catch (...) {
        return false;
    }
}

bool FileOps::fileExists(const std::string &path) {
    return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
}

bool FileOps::directoryExists(const std::string &path) {
    return std::filesystem::exists(path) && std::filesystem::is_directory(path);
}

/**
 * appendErrorLog:
 * Appends 'message' to error.log
 */
void FileOps::appendErrorLog(const std::string &message) {
    std::ofstream ofs("error.log", std::ios::app);
    if (ofs) {
        ofs << message << "\n";
    }
}

} // namespace Ops