#include "FileOps.h"
#include <fstream>
#include <filesystem>

namespace Ops {

bool FileOps::writeFile(const std::string &path, const std::string &data) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    ofs.write(data.data(), data.size());
    return true;
}

std::string FileOps::readFile(const std::string &path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return "";
    return std::string((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
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

} // namespace Ops