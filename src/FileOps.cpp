#include "FileOps.h"
#include <filesystem>
#include <fstream>
#include <iostream>

namespace Ops {

bool FileOps::writePlain(const std::string& path, const std::string& data) {
    std::ofstream out(path, std::ios::binary);
    if (!out) return false;
    out.write(data.c_str(), data.size());
    return true;
}

std::string FileOps::readPlain(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return "";
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return content;
}

bool FileOps::writeEncrypted(const std::string& path, const std::string& encryptedData) {
    std::ofstream out(path, std::ios::binary);
    if (!out) return false;
    out.write(encryptedData.data(), encryptedData.size());
    return true;
}

std::string FileOps::readRaw(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return "";
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return content;
}

bool FileOps::makeDirectory(const std::string& path) {
    try {
        std::filesystem::create_directories(path);
        return true;
    } catch (...) {
        return false;
    }
}

bool FileOps::fileExists(const std::string& path) {
    return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
}

bool FileOps::directoryExists(const std::string& path) {
    return std::filesystem::exists(path) && std::filesystem::is_directory(path);
}

} // namespace Ops
