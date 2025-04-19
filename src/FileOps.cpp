#include "FileOps.h"
#include "SecurityOps.h"
#include "UserOps.h"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

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
void FileOps::appendErrorLog(const std::string &message, const UOps::User &user) {
    // decrypt the error.log file using the user's global mapping key in user_file_mapping.json
    // Get the global mapping key from the user_file_mapping.json
    json userFileMapping = loadUserFileMappingPublic(user.username, user.privateKey);
    if (userFileMapping.empty() || !userFileMapping.contains("global_mapping_key")) {
        if (user.username == "admin") {
            std::cerr << "[Debug] appendErrorLog: global_mapping_key not found in user_file_mapping.json for " + user.username;
        }
        else {
            std::cerr << "[Debug] Please contact the admin to resolve this issue.\n";
        }
        return;
    }
    std::string globalMappingKey = userFileMapping["global_mapping_key"];
    auto keyBytes = hexToBytes(globalMappingKey);
    std::string keyStr(reinterpret_cast<char*>(keyBytes.data()), keyBytes.size());

    // Read the error.log file if it exists
    // hash the name of error.log
    std::string errorLogFileName = SecOps::SecurityOps::sha256("error.log");
    std::string errorLogPath = "filesystem/" + errorLogFileName;
    std::string encData = readFile(errorLogPath);
    // create empty decData
    std::string decData;
    if (!encData.empty()) {
        try {
            // Decrypt the error.log file using the global mapping key.
            decData = SecOps::SecurityOps::aesDecrypt(encData, keyStr);
        } catch (...) {
            if (user.username == "admin") {
                std::cerr << "[Debug] appendErrorLog: global_mapping_key not found in user_file_mapping.json for " + user.username;
            }
            else {
                std::cerr << "[Debug] Please contact the admin to resolve this issue.\n";
            }
            return;
        }
    }
    // Append the new message to the decrypted data
    decData += message + "\n";
    // Encrypt the updated data using the global mapping key
    std::string enc;
    try {
        enc = SecOps::SecurityOps::aesEncrypt(decData, keyStr);
    } catch (...) {
        if (user.username == "admin") {
            std::cerr << "[Debug] appendErrorLog: global_mapping_key not found in user_file_mapping.json for " + user.username;
        }
        else {
            std::cerr << "[Debug] Please contact the admin to resolve this issue.\n";
        }
        return;
    }
    // Write the encrypted data back to the error.log file
    if (!writeFile(errorLogPath, enc)) {
        if (user.username == "admin") {
            std::cerr << "[Debug] appendErrorLog: global_mapping_key not found in user_file_mapping.json for " + user.username;
        }
        else {
            std::cerr << "[Debug] Please contact the admin to resolve this issue.\n";
        }
        return;
    }
}

} // namespace Ops