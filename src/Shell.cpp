#include "Shell.h"
#include "FileOps.h"
#include "UserOps.h"
#include "SecurityOps.h"
#include <iostream>
#include <sstream>
#include <filesystem>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace {
    // Global mapping file for shared folder and base directories.
    static const std::string GLOBAL_MAPPING_FILE = "global_mapping.json";

    json loadGlobalMapping() {
        std::ifstream ifs(GLOBAL_MAPPING_FILE);
        if (!ifs) return json::object();
        json j;
        ifs >> j;
        return j;
    }
    bool saveGlobalMapping(const json &j) {
        std::ofstream ofs(GLOBAL_MAPPING_FILE);
        ofs << j.dump(4);
        return ofs.good();
    }

    // For per-user mapping stored in user_file_mapping.json.
    json loadUserFileMapping(const std::string &userRootPath, const std::string &privateKey) {
        std::string mappingPath = userRootPath + "/user_file_mapping.json";
        if (!std::filesystem::exists(mappingPath))
            return json::object();
        std::string encrypted = Ops::FileOps::readFile(mappingPath);
        std::string decrypted;
        try {
            decrypted = SecOps::SecurityOps::rsaDecrypt(encrypted, privateKey);
        } catch (...) {
            return json::object();
        }
        return json::parse(decrypted);
    }
    bool saveUserFileMapping(const std::string &userRootPath, const json &j, const std::string &publicKey) {
        std::string mappingPath = userRootPath + "/user_file_mapping.json";
        std::string plain = j.dump(4);
        std::string encrypted = SecOps::SecurityOps::rsaEncrypt(plain, publicKey);
        return Ops::FileOps::writeFile(mappingPath, encrypted);
    }
}


namespace Shell {

// Define the filesystem folder constant.
static const std::string FILESYSTEM_DIR = "filesystem";

// resolvePath converts a virtual path (using plaintext names) to the actual on-disk path (using hashes).
// For personal folders, look in the user's own root; for shared, use the global mapping.
std::string InteractiveShell::resolvePath(const std::string &vpath) {
    // If vpath starts with "/shared", then the path is in the shared folder.
    if (vpath.find("/shared") == 0) {
        // Global mapping for the current user.
        json global = loadGlobalMapping();
        std::string sharedHash = global[currentUser]["shared"];
        std::string base = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(currentUser) + "/" + sharedHash;
        // Append any subpaths.
        std::istringstream iss(vpath);
        std::string token;
        std::string hashedPath = base;
        // Skip the first token ("shared")
        std::getline(iss, token, '/');
        while (std::getline(iss, token, '/')) {
            if (token.empty() || token == ".") continue;
            if (token == "..") {
                size_t pos = path.find_last_of('/');
                if (pos != std::string::npos)
                    hashedPath = hashedPath.substr(0, pos);
            } else {
                hashedPath += "/" + SecOps::SecurityOps::sha256(token);
            }
        }
        return hashedPath;
    } else {
        // Base directory is FILESYSTEM_DIR/<hash(currentUser)>
        std::string base = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(currentUser);
        if (vpath == "/" || vpath.empty())
            return base;
        std::istringstream iss(vpath);
        std::string token;
        std::string hashedPath = base;
        while (std::getline(iss, token, '/')) {
            if (token.empty() || token == ".")
                continue;
            if (token == "..") {
                size_t pos = hashedPath.find_last_of('/');
                if (pos != std::string::npos)
                    hashedPath = hashedPath.substr(0, pos);
                continue;
            }
            // For each component, convert to its hash.
            hashedPath += "/" + SecOps::SecurityOps::sha256(token);
        }
        return hashedPath;
    }
}

// normalizePath() processes a path to handle "." and "..".
std::string InteractiveShell::normalizePath(const std::string &path) {
    std::vector<std::string> parts;
    std::istringstream iss(path);
    std::string token;
    while (std::getline(iss, token, '/')) {
        if (token.empty() || token == ".")
            continue;
        if (token == "..") {
            if (!parts.empty())
                parts.pop_back();
        } else {
            parts.push_back(token);
        }
    }
    std::string result = "/";
    for (size_t i = 0; i < parts.size(); i++) {
        result += parts[i];
        if (i + 1 < parts.size())
            result += "/";
    }
    return result;
}

// Constructor: ensures the user’s base folder (and fixed subfolders "personal" and "shared")
// are created using hashed names. Also updates the name mapping.
InteractiveShell::InteractiveShell(const std::string &username)
    : currentUser(username), currentDir("/") {
    std::string userDir = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(currentUser);
    std::string personalDir = userDir + "/" + SecOps::SecurityOps::sha256("personal");
    std::string sharedDir = userDir + "/" + SecOps::SecurityOps::sha256("shared");
    if (!Ops::FileOps::directoryExists(userDir)) {
        Ops::FileOps::makeDirectory(userDir);
        Ops::FileOps::makeDirectory(personalDir);
        Ops::FileOps::makeDirectory(sharedDir);
        json personalMapping;
        personalMapping["username"] = currentUser;
        personalMapping["files"] = json::object();
        // Get user's public key.
        std::string pubFilePath = "public_keys/" + currentUser + "_public.pem";
        std::ifstream pubFile(pubFilePath);
        std::stringstream pubSS;
        pubSS << pubFile.rdbuf();
        std::string userPub = pubSS.str();
        std::string mappingStr = personalMapping.dump(4);
        std::string encryptedMapping = SecOps::SecurityOps::rsaEncrypt(mappingStr, userPub);
        Ops::FileOps::writeFile(userDir + "/user_file_mapping.json", encryptedMapping);
    }
}

void InteractiveShell::handle_cd(const std::string &arg) {
    if (arg.empty())
        return;
    std::string newPath;
    if (arg[0] == '/')
        newPath = normalizePath(arg);
    else
        newPath = normalizePath(currentDir + "/" + arg);
    std::string realPath = resolvePath(newPath);
    if (Ops::FileOps::directoryExists(realPath))
        currentDir = newPath;
}

void InteractiveShell::handle_pwd() {
    std::cout << currentDir << "\n";
}

void InteractiveShell::handle_ls() {
    std::string realDir = resolvePath(currentDir);
    if (!Ops::FileOps::directoryExists(realDir)) {
        std::cout << "Directory does not exist.\n";
        return;
    }
    std::cout << "d -> .\n";
    std::cout << "d -> ..\n";
    for (const auto &entry : std::filesystem::directory_iterator(realDir)) {
        // For shared folder, look up in global mapping.
        std::string hashedName = entry.path().filename().string();
        std::string displayName = hashedName;
        if (currentDir.find("/shared") == 0) {
            json global = loadGlobalMapping();
            if (global.contains(currentUser) && global[currentUser].contains("shared_files")) {
                if (global[currentUser]["shared_files"].contains(hashedName))
                    displayName = global[currentUser]["shared_files"][hashedName];
            }
        } else {
            // For personal folder, load the decrypted per-user mapping.
            std::string userRoot = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(currentUser);
            // Use the user's private key from in-memory User record.
            std::string privateKey = UOps::UserOps::getUser(currentUser).privateKey;
            json personal = loadUserFileMapping(userRoot, privateKey);
            if (personal.contains("files") && personal["files"].contains(hashedName))
                displayName = personal["files"][hashedName];
        }
        if (entry.is_directory())
            std::cout << "d -> " << displayName << "\n";
        else
            std::cout << "f -> " << displayName << "\n";
    }
}


void InteractiveShell::handle_cat(const std::string &filename) {
    if (filename.empty())
        return;
    std::string realFile = resolvePath(filename);
    if (!Ops::FileOps::fileExists(realFile)) {
        std::cout << filename << " doesn't exist\n";
        return;
    }
    // Derive an AES key from the user's private key (naively: first 32 characters).
    std::string userKey = UOps::UserOps::getUser(currentUser).privateKey;
    std::string aesKey = userKey.substr(0, 32);
    std::string encContent = Ops::FileOps::readFile(realFile);
    try {
        std::string plain = SecOps::SecurityOps::aesDecrypt(encContent, aesKey);
        std::cout << plain << "\n";
    } catch (std::exception &e) {
        std::cout << "Error decrypting file: " << e.what() << "\n";
    }
}

void InteractiveShell::handle_share(const std::string &args) {
    // Format: share <filename> <targetUser>
    std::istringstream iss(args);
    std::string filename, targetUser;
    iss >> filename >> targetUser;
    if (filename.empty() || targetUser.empty()) {
        std::cout << "Usage: share <filename> <targetUser>\n";
        return;
    }
    std::string sourceFile = resolvePath(filename);
    if (!Ops::FileOps::fileExists(sourceFile)) {
        std::cout << "File " << filename << " doesn't exist\n";
        return;
    }
    if (!UOps::UserOps::users.count(targetUser)) {
        std::cout << "User " << targetUser << " doesn't exist\n";
        return;
    }
    // Shared files go to the target user's shared folder.
    json global = loadGlobalMapping();
    if (!global.contains(targetUser))
        global[targetUser] = json::object();
    if (!global[targetUser].contains("shared_files"))
        global[targetUser]["shared_files"] = json::object();
    std::string hashName = SecOps::SecurityOps::sha256(filename);
    // Update global mapping for the target user's shared_files.
    global[targetUser]["shared_files"][hashName] = filename;
    saveGlobalMapping(global);
    std::string targetDir = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(targetUser) + "/" + 
                            SecOps::SecurityOps::sha256("shared");
    Ops::FileOps::makeDirectory(targetDir);
    std::string targetFile = targetDir + "/" + hashName;
    std::string data = Ops::FileOps::readFile(sourceFile);
    Ops::FileOps::writeFile(targetFile, data);
    std::cout << "Shared file with " << targetUser << " at /shared/" << filename << "\n";
}

void InteractiveShell::handle_mkdir(const std::string &dirname) {
    // Format: mkdir <directory_name>
    if (dirname.empty()) {
        std::cout << "Usage: mkdir <directory_name>\n";
        return;
    }
    // Hash the folder name.
    std::string hashName = SecOps::SecurityOps::sha256(dirname);
    // Determine if current directory is shared or personal.
    if (currentDir.find("/shared") == 0) {
        json global = loadGlobalMapping();
        if (!global.contains(currentUser))
            global[currentUser] = json::object();
        if (!global[currentUser].contains("shared_files"))
            global[currentUser]["shared_files"] = json::object();
        if (global[currentUser]["shared_files"].contains(hashName)) {
            std::cout << "Directory already exists\n";
            return;
        }
        // Update the global mapping.
        global[currentUser]["shared_files"][hashName] = dirname;
        saveGlobalMapping(global);
    } else {
        std::string userRoot = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(currentUser);
        json personal = loadUserFileMapping(userRoot, UOps::UserOps::getUser(currentUser).privateKey);
        if (personal.contains("files") && personal["files"].contains(hashName)) {
            std::cout << "Directory already exists\n";
            return;
        }
        personal["files"][hashName] = dirname;
        // Load user's public key.
        std::string pubFilePath = "public_keys/" + currentUser + "_public.pem";
        std::ifstream pubFile(pubFilePath);
        std::stringstream pubSS;
        pubSS << pubFile.rdbuf();
        std::string userPub = pubSS.str();
        // Update the User's mapping.
        saveUserFileMapping(userRoot, personal, userPub);
    }
    // Create the directory on disk.
    std::string realDir = resolvePath(hashName);
    if (!Ops::FileOps::makeDirectory(realDir))
        std::cout << "Failed to create directory\n";
    
}

void InteractiveShell::handle_mkfile(const std::string &args) {
    // Format: mkfile <filename> <contents>
    std::istringstream iss(args);
    std::string filename;
    iss >> filename;
    if (filename.empty()) {
        std::cout << "Usage: mkfile <filename> <contents>\n";
        return;
    }
    std::string content;
    std::getline(iss, content);
    if (!content.empty() && content[0]==' ')
        content.erase(content.begin());
    // Hash the file name.
    std::string hashName = SecOps::SecurityOps::sha256(filename);
    // Determine if current directory is shared or personal.
    if (currentDir.find("/shared") == 0) {
        json global = loadGlobalMapping();
        if (!global.contains(currentUser))
            global[currentUser] = json::object();
        if (!global[currentUser].contains("shared_files"))
            global[currentUser]["shared_files"] = json::object();
        global[currentUser]["shared_files"][hashName] = filename;
        // Update the global mapping.
        saveGlobalMapping(global);
    } else {
        std::string userRoot = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(currentUser);
        json personal = loadUserFileMapping(userRoot, UOps::UserOps::getUser(currentUser).privateKey);
        personal["files"][hashName] = filename;
        std::string pubFilePath = "public_keys/" + currentUser + "_public.pem";
        std::ifstream pubFile(pubFilePath);
        std::stringstream pubSS;
        pubSS << pubFile.rdbuf();
        std::string userPub = pubSS.str();
        // Update the User's mapping.
        saveUserFileMapping(userRoot, personal, userPub);
    }
    // Derive an AES key from the user's private key (naively).
    std::string userKey = UOps::UserOps::getUser(currentUser).privateKey;
    std::string aesKey = userKey.substr(0, 32);
    std::string encContent;
    try {
        encContent = SecOps::SecurityOps::aesEncrypt(content, aesKey);
    } catch (std::exception &e) {
        std::cout << "Error encrypting file: " << e.what() << "\n";
        return;
    }
    std::string realFile = resolvePath(hashName);
    Ops::FileOps::writeFile(realFile, encContent);

}

void InteractiveShell::handle_adduser(const std::string &username) {
    if (currentUser != "admin") {
        std::cout << "Forbidden: Only admin can add users\n";
        return;
    }
    if (username.empty()) {
        std::cout << "Usage: adduser <username>\n";
        return;
    }
    UOps::UserOps::createUser(username);
}

// Since we removed export functionality per the revised plan, we do not include an exportkey command.

void InteractiveShell::showHelp() {
    std::cout << "Commands:\n"
              << "  cd <directory>         - Change directory (supports . and .. and multiple levels)\n"
              << "  pwd                    - Print current working directory\n"
              << "  ls                     - List files and directories\n"
              << "  cat <filename>         - Display decrypted contents of a file\n"
              << "  share <file> <user>    - Share file with target user (copies file to target's shared folder)\n"
              << "  mkdir <dirname>        - Create a new directory\n"
              << "  mkfile <file> <text>   - Create or overwrite a file with contents\n"
              << "  exit                   - Terminate the program\n";
    if (currentUser == "admin")
        std::cout << "  adduser <username>     - Create a new user (admin only)\n";
}

void InteractiveShell::start() {
    std::string line;
    while (true) {
        std::cout << "[" << currentUser << " @filesystem:" << currentDir << "]$ ";
        if (!std::getline(std::cin, line))
            break;
        if (line.empty())
            continue;
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;
        if (cmd == "cd") {
            std::string arg;
            std::getline(iss, arg);
            if (!arg.empty() && arg[0]==' ')
                arg.erase(arg.begin());
            handle_cd(arg);
        } else if (cmd == "pwd") {
            handle_pwd();
        } else if (cmd == "ls") {
            handle_ls();
        } else if (cmd == "cat") {
            std::string filename;
            iss >> filename;
            handle_cat(filename);
        } else if (cmd == "share") {
            std::string rest;
            std::getline(iss, rest);
            if (!rest.empty() && rest[0]==' ')
                rest.erase(rest.begin());
            handle_share(rest);
        } else if (cmd == "mkdir") {
            std::string dirname;
            iss >> dirname;
            handle_mkdir(dirname);
        } else if (cmd == "mkfile") {
            std::string rest;
            std::getline(iss, rest);
            if (!rest.empty() && rest[0]==' ')
                rest.erase(rest.begin());
            handle_mkfile(rest);
        } else if (cmd == "adduser") {
            std::string uname;
            iss >> uname;
            handle_adduser(uname);
        } else if (cmd == "exit") {
            break;
        } else if (cmd == "help") {
            showHelp();
        } else {
            std::cout << "Unknown command. Type 'help' for usage.\n";
        }
    }
}

} // namespace Shell