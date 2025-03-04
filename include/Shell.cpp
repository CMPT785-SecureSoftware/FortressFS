#include "Shell.h"
#include "FileOps.h"
#include "UserOps.h"
#include "SecurityOps.h"
#include <iostream>
#include <sstream>
#include <filesystem>
#include <vector>

namespace Shell {

// Constants for folder paths.
static const std::string FILESYSTEM_DIR = "filesystem";
static const std::string ENCRYPTED_KEYS_DIR = FILESYSTEM_DIR + "/EncryptedKeys";
static const std::string PUBLIC_KEYS_DIR = "public_keys";
static const std::string ADMIN_SYMMETRIC_KEY = "0123456789abcdef0123456789abcdef";

// resolvePath() converts a virtual path (e.g., "/personal/test.txt")
// into an absolute path within FILESYSTEM_DIR/<currentUser>.
std::string InteractiveShell::resolvePath(const std::string &vpath) {
    std::string base = FILESYSTEM_DIR + "/" + currentUser;
    if (vpath == "/" || vpath.empty())
        return base;
    if (vpath[0] == '/')
        return base + vpath;
    return base + "/" + vpath;
}

// normalizePath() handles '.' and '..' components.
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

InteractiveShell::InteractiveShell(const std::string &username)
    : currentUser(username), currentDir("/") {
    std::string userDir = FILESYSTEM_DIR + "/" + currentUser;
    if (!Ops::FileOps::directoryExists(userDir)) {
        Ops::FileOps::makeDirectory(userDir + "/personal");
        Ops::FileOps::makeDirectory(userDir + "/shared");
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
        std::string name = entry.path().filename().string();
        if (entry.is_directory())
            std::cout << "d -> " << name << "\n";
        else
            std::cout << "f -> " << name << "\n";
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
    // Derive AES key from user's private key (naively).
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
    if (!UOps::UserOps::userExists(targetUser)) {
        std::cout << "User " << targetUser << " doesn't exist\n";
        return;
    }
    std::string targetDir = FILESYSTEM_DIR + "/" + targetUser + "/shared";
    Ops::FileOps::makeDirectory(targetDir);
    std::string targetFile = targetDir + "/" + filename.substr(filename.find_last_of('/') + 1);
    std::string data = Ops::FileOps::readFile(sourceFile);
    Ops::FileOps::writeFile(targetFile, data);
    std::cout << "Shared file with " << targetUser << " at /shared/" << filename << "\n";
}

void InteractiveShell::handle_mkdir(const std::string &dirname) {
    if (dirname.empty()) {
        std::cout << "Usage: mkdir <directory_name>\n";
        return;
    }
    std::string realDir = resolvePath(dirname);
    if (Ops::FileOps::directoryExists(realDir)) {
        std::cout << "Directory already exists\n";
        return;
    }
    if (!Ops::FileOps::makeDirectory(realDir))
        std::cout << "Failed to create directory\n";
}

void InteractiveShell::handle_mkfile(const std::string &args) {
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
    // Derive AES key from user's private key (naively).
    std::string userKey = UOps::UserOps::getUser(currentUser).privateKey;
    std::string aesKey = userKey.substr(0, 32);
    std::string encContent;
    try {
        encContent = SecOps::SecurityOps::aesEncrypt(content, aesKey);
    } catch (std::exception &e) {
        std::cout << "Error encrypting file: " << e.what() << "\n";
        return;
    }
    std::string realFile = resolvePath(filename);
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

// Updated: handle_exportkey() now writes the exported key as a PEM file in the current directory.
void InteractiveShell::handle_exportkey(const std::string &username) {
    if (currentUser != "admin") {
        std::cout << "Forbidden: Only admin can export user keys\n";
        return;
    }
    if (username.empty()) {
        std::cout << "Usage: exportkey <username>\n";
        return;
    }
    std::string keyfilePath = ENCRYPTED_KEYS_DIR + "/" + username + "_keyfile";
    if (!Ops::FileOps::fileExists(keyfilePath)) {
        std::cout << "Keyfile for user " << username << " does not exist.\n";
        return;
    }
    std::string encKey = Ops::FileOps::readFile(keyfilePath);
    try {
        // Decrypt the user's private key.
        std::string userPriv = SecOps::SecurityOps::aesDecrypt(encKey, ADMIN_SYMMETRIC_KEY);
        // Export the key to a PEM file in the current directory.
        std::string outFilename = username + "_keyfile.pem";
        if (Ops::FileOps::writeFile(outFilename, userPriv))
            std::cout << "Exported key to " << outFilename << "\n";
        else
            std::cout << "Failed to export key.\n";
    } catch (std::exception &e) {
        std::cout << "Error exporting key: " << e.what() << "\n";
    }
}

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
    if (currentUser == "admin") {
        std::cout << "  adduser <username>     - Create a new user (admin only)\n"
                  << "  exportkey <username>   - Export a user's private key as <username>_keyfile.pem (admin only)\n";
    }
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
        } else if (cmd == "exportkey") {
            std::string uname;
            iss >> uname;
            handle_exportkey(uname);
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