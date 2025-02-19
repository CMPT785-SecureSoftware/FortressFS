#include "Shell.h"
#include "FileOps.h"
#include "UserOps.h"
#include "SecurityOps.h"

#include <iostream>
#include <readline/readline.h>
#include <readline/history.h>

namespace Shell {

InteractiveShell::InteractiveShell(const std::string& username)
    : currentUser(username)
{
    currentDir = username + "_home/";
    Ops::FileOps::makeDirectory(currentDir);
}

void InteractiveShell::start() {
    while (true) {
        std::string prompt = "[" + currentUser + " @SecFS:" + currentDir + "]$ ";
        char* line = readline(prompt.c_str());
        if (!line) {
            continue;
        }
        std::string cmd(line);
        free(line);

        if (cmd.empty()) {
            continue;
        }
        add_history(cmd.c_str());

        auto spacePos = cmd.find(' ');
        std::string command = (spacePos == std::string::npos) ? cmd : cmd.substr(0, spacePos);
        std::string args = (spacePos == std::string::npos) ? "" : cmd.substr(spacePos + 1);

        if (command == "exit") {
            std::cout << "Exiting SecureFS...\n";
            break;
        } else if (command == "mkdir") {
            handleMkdir(args);
        } else if (command == "mkfile") {
            // example usage: mkfile test.txt "Hello World"
            auto quotePos = args.find('"');
            if (quotePos == std::string::npos) {
                std::cout << "Usage: mkfile <filename> \"content\"\n";
                continue;
            }
            std::string fileName = args.substr(0, quotePos - 1);
            std::string content = args.substr(quotePos + 1, args.size() - (quotePos + 2));
            handleCreateFile(fileName, content);
        } else if (command == "read") {
            handleReadFile(args);
        } else if (command == "share") {
            // usage: share <filename> <targetUser>
            auto spacePos2 = args.find(' ');
            if (spacePos2 == std::string::npos) {
                std::cout << "Usage: share <filename> <targetUser>\n";
                continue;
            }
            std::string fileName = args.substr(0, spacePos2);
            std::string targetUser = args.substr(spacePos2 + 1);
            handleShare(fileName, targetUser);
        } else if (command == "help") {
            showHelp();
        } else {
            std::cout << "Unknown command. Type 'help' for usage.\n";
        }
    }
}

void InteractiveShell::handleMkdir(const std::string& dirName) {
    if (dirName.empty()) {
        std::cout << "Usage: mkdir <dirname>\n";
        return;
    }
    std::string path = currentDir + dirName;
    if (Ops::FileOps::directoryExists(path)) {
        std::cout << "Directory already exists.\n";
        return;
    }
    if (!Ops::FileOps::makeDirectory(path)) {
        std::cout << "Failed to create directory.\n";
    } else {
        std::cout << "Directory created: " << path << "\n";
    }
}

void InteractiveShell::handleCreateFile(const std::string& fileName, const std::string& content) {
    if (fileName.empty()) {
        std::cout << "Usage: mkfile <filename> \"content\"\n";
        return;
    }
    // Demo AES key (32 bytes for AES-256)
    std::string aesKey = "01234567890123456789012345678901";
    std::string ciphertext;
    try {
        ciphertext = SecOps::SecurityOps::aesEncrypt(content, aesKey);
    } catch (std::exception& e) {
        std::cout << "Error encrypting content: " << e.what() << "\n";
        return;
    }

    std::string path = currentDir + fileName;
    if (!Ops::FileOps::writeEncrypted(path, ciphertext)) {
        std::cout << "Failed to create file.\n";
    } else {
        std::cout << "File created: " << path << "\n";
    }
}

void InteractiveShell::handleReadFile(const std::string& fileName) {
    if (fileName.empty()) {
        std::cout << "Usage: read <filename>\n";
        return;
    }
    std::string path = currentDir + fileName;
    if (!Ops::FileOps::fileExists(path)) {
        std::cout << "File not found.\n";
        return;
    }

    std::string encryptedData = Ops::FileOps::readRaw(path);
    std::string aesKey = "01234567890123456789012345678901";
    try {
        std::string plaintext = SecOps::SecurityOps::aesDecrypt(encryptedData, aesKey);
        std::cout << "File content:\n" << plaintext << "\n";
    } catch (std::exception& ex) {
        std::cout << "Error decrypting file: " << ex.what() << "\n";
    }
}

void InteractiveShell::handleShare(const std::string& fileName, const std::string& targetUser) {
    if (fileName.empty() || targetUser.empty()) {
        std::cout << "Usage: share <filename> <targetUser>\n";
        return;
    }
    if (!UOps::UserOps::userExists(targetUser)) {
        std::cout << "Target user does not exist.\n";
        return;
    }
    std::string sourcePath = currentDir + fileName;
    if (!Ops::FileOps::fileExists(sourcePath)) {
        std::cout << "File not found.\n";
        return;
    }
    // Copy the raw-encrypted file to <targetUser>_home/shared/
    std::string targetDir = targetUser + "_home/shared/";
    Ops::FileOps::makeDirectory(targetDir);

    std::string targetFile = targetDir + fileName;
    std::string encryptedData = Ops::FileOps::readRaw(sourcePath);

    if (!Ops::FileOps::writeEncrypted(targetFile, encryptedData)) {
        std::cout << "Failed to share file.\n";
    } else {
        std::cout << "File shared to " << targetFile << "\n";
    }
}

void InteractiveShell::showHelp() {
    std::cout << "Commands:\n"
              << "  mkdir <dirname>           - Create a directory\n"
              << "  mkfile <file> \"content\"   - Create an AES-encrypted file\n"
              << "  read <file>               - Decrypt and read an AES-encrypted file\n"
              << "  share <file> <user>       - Copy encrypted file to target user's shared folder\n"
              << "  help                      - Show this help\n"
              << "  exit                      - Quit the shell\n";
}

} // namespace Shell