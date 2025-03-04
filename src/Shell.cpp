#include "Shell.h"
#include "FileOps.h"
#include "UserOps.h"
#include "SecurityOps.h"
#include <iostream>
#include <sstream>
#include <filesystem>
#include <vector>
#include <fstream>
#include <unordered_map>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace {
    // Global mapping file for user base directories and shared files.
    static const std::string GLOBAL_MAPPING_FILE = "global_mapping.json";

    // Loads the global mapping from file.
    json loadGlobalMapping() {
        std::ifstream ifs(GLOBAL_MAPPING_FILE);
        if (!ifs) return json::object();
        json j;
        ifs >> j;
        return j;
    }

    // Saves the global mapping to file.
    bool saveGlobalMapping(const json &j) {
        std::ofstream ofs(GLOBAL_MAPPING_FILE);
        ofs << j.dump(4);
        return ofs.good();
    }

    /**
     * loadUserFileMapping:
     * Loads and decrypts the per-user mapping file from the given user root directory.
     * The file name is computed as sha256("<username>_file_mapping.json").
     */
    json loadUserFileMapping(const std::string &userRootPath, const std::string &username, const std::string &privateKey) {
        std::string mappingFileName = SecOps::SecurityOps::sha256(username + "_file_mapping.json");
        std::string mappingPath = userRootPath + "/" + mappingFileName;
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

    /**
     * saveUserFileMapping:
     * Encrypts and saves the per-user mapping file in the given user root directory.
     * The file name is computed as sha256("<username>_file_mapping.json").
     */
    bool saveUserFileMapping(const std::string &userRootPath, const std::string &username, const json &j, const std::string &publicKey) {
        std::string mappingFileName = SecOps::SecurityOps::sha256(username + "_file_mapping.json");
        std::string mappingPath = userRootPath + "/" + mappingFileName;
        std::string plain = j.dump(4);
        std::string encrypted = SecOps::SecurityOps::rsaEncrypt(plain, publicKey);
        return Ops::FileOps::writeFile(mappingPath, encrypted);
    }

    // Helper: Returns true if vpath begins with "/personal".
    bool isInPersonalDirectory(const std::string &vpath) {
        return (vpath == "/personal" || vpath.find("/personal/") == 0);
    }

    // Helper: Returns true if vpath begins with "/shared".
    bool isInSharedDirectory(const std::string &vpath) {
        return (vpath == "/shared" || vpath.find("/shared/") == 0);
    }

    // Enum for commands.
    enum Command {
        CMD_UNKNOWN = 0,
        CMD_CD,
        CMD_PWD,
        CMD_LS,
        CMD_CAT,
        CMD_SHARE,
        CMD_MKDIR,
        CMD_MKFILE,
        CMD_ADDUSER,
        CMD_EXIT,
        CMD_HELP
    };

    // Converts a command string to the corresponding Command enum.
    Command getCommand(const std::string &cmd) {
        static const std::unordered_map<std::string, Command> cmdMap = {
            {"cd", CMD_CD},
            {"pwd", CMD_PWD},
            {"ls", CMD_LS},
            {"cat", CMD_CAT},
            {"share", CMD_SHARE},
            {"mkdir", CMD_MKDIR},
            {"mkfile", CMD_MKFILE},
            {"adduser", CMD_ADDUSER},
            {"exit", CMD_EXIT},
            {"help", CMD_HELP}
        };
        auto it = cmdMap.find(cmd);
        if (it != cmdMap.end())
            return it->second;
        return CMD_UNKNOWN;
    }
}

namespace Shell {

static const std::string FILESYSTEM_DIR = "filesystem";

/**
 * resolvePath:
 * Converts a virtual (plaintext) path to the on-disk path using hashed names.
 * For shared paths, it uses the global mapping; for personal, it uses the user's root.
 * When admin is in read-only (viewing another user's) mode, it uses that user's hash.
 */
std::string InteractiveShell::resolvePath(const std::string &vpath) {
    // Determine the active user: if admin is viewing another user, use that.
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
    // For shared paths.
    if (vpath.find("/shared") == 0) {
        json global = loadGlobalMapping();
        std::string sharedHash = global[activeUser]["shared"];
        std::string base = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(activeUser) + "/" + sharedHash;
        std::istringstream iss(vpath);
        std::string token;
        std::string path = base;
        std::getline(iss, token, '/'); // Skip "shared"
        while (std::getline(iss, token, '/')) {
            if (token.empty() || token == ".") continue;
            if (token == "..") {
                size_t pos = path.find_last_of('/');
                if (pos != std::string::npos)
                    path = path.substr(0, pos);
            } else {
                path += "/" + SecOps::SecurityOps::sha256(token);
            }
        }
        return path;
    } else {
        // Personal path resolution.
        std::string base = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(activeUser);
        std::istringstream iss(vpath);
        std::string token;
        std::string path = base;
        while (std::getline(iss, token, '/')) {
            if (token.empty() || token == ".") continue;
            if (token == "..") {
                size_t pos = path.find_last_of('/');
                if (pos != std::string::npos)
                    path = path.substr(0, pos);
            } else {
                path += "/" + SecOps::SecurityOps::sha256(token);
            }
        }
        return path;
    }
}

/**
 * normalizePath:
 * Normalizes a given path by resolving "." and ".." components.
 */
std::string InteractiveShell::normalizePath(const std::string &path) {
    std::vector<std::string> parts;
    std::istringstream iss(path);
    std::string token;
    while (std::getline(iss, token, '/')) {
        if (token.empty() || token == ".") continue;
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

/**
 * Constructor:
 * Initializes the shell for the logged-in user.
 * For normal users, "/" is their root (showing only "personal" and "shared").
 * For admin, by default, viewedUser is empty and isAdminFSMode is false (admin sees his own root).
 */
InteractiveShell::InteractiveShell(const std::string &username)
    : currentUser(username), currentDir("/") {
    // For admin, initialize admin state.
    if (currentUser == "admin") {
        isAdminFSMode = false;
        viewedUser = "";
    }
    std::string userHash = SecOps::SecurityOps::sha256(currentUser);
    std::string userDir = FILESYSTEM_DIR + "/" + userHash;
    std::string personalDir = userDir + "/" + SecOps::SecurityOps::sha256("personal");
    std::string sharedDir = userDir + "/" + SecOps::SecurityOps::sha256("shared");
    if (!Ops::FileOps::directoryExists(userDir)) {
        Ops::FileOps::makeDirectory(userDir);
        Ops::FileOps::makeDirectory(personalDir);
        Ops::FileOps::makeDirectory(sharedDir);
        // Create per-user mapping file for personal folder.
        json personalMapping;
        personalMapping["username"] = currentUser;
        // Files and folders stored as { hash: [originalName, type] }.
        personalMapping["files"] = json::object();
        std::string pubFilePath = "public_keys/" + currentUser + "_public.pem";
        std::ifstream pubFile(pubFilePath);
        std::stringstream pubSS;
        pubSS << pubFile.rdbuf();
        std::string userPub = pubSS.str();
        saveUserFileMapping(userDir, currentUser, personalMapping, userPub);
    }
}

/**
 * handle_cd:
 * Processes the "cd" command.
 * For normal users, cd is not allowed to leave their root ("/").
 * For admin:
 *  - In his own root view (viewedUser empty, isAdminFSMode false), "cd .." switches to filesystem view.
 *  - In filesystem view (isAdminFSMode true), "cd <username>" enters that user's view (read-only).
 *  - In a user's view (viewedUser non-empty), "cd .." returns to filesystem view.
 */
void InteractiveShell::handle_cd(const std::string &arg) {
    if (arg.empty())
        return;
    std::string target = arg;
    // If admin is logged in.
    if (currentUser == "admin") {
        // In admin's own root view.
        if (!isAdminFSMode && viewedUser.empty()) {
            if (target == "..") {
                // Switch to filesystem view.
                isAdminFSMode = true;
                currentDir = "/";
                return;
            }
        }
        // In filesystem view.
        if (isAdminFSMode) {
            if (target == "..") {
                // Cannot go above filesystem view.
                std::cout << "Already at filesystem view.\n";
                return;
            }
            // Check admin_mapping.json for the target username.
            std::string adminMappingFile = SecOps::SecurityOps::sha256("admin_mapping.json");
            std::string adminMappingPath = FILESYSTEM_DIR + "/" + adminMappingFile;
            json admMap;
            if (std::filesystem::exists(adminMappingPath)) {
                std::string adminPriv = UOps::UserOps::getUser("admin").privateKey;
                std::string key = adminPriv.substr(0, 32);
                try {
                    std::string decrypted = SecOps::SecurityOps::aesDecrypt(Ops::FileOps::readFile(adminMappingPath), key);
                    admMap = json::parse(decrypted);
                } catch (...) {
                    admMap = json::object();
                }
            }
            if (admMap.contains(target)) {
                // Enter the target user's view.
                viewedUser = target;
                isAdminFSMode = false;
                currentDir = "/";
                return;
            } else {
                std::cout << "User " << target << " not found in admin mapping.\n";
                return;
            }
        }
        // In a user's view (viewedUser is non-empty).
        if (!viewedUser.empty() && target == "..") {
            // Return to filesystem view.
            viewedUser = "";
            isAdminFSMode = true;
            currentDir = "/";
            return;
        }
        // Otherwise, for admin in a user's view, disallow modification commands like "cd" that attempt to navigate within the user's directory.
        // We'll allow normal cd for viewing files (read-only), so handle normally.
    }
    // For non-admin users, they cannot cd to "/" (their root is fixed).
    if (target == "/" && currentUser != "admin") {
        std::cout << "Access denied: You cannot cd to root (/).\n";
        return;
    }
    std::string newPath;
    if (target[0] == '/')
        newPath = normalizePath(target);
    else
        newPath = normalizePath(currentDir + "/" + target);
    if (newPath == "/" && currentUser != "admin") {
        std::cout << "Access denied: You cannot move above your root.\n";
        return;
    }
    std::string realPath = resolvePath(newPath);
    if (Ops::FileOps::directoryExists(realPath))
        currentDir = newPath;
    else
        std::cout << "Directory does not exist.\n";
}

/**
 * handle_pwd:
 * Displays the current virtual directory.
 * - For normal users, "/" shows only "personal" and "shared".
 * - For admin in filesystem view, prints "filesystem".
 * - For admin in a user's view, prints "/" followed by the username.
 * - Otherwise, prints the currentDir.
 */
void InteractiveShell::handle_pwd() {
    if (currentUser == "admin") {
        if (isAdminFSMode) {
            std::cout << "filesystem\n";
            return;
        } else if (!viewedUser.empty()) {
            std::cout << "/" << viewedUser << "\n";
            return;
        }
    }
    std::cout << currentDir << "\n";
}

/**
 * handle_ls:
 * Lists the contents of the current directory.
 * - For admin in filesystem view, lists all users from admin_mapping.json.
 * - Otherwise, in personal directories, reads from the per-user mapping file.
 * - In shared directories, uses the global mapping.
 */
void InteractiveShell::handle_ls() {
    // For admin in filesystem view.
    if (currentUser == "admin" && isAdminFSMode) {
        json adminMapping;
        std::string adminMappingFile = SecOps::SecurityOps::sha256("admin_mapping.json");
        std::string adminMappingPath = FILESYSTEM_DIR + "/" + adminMappingFile;
        if (std::filesystem::exists(adminMappingPath)) {
            std::string adminPriv = UOps::UserOps::getUser("admin").privateKey;
            std::string key = adminPriv.substr(0, 32);
            try {
                std::string decrypted = SecOps::SecurityOps::aesDecrypt(Ops::FileOps::readFile(adminMappingPath), key);
                adminMapping = json::parse(decrypted);
            } catch (...) {
                adminMapping = json::object();
            }
        }
        std::cout << "Users:\n";
        for (auto it = adminMapping.begin(); it != adminMapping.end(); ++it) {
            std::cout << " - " << it.key() << "\n";
        }
        return;
    }
    // For all other cases, resolve the virtual path.
    std::string realDir = resolvePath(currentDir);
    if (!Ops::FileOps::directoryExists(realDir)) {
        std::cout << "Directory does not exist.\n";
        return;
    }
    std::cout << "d -> .\n";
    std::cout << "d -> ..\n";
    for (const auto &entry : std::filesystem::directory_iterator(realDir)) {
        std::string hashedName = entry.path().filename().string();
        std::string displayName = hashedName;
        if (currentDir.find("/shared") == 0) {
            json global = loadGlobalMapping();
            if (global.contains((currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser) &&
                global[(currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser].contains("shared_files")) {
                if (global[(currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser]["shared_files"].contains(hashedName))
                    displayName = global[(currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser]["shared_files"][hashedName];
            }
        } else {
            std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
            std::string userRoot = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(activeUser);
            std::string privateKey = UOps::UserOps::getUser(activeUser).privateKey;
            json personal = loadUserFileMapping(userRoot, activeUser, privateKey);
            if (personal.contains("files") && personal["files"].contains(hashedName)) {
                auto arr = personal["files"][hashedName];
                displayName = arr[0].get<std::string>();
                std::string type = arr[1].get<std::string>();
                if (type == "d")
                    displayName = "d -> " + displayName;
                else if (type == "f")
                    displayName = "f -> " + displayName;
            }
        }
        std::cout << displayName << "\n";
    }
}

/**
 * handle_cat:
 * Displays the decrypted contents of a file.
 * Allowed only in personal or shared directories.
 */
void InteractiveShell::handle_cat(const std::string &filename) {
    if (filename.empty())
        return;
    if (!(isInPersonalDirectory(currentDir) || isInSharedDirectory(currentDir))) {
        std::cout << "Access denied: cat is allowed only in personal or shared directories.\n";
        return;
    }
    // Determine active user for file operations.
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
    std::string realFile = resolvePath(filename);
    if (!Ops::FileOps::fileExists(realFile)) {
        std::cout << filename << " doesn't exist\n";
        return;
    }
    std::string userKey = UOps::UserOps::getUser(activeUser).privateKey;
    std::string aesKey = userKey.substr(0, 32);
    std::string encContent = Ops::FileOps::readFile(realFile);
    try {
        std::string plain = SecOps::SecurityOps::aesDecrypt(encContent, aesKey);
        std::cout << plain << "\n";
    } catch (std::exception &e) {
        std::cout << "Error decrypting file: " << e.what() << "\n";
    }
}

/**
 * handle_share:
 * Shares a file from the personal directory with a target user.
 * Process:
 *  - Ensures the command is run in the personal directory.
 *  - Verifies that the file exists.
 *  - Checks that the target user exists (via global mapping).
 *  - Locates the target user's shared folder using global mapping.
 *  - Copies the file to the target's shared folder.
 *  - Updates the target's "shared_files" mapping in global mapping.
 */
void InteractiveShell::handle_share(const std::string &args) {
    std::istringstream iss(args);
    std::string filename, targetUser;
    iss >> filename >> targetUser;
    if (filename.empty() || targetUser.empty()) {
        std::cout << "Usage: share <filename> <targetUser>\n";
        return;
    }
    if (!isInPersonalDirectory(currentDir)) {
        std::cout << "Share command allowed only in personal directory and its subdirectories.\n";
        return;
    }
    std::string sourceFile = resolvePath(filename);
    if (!Ops::FileOps::fileExists(sourceFile)) {
        std::cout << "File " << filename << " doesn't exist\n";
        return;
    }
    json global = loadGlobalMapping();
    if (!global.contains(targetUser)) {
        std::cout << "User " << targetUser << " doesn't exist in global mapping.\n";
        return;
    }
    // Locate target user's shared folder.
    std::string targetSharedHash = global[targetUser]["shared"];
    std::string targetDir = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(targetUser) + "/" + targetSharedHash;
    Ops::FileOps::makeDirectory(targetDir);
    // (For simplicity, we copy the file as is; shared files are read-only.)
    std::string fileData = Ops::FileOps::readFile(sourceFile);
    std::string hashName = SecOps::SecurityOps::sha256(filename);
    global[targetUser]["shared_files"][hashName] = filename;
    saveGlobalMapping(global);
    std::string targetFile = targetDir + "/" + hashName;
    Ops::FileOps::writeFile(targetFile, fileData);
    std::cout << "Shared file with " << targetUser << " at /shared/" << filename << "\n";
}

/**
 * handle_mkdir:
 * Creates a new directory.
 * Allowed only in the personal directory (or its subdirectories).
 * Admin cannot modify another user's directories (mkdir disallowed in user's view).
 * Updates the per-user mapping file with an entry: { hash: [originalName, "d"] }.
 */
void InteractiveShell::handle_mkdir(const std::string &dirname) {
    if (dirname.empty()) {
        std::cout << "Usage: mkdir <directory_name>\n";
        return;
    }
    // Disallow modifications in admin filesystem view.
    if (currentUser == "admin" && (isAdminFSMode || (!viewedUser.empty()))) {
        std::cout << "Admin is read-only in user directories. mkdir not allowed.\n";
        return;
    }
    if (!isInPersonalDirectory(currentDir)) {
        std::cout << "mkdir allowed only in personal directory and its subdirectories.\n";
        return;
    }
    std::string hashName = SecOps::SecurityOps::sha256(dirname);
    std::string userKey = (currentUser == "admin" && !viewedUser.empty()) ? 
                           UOps::UserOps::getUser(viewedUser).privateKey : UOps::UserOps::getUser(currentUser).privateKey;
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
    std::string userRoot = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(activeUser);
    json personal = loadUserFileMapping(userRoot, activeUser, userKey);
    if (personal.contains("files") && personal["files"].contains(hashName)) {
        std::cout << "Directory already exists\n";
        return;
    }
    personal["files"][hashName] = json::array({ dirname, "d" });
    std::string pubFilePath = "public_keys/" + activeUser + "_public.pem";
    std::ifstream pubFile(pubFilePath);
    std::stringstream pubSS;
    pubSS << pubFile.rdbuf();
    std::string userPub = pubSS.str();
    saveUserFileMapping(userRoot, activeUser, personal, userPub);
    std::string realDir = resolvePath(dirname);
    if (!Ops::FileOps::makeDirectory(realDir))
        std::cout << "Failed to create directory\n";
}

/**
 * handle_mkfile:
 * Creates or overwrites a file.
 * Allowed only in the personal directory (or its subdirectories).
 * Admin cannot modify another user's directories.
 * Updates the per-user mapping file with an entry: { hash: [originalName, "f"] }.
 */
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
    if (!isInPersonalDirectory(currentDir)) {
        std::cout << "mkfile allowed only in personal directory and its subdirectories.\n";
        return;
    }
    if (currentUser == "admin" && (isAdminFSMode || (!viewedUser.empty()))) {
        std::cout << "Admin is read-only in user directories. mkfile not allowed.\n";
        return;
    }
    std::string hashName = SecOps::SecurityOps::sha256(filename);
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
    std::string userRoot = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(activeUser);
    std::string userKey = (currentUser == "admin" && !viewedUser.empty()) ?
                           UOps::UserOps::getUser(viewedUser).privateKey : UOps::UserOps::getUser(currentUser).privateKey;
    json personal = loadUserFileMapping(userRoot, activeUser, userKey);
    personal["files"][hashName] = json::array({ filename, "f" });
    std::string pubFilePath = "public_keys/" + activeUser + "_public.pem";
    std::ifstream pubFile(pubFilePath);
    std::stringstream pubSS;
    pubSS << pubFile.rdbuf();
    std::string userPub = pubSS.str();
    saveUserFileMapping(userRoot, activeUser, personal, userPub);
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

/**
 * handle_adduser:
 * Allows admin to add a new user.
 * Checks if the user exists, creates the user, and updates admin_mapping.json.
 */
void InteractiveShell::handle_adduser(const std::string &username) {
    if (currentUser != "admin") {
        std::cout << "Forbidden: Only admin can add users\n";
        return;
    }
    if (username.empty()) {
        std::cout << "Usage: adduser <username>\n";
        return;
    }
    if (UOps::UserOps::userExists(username)) {
        std::cout << "User " << username << " already exists.\n";
        return;
    }
    if (!UOps::UserOps::createUser(username)) {
        std::cout << "Failed to create user " << username << "\n";
        return;
    }
    // Update admin_mapping.json with the new user's private key.
    std::string adminPriv = UOps::UserOps::getUser("admin").privateKey;
    if (!UOps::UserOps::updateAdminMapping(username, UOps::UserOps::getUser(username).privateKey, adminPriv)) {
        std::cout << "Failed to update admin mapping.\n";
    }
}

/**
 * showHelp:
 * Displays the list of available commands.
 */
void InteractiveShell::showHelp() {
    std::cout << "Commands:\n"
              << "  cd <directory>         - Change directory (cd allowed everywhere; non-admin cannot cd to root)\n"
              << "  pwd                    - Print current directory (for users, root shows as /; admin sees 'filesystem' in FS view or '/<username>' when viewing a user)\n"
              << "  ls                     - List directory contents\n"
              << "  cat <filename>         - Display file contents (allowed only in personal/shared directories)\n"
              << "  share <file> <user>    - Share a file (allowed only in personal directory)\n"
              << "  mkdir <dirname>        - Create a directory (allowed only in personal directory)\n"
              << "  mkfile <file> <text>   - Create/overwrite a file (allowed only in personal directory)\n"
              << "  exit                   - Terminate the program\n";
    if (currentUser == "admin")
        std::cout << "  adduser <username>     - Create a new user (admin only)\n";
}

/**
 * start:
 * The main interactive loop. Reads commands, converts them to enum values,
 * and dispatches via a switch-case statement.
 */
void InteractiveShell::start() {
    // Mapping from command strings to enum values.
    std::unordered_map<std::string, int> cmdMap = {
        {"cd", CMD_CD},
        {"pwd", CMD_PWD},
        {"ls", CMD_LS},
        {"cat", CMD_CAT},
        {"share", CMD_SHARE},
        {"mkdir", CMD_MKDIR},
        {"mkfile", CMD_MKFILE},
        {"adduser", CMD_ADDUSER},
        {"exit", CMD_EXIT},
        {"help", CMD_HELP}
    };

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
        int command = CMD_UNKNOWN;
        if (cmdMap.find(cmd) != cmdMap.end())
            command = cmdMap[cmd];

        switch (command) {
            case CMD_CD: {
                std::string arg;
                std::getline(iss, arg);
                if (!arg.empty() && arg[0] == ' ')
                    arg.erase(arg.begin());
                handle_cd(arg);
                break;
            }
            case CMD_PWD:
                handle_pwd();
                break;
            case CMD_LS:
                handle_ls();
                break;
            case CMD_CAT: {
                std::string filename;
                iss >> filename;
                handle_cat(filename);
                break;
            }
            case CMD_SHARE: {
                std::string rest;
                std::getline(iss, rest);
                if (!rest.empty() && rest[0] == ' ')
                    rest.erase(rest.begin());
                handle_share(rest);
                break;
            }
            case CMD_MKDIR: {
                std::string dirname;
                iss >> dirname;
                handle_mkdir(dirname);
                break;
            }
            case CMD_MKFILE: {
                std::string rest;
                std::getline(iss, rest);
                if (!rest.empty() && rest[0] == ' ')
                    rest.erase(rest.begin());
                handle_mkfile(rest);
                break;
            }
            case CMD_ADDUSER: {
                std::string uname;
                iss >> uname;
                handle_adduser(uname);
                break;
            }
            case CMD_EXIT:
                return;
            case CMD_HELP:
                showHelp();
                break;
            default:
                std::cout << "Unknown command. Type 'help' for usage.\n";
                break;
        }
    }
}

} // namespace Shell