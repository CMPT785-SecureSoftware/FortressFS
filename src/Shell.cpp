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

    // Loads the global mapping JSON from file.
    json loadGlobalMapping() {
        std::ifstream ifs(GLOBAL_MAPPING_FILE);
        if (!ifs) return json::object();
        json j;
        ifs >> j;
        return j;
    }

    // Saves the global mapping JSON to file.
    bool saveGlobalMapping(const json &j) {
        std::ofstream ofs(GLOBAL_MAPPING_FILE);
        ofs << j.dump(4);
        return ofs.good();
    }

    /**
     * loadUserFileMapping:
     * Loads and decrypts the per-user mapping file from the user's root directory.
     * The mapping file name is computed as SHA-256("<username>_file_mapping.json").
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
     * Encrypts and saves the per-user mapping file in the user's root directory.
     * The file name is computed as SHA-256("<username>_file_mapping.json").
     */
    bool saveUserFileMapping(const std::string &userRootPath, const std::string &username, const json &j, const std::string &publicKey) {
        std::string mappingFileName = SecOps::SecurityOps::sha256(username + "_file_mapping.json");
        std::string mappingPath = userRootPath + "/" + mappingFileName;
        std::string plain = j.dump(4);
        std::string encrypted = SecOps::SecurityOps::rsaEncrypt(plain, publicKey);
        return Ops::FileOps::writeFile(mappingPath, encrypted);
    }

    // Helper: Returns true if the virtual path starts with "/personal".
    bool isInPersonalDirectory(const std::string &vpath) {
        return (vpath == "/personal" || vpath.find("/personal/") == 0);
    }

    // Helper: Returns true if the virtual path starts with "/shared".
    bool isInSharedDirectory(const std::string &vpath) {
        return (vpath == "/shared" || vpath.find("/shared/") == 0);
    }

    // Enum for command types.
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
 * If admin is viewing another user's directory, that user's hash is used.
 * For shared paths, the global mapping is used; for personal paths, the user's root is used.
 */
std::string InteractiveShell::resolvePath(const std::string &vpath) {
    // Determine the active user: if admin is viewing another user's directory, use that username.
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
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
 * Normalizes a path by resolving "." and ".." components.
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
 * For normal users, the virtual root ("/") shows only "personal" and "shared".
 * For admin, extra state (isAdminFSMode and viewedUser) is used to switch between his own view and filesystem view.
 */
InteractiveShell::InteractiveShell(const std::string &username)
    : currentUser(username), currentDir("/") {
    // For admin, initialize additional state.
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
        // Create the per-user mapping file for the personal directory.
        json personalMapping;
        personalMapping["username"] = currentUser;
        // Files and directories stored as { hash: [originalName, type] }.
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
 * Handles the "cd" command.
 * - Non-admin users cannot leave their root ("/").
 * - For admin:
 *   - In his own view (not in filesystem view), "cd .." switches to filesystem view.
 *   - In filesystem view, "cd <username>" enters that user's view (read-only).
 *   - In a user's view, "cd .." returns to filesystem view.
 */
void InteractiveShell::handle_cd(const std::string &arg) {
    if (arg.empty())
        return;
    std::string target = arg;
    // Admin special handling.
    if (currentUser == "admin") {
        if (!isAdminFSMode && viewedUser.empty()) {
            if (target == "..") {
                // Switch to filesystem view.
                isAdminFSMode = true;
                currentDir = "/";
                return;
            }
        }
        if (isAdminFSMode) {
            if (target == "..") {
                std::cout << "Already at filesystem view.\n";
                return;
            }
            // In filesystem view, check admin_mapping.json for target user.
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
                // Enter the target user's view (read-only).
                viewedUser = target;
                isAdminFSMode = false;
                currentDir = "/";
                return;
            } else {
                std::cout << "User " << target << " not found in admin mapping.\n";
                return;
            }
        }
        if (!viewedUser.empty() && target == "..") {
            // Return to filesystem view.
            viewedUser = "";
            isAdminFSMode = true;
            currentDir = "/";
            return;
        }
    }
    // For non-admin users, cd to "/" is not allowed.
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
 * Prints the current virtual directory.
 * - For normal users, "/" represents their root (showing only "personal" and "shared").
 * - For admin in filesystem view, prints "filesystem".
 * - For admin in a user's view, prints "/<username>".
 */
void InteractiveShell::handle_pwd() {
    if (currentUser == "admin") {
        if (isAdminFSMode)
            std::cout << "filesystem\n";
        else if (!viewedUser.empty())
            std::cout << "/" << viewedUser << "\n";
        else
            std::cout << currentDir << "\n";
    } else {
        std::cout << currentDir << "\n";
    }
}

/**
 * handle_ls:
 * Lists the contents of the current virtual directory.
 * Special behavior:
 *  - If the current directory is "/" (i.e. the user's root) and the user is not in admin filesystem view,
 *    then only "d -> .", "d -> ..", "personal", and "shared" are shown.
 *  - For admin in filesystem view, ls lists all users from admin_mapping.json.
 *  - In other directories, it uses the per-user mapping file (for personal) or the global mapping (for shared).
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
    // For a user's root folder: if currentDir is "/" and we are not in admin filesystem view,
    // then list exactly "d -> .", "d -> ..", "personal", and "shared".
    if (currentDir == "/" && (currentUser != "admin" || (currentUser == "admin" && !isAdminFSMode && viewedUser.empty()))) {
        std::cout << "d -> .\n";
        std::cout << "d -> ..\n";
        std::cout << "personal\n";
        std::cout << "shared\n";
        return;
    }
    // Otherwise, list the directory contents from the underlying directory.
    std::string realDir = resolvePath(currentDir);
    if (!Ops::FileOps::directoryExists(realDir)) {
        std::cout << "Directory does not exist.\n";
        return;
    }
    std::cout << "d -> .\n";
    std::cout << "d -> ..\n";
    // Determine active user: if admin is viewing another user, use that user.
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
    // In personal directories, we read the per-user mapping file to get original names.
    if (currentDir.find("/shared") == 0) {
        json global = loadGlobalMapping();
        if (global.contains(activeUser) && global[activeUser].contains("shared_files")) {
            for (auto &item : global[activeUser]["shared_files"].items()) {
                std::cout << item.value() << "\n";
            }
        }
    } else {
        // For directories other than root in personal area, list based on the mapping file.
        std::string userRoot = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(activeUser);
        std::string privateKey = UOps::UserOps::getUser(activeUser).privateKey;
        json personal = loadUserFileMapping(userRoot, activeUser, privateKey);
        if (personal.contains("files")) {
            for (auto &item : personal["files"].items()) {
                std::string displayName = item.value()[0].get<std::string>();
                std::string type = item.value()[1].get<std::string>();
                if (type == "d")
                    std::cout << "d -> " << displayName << "\n";
                else if (type == "f")
                    std::cout << "f -> " << displayName << "\n";
            }
        }
    }
}

/**
 * handle_cat:
 * Displays the decrypted contents of a file.
 * Allowed only in personal and shared directories.
 * Uses the active user's private key from the in-memory structure.
 */
void InteractiveShell::handle_cat(const std::string &filename) {
    if (filename.empty())
        return;
    if (!(isInPersonalDirectory(currentDir) || isInSharedDirectory(currentDir))) {
        std::cout << "Access denied: cat is allowed only in personal or shared directories.\n";
        return;
    }
    std::string realFile = resolvePath(filename);
    if (!Ops::FileOps::fileExists(realFile)) {
        std::cout << filename << " doesn't exist\n";
        return;
    }
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
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
    // For simplicity, we copy the file as is.
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
 * Allowed only in the personal directory and its subdirectories.
 * Admin cannot modify user directories (mkdir not allowed in user's view).
 * Updates the per-user mapping file with an entry: { hash: [originalName, "d"] }.
 */
void InteractiveShell::handle_mkdir(const std::string &dirname) {
    if (dirname.empty()) {
        std::cout << "Usage: mkdir <directory_name>\n";
        return;
    }
    // Admin in user view (or filesystem view) cannot modify.
    if (currentUser == "admin" && (!isAdminFSMode || !viewedUser.empty())) {
        std::cout << "Admin is read-only in user directories. mkdir not allowed.\n";
        return;
    }
    if (!isInPersonalDirectory(currentDir)) {
        std::cout << "mkdir allowed only in personal directory and its subdirectories.\n";
        return;
    }
    std::string hashName = SecOps::SecurityOps::sha256(dirname);
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
    std::string userRoot = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(activeUser);
    json personal = loadUserFileMapping(userRoot, activeUser, UOps::UserOps::getUser(activeUser).privateKey);
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
 * Allowed only in the personal directory and its subdirectories.
 * Admin cannot modify user directories.
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
    if (currentUser == "admin" && (!isAdminFSMode || !viewedUser.empty())) {
        std::cout << "Admin is read-only in user directories. mkfile not allowed.\n";
        return;
    }
    std::string hashName = SecOps::SecurityOps::sha256(filename);
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
    std::string userRoot = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(activeUser);
    std::string userKey = UOps::UserOps::getUser(activeUser).privateKey;
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
              << "  cd <directory>         - Change directory (allowed everywhere; non-admin cannot cd to root)\n"
              << "  pwd                    - Print current directory (for users, root shows as /; admin sees 'filesystem' in FS view or '/<username>' when viewing a user)\n"
              << "  ls                     - List directory contents (for root, shows only personal and shared)\n"
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
 * The main interactive loop. Reads a command line, converts the command to an enum value,
 * and dispatches to the appropriate handler via a switch-case statement.
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