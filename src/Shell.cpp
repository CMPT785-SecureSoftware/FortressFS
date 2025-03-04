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
     * Loads and decrypts the per-user mapping file from the given user root directory.
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
     * saveDirMapping:
     * Encrypts and saves a directory's mapping file.
     * The mapping file is named as SHA-256("<dirName>_file_mapping.json").
     */
    bool saveDirMapping(const std::string &dirPath, const std::string &dirName, const json &j, const std::string &publicKey) {
        std::string mappingFileName = SecOps::SecurityOps::sha256(dirName + "_file_mapping.json");
        std::string mappingPath = dirPath + "/" + mappingFileName;
        std::string plain = j.dump(4);
        std::string encrypted = SecOps::SecurityOps::rsaEncrypt(plain, publicKey);
        return Ops::FileOps::writeFile(mappingPath, encrypted);
    }

    // Helper: Returns true if the virtual path begins with "/personal".
    bool isInPersonalDirectory(const std::string &vpath) {
        return (vpath == "/personal" || vpath.find("/personal/") == 0);
    }

    // Helper: Returns true if the virtual path begins with "/shared".
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
 * Converts a virtual (plaintext) path to an on-disk path using hashed names.
 * If admin is viewing another user's directory, that user's hash is used.
 * For shared paths, the global mapping is used; for personal paths, the user's root is used.
 */
std::string InteractiveShell::resolvePath(const std::string &vpath) {
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
 * Normalizes the given path by resolving "." and ".." components.
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
 * For admin, additional state (isAdminFSMode and viewedUser) is initialized.
 */
InteractiveShell::InteractiveShell(const std::string &username)
    : currentUser(username), currentDir("/") {
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
        // Create the per-user mapping file for the personal area (root level).
        json personalMapping;
        personalMapping["username"] = currentUser;
        // Mapping file stores immediate children as { hash: [originalName, type] }.
        personalMapping["files"] = json::object();
        // Save this mapping file in the user root.
        // Here we use currentUser + "_file_mapping" as the base name.
        saveDirMapping(userDir, currentUser + "_file_mapping", personalMapping, UOps::UserOps::getUser(currentUser).publicKey);
    }
}

/**
 * handle_cd:
 * Processes the "cd" command.
 * - Non-admin users cannot leave their root ("/").
 * - For admin:
 *    - In his own view, "cd .." switches to filesystem view.
 *    - In filesystem view, "cd <username>" enters that user's view (read-only).
 *    - In a user's view, "cd .." returns to filesystem view.
 */
void InteractiveShell::handle_cd(const std::string &arg) {
    if (arg.empty())
        return;
    std::string target = arg;
    if (currentUser == "admin") {
        if (!isAdminFSMode && viewedUser.empty()) {
            if (target == "..") {
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
            viewedUser = "";
            isAdminFSMode = true;
            currentDir = "/";
            return;
        }
    }
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
 * - For normal users, "/" shows only "personal" and "shared".
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
 * - At the user’s root ("/"), lists only:
 *     d -> .
 *     d -> ..
 *     personal
 *     shared
 * - In other directories within personal, it loads the directory’s mapping file (if available)
 *   to display the original names instead of hashed names.
 * - For shared directories, uses the global mapping.
 */
void InteractiveShell::handle_ls() {
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
    if (currentDir == "/" && (currentUser != "admin" || (currentUser == "admin" && !isAdminFSMode && viewedUser.empty()))) {
        std::cout << "d -> .\n";
        std::cout << "d -> ..\n";
        std::cout << "personal\n";
        std::cout << "shared\n";
        return;
    }
    std::string realDir = resolvePath(currentDir);
    if (!Ops::FileOps::directoryExists(realDir)) {
        std::cout << "Directory does not exist.\n";
        return;
    }
    std::cout << "d -> .\n";
    std::cout << "d -> ..\n";
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
    if (currentDir.find("/shared") == 0) {
        json global = loadGlobalMapping();
        if (global.contains(activeUser) && global[activeUser].contains("shared_files")) {
            for (auto &item : global[activeUser]["shared_files"].items()) {
                std::cout << item.value() << "\n";
            }
        }
    } else {
        std::string userRoot = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(activeUser);
        std::string privateKey = UOps::UserOps::getUser(activeUser).privateKey;
        // Load mapping file for the current directory.
        json mapping = loadUserFileMapping(realDir, "dummy", privateKey);
        if (mapping.empty() || !mapping.contains("files")) {
            // If mapping not available, list raw hashed names.
            for (const auto &entry : std::filesystem::directory_iterator(realDir)) {
                std::cout << entry.path().filename().string() << "\n";
            }
        } else {
            for (auto &item : mapping["files"].items()) {
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
 * Uses the active user's private key from the in-memory data structure.
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
 *  - Ensures the command is run inside the personal directory.
 *  - Verifies that the file exists.
 *  - Checks that the target user exists via the global mapping.
 *  - Locates the target user's shared folder using global mapping.
 *  - Copies the file into the target's shared folder.
 *  - Updates the target's "shared_files" mapping in the global mapping.
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
    std::string targetSharedHash = global[targetUser]["shared"];
    std::string targetDir = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(targetUser) + "/" + targetSharedHash;
    Ops::FileOps::makeDirectory(targetDir);
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
 * After creating the directory, an empty mapping file is also created inside it.
 * Updates the parent's mapping file with an entry: { hash: [originalName, "d"] }.
 */
void InteractiveShell::handle_mkdir(const std::string &dirname) {
    if (dirname.empty()) {
        std::cout << "Usage: mkdir <directory_name>\n";
        return;
    }
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
    // Get physical path for the current directory.
    std::string realDir = resolvePath(currentDir);
    // Load the current directory's mapping.
    json currentMapping = loadUserFileMapping(realDir, "dummy", UOps::UserOps::getUser(activeUser).privateKey);
    // Update parent's mapping: add { hashName: [dirname, "d"] }.
    currentMapping["files"][hashName] = json::array({ dirname, "d" });
    // Save updated mapping back. (Here we use a helper function to save the mapping for current directory.)
    saveDirMapping(realDir, "dummy", currentMapping, UOps::UserOps::getUser(activeUser).publicKey);
    // Create the new directory physically.
    std::string newDirPath = realDir + "/" + SecOps::SecurityOps::sha256(dirname);
    if (!Ops::FileOps::makeDirectory(newDirPath)) {
        std::cout << "Failed to create directory\n";
        return;
    }
    // Create an empty mapping file in the new directory.
    json newMapping;
    newMapping["dirname"] = dirname;
    newMapping["files"] = json::object();
    saveDirMapping(newDirPath, dirname + "_file_mapping", newMapping, UOps::UserOps::getUser(activeUser).publicKey);
}

/**
 * handle_mkfile:
 * Creates or overwrites a file.
 * Allowed only in the personal directory and its subdirectories.
 * Updates the parent's mapping file with an entry: { hash: [originalName, "f"] }.
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
    std::string realDir = resolvePath(currentDir);
    json mapping = loadUserFileMapping(realDir, "dummy", UOps::UserOps::getUser(activeUser).privateKey);
    mapping["files"][hashName] = json::array({ filename, "f" });
    saveDirMapping(realDir, "dummy", mapping, UOps::UserOps::getUser(activeUser).publicKey);
    std::string userKey = UOps::UserOps::getUser(activeUser).privateKey;
    std::string aesKey = userKey.substr(0, 32);
    std::string encContent;
    try {
        encContent = SecOps::SecurityOps::aesEncrypt(content, aesKey);
    } catch (std::exception &e) {
        std::cout << "Error encrypting file: " << e.what() << "\n";
        return;
    }
    std::string realFile = realDir + "/" + SecOps::SecurityOps::sha256(filename);
    Ops::FileOps::writeFile(realFile, encContent);
}

/**
 * handle_adduser:
 * Allows admin to add a new user.
 * Checks for existence, creates the user, and updates admin_mapping.json.
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
    std::string adminPriv = UOps::UserOps::getUser("admin").privateKey;
    if (!UOps::UserOps::updateAdminMapping(username, UOps::UserOps::getUser(username).privateKey, adminPriv)) {
        std::cout << "Failed to update admin mapping.\n";
    }
}

/**
 * showHelp:
 * Displays only the allowed commands based on the user's role and current directory.
 */
void InteractiveShell::showHelp() {
    std::cout << "Allowed Commands:\n";
    if (currentUser != "admin") {
        if (currentDir == "/") {
            std::cout << "  cd <directory>         - Change directory (to 'personal' or 'shared')\n";
            std::cout << "  pwd                    - Print current directory\n";
            std::cout << "  ls                     - List contents (shows only 'personal' and 'shared')\n";
            std::cout << "  exit                   - Terminate the program\n";
            std::cout << "  help                   - Display this help message\n";
        } else if (isInPersonalDirectory(currentDir)) {
            std::cout << "  cd <directory>         - Change directory\n";
            std::cout << "  pwd                    - Print current directory\n";
            std::cout << "  ls                     - List directory contents\n";
            std::cout << "  cat <filename>         - Display file contents\n";
            std::cout << "  mkdir <dirname>        - Create a new directory\n";
            std::cout << "  mkfile <file> <text>   - Create or overwrite a file\n";
            std::cout << "  share <file> <user>    - Share a file\n";
            std::cout << "  exit                   - Terminate the program\n";
            std::cout << "  help                   - Display this help message\n";
        } else if (isInSharedDirectory(currentDir)) {
            std::cout << "  cd <directory>         - Change directory\n";
            std::cout << "  pwd                    - Print current directory\n";
            std::cout << "  ls                     - List directory contents\n";
            std::cout << "  cat <filename>         - Display file contents\n";
            std::cout << "  exit                   - Terminate the program\n";
            std::cout << "  help                   - Display this help message\n";
        } else {
            std::cout << "  cd <directory>         - Change directory\n";
            std::cout << "  pwd                    - Print current directory\n";
            std::cout << "  ls                     - List directory contents\n";
            std::cout << "  exit                   - Terminate the program\n";
            std::cout << "  help                   - Display this help message\n";
        }
    } else { // Admin user
        if (isAdminFSMode) {
            std::cout << "  cd <username>          - Enter a user's view (read-only)\n";
            std::cout << "  pwd                    - Print current directory (shows 'filesystem')\n";
            std::cout << "  ls                     - List all users\n";
            std::cout << "  adduser <username>     - Add a new user\n";
            std::cout << "  exit                   - Terminate the program\n";
            std::cout << "  help                   - Display this help message\n";
        } else if (!isAdminFSMode && viewedUser.empty()) {
            std::cout << "  cd <directory>         - Change directory (allowed: 'personal', 'shared')\n";
            std::cout << "  pwd                    - Print current directory\n";
            std::cout << "  ls                     - List directory contents\n";
            std::cout << "  adduser <username>     - Add a new user\n";
            std::cout << "  cd ..                  - Switch to filesystem view\n";
            std::cout << "  exit                   - Terminate the program\n";
            std::cout << "  help                   - Display this help message\n";
        } else if (!isAdminFSMode && !viewedUser.empty()) {
            std::cout << "  cd <directory>         - Change directory (read-only view)\n";
            std::cout << "  pwd                    - Print current directory (shows '/<username>')\n";
            std::cout << "  ls                     - List directory contents\n";
            std::cout << "  cat <filename>         - Display file contents\n";
            std::cout << "  cd ..                  - Return to filesystem view\n";
            std::cout << "  exit                   - Terminate the program\n";
            std::cout << "  help                   - Display this help message\n";
        }
    }
}

/**
 * start:
 * The main interactive loop that reads a command line, converts the command string to an enum,
 * and dispatches it via a switch-case statement.
 */
void InteractiveShell::start() {
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