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
    static const std::string GLOBAL_MAPPING_FILE = "global_mapping.json";

    // Load global mapping from "global_mapping.json"
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

    // Check if the virtual path is in the personal directory.
    bool isInPersonalDirectory(const std::string &vpath) {
        if (vpath == "/personal") return true;
        return (vpath.rfind("/personal/", 0) == 0);
    }

    // Check if the virtual path is in the shared directory.
    bool isInSharedDirectory(const std::string &vpath) {
        if (vpath == "/shared") return true;
        return (vpath.rfind("/shared/", 0) == 0);
    }

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

    // getCommand: maps input strings to Command enum.
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
        if (it != cmdMap.end()) return it->second;
        return CMD_UNKNOWN;
    }
}

namespace Shell {

static const std::string FILESYSTEM_DIR = "filesystem";

/**
 * InteractiveShell Constructor:
 * Sets up the shell for the logged-in user.
 */
InteractiveShell::InteractiveShell(const std::string &username)
    : currentUser(username), currentDir("/") {
    if (currentUser == "admin") {
        isAdminFSMode = false; // Admin starts in own root view.
        viewedUser.clear();
    } else {
        isAdminFSMode = false;
        viewedUser.clear();
    }
}

/**
 * resolvePath:
 * Converts a virtual path (e.g., "/shared/docs" or "/personal") to the corresponding hashed on-disk path.
 * For "shared", it consults global_mapping.json to get the shared folder hash for the active user.
 * If the global mapping does not contain a "shared" value, it falls back to using sha256("shared").
 * For "personal", it uses the hashed user root.
 */
std::string InteractiveShell::resolvePath(const std::string &vpath) {
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
    if (vpath.rfind("/shared", 0) == 0) {
        json global = loadGlobalMapping();
        std::string sharedHash;
        if (global.contains(activeUser) && global[activeUser].contains("shared"))
            sharedHash = global[activeUser]["shared"];
        else
            sharedHash = SecOps::SecurityOps::sha256("shared"); // fallback default

        std::string rootHash = global[activeUser]["root"];
        std::string base = FILESYSTEM_DIR + "/" + rootHash + "/" + sharedHash;
        // If the virtual path is exactly "/shared", return base.
        if(vpath == "/shared" || vpath == "shared")
            return base;
        std::istringstream iss(vpath);
        std::string token;
        // Skip the leading "/" and then "shared"
        std::getline(iss, token, '/'); // May be empty.
        std::getline(iss, token, '/'); // This should be "shared"
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
    } else {
        std::string base = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(activeUser);
        if (vpath.empty() || vpath == "/")
            return base;
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
 * Splits a virtual path by '/' and resolves "." and ".." components.
 */
std::string InteractiveShell::normalizePath(const std::string &path) {
    std::vector<std::string> parts;
    std::istringstream iss(path);
    std::string token;
    while (std::getline(iss, token, '/')) {
        if (token.empty() || token == ".") continue;
        if (token == "..") {
            if (!parts.empty()) parts.pop_back();
        } else {
            parts.push_back(token);
        }
    }
    std::string result = "/";
    for (size_t i = 0; i < parts.size(); i++) {
        result += parts[i];
        if (i + 1 < parts.size()) result += "/";
    }
    return result;
}

/**
 * handle_cd:
 * Implements the cd command:
 * - For normal users, navigates within personal/shared directories.
 * - For admin:
 *   * At admin's own root ("/"), "cd shared" or "cd personal" is allowed (creating the folder if it doesn’t exist).
 *   * "cd .." at admin's root switches to filesystem view.
 *   * In filesystem view, "cd <username>" lets admin view that user's directory.
 *   * When admin is viewing a user, "cd .." from "/" returns to filesystem view.
 */
void InteractiveShell::handle_cd(const std::string &arg) {
    if (arg.empty()) return;
    std::string target = arg;

    // Admin at own root (not in filesystem view) can type "cd shared" or "cd personal".
    if (currentUser == "admin" && !isAdminFSMode && viewedUser.empty() && currentDir == "/") {
        if (target == "..") {
            isAdminFSMode = true;
            currentDir = "/";
            return;
        }
        if (target == "shared" || target == "personal") {
            std::string userHash = SecOps::SecurityOps::sha256("admin");
            std::string dirHash = SecOps::SecurityOps::sha256(target);
            std::string realPath = FILESYSTEM_DIR + "/" + userHash + "/" + dirHash;
            if (!Ops::FileOps::directoryExists(realPath)) {
                Ops::FileOps::makeDirectory(realPath);
            }
            currentDir = "/" + target;
            return;
        }
    }

    // Normal users at root: if cd to "shared" or "personal", ensure folder exists.
    if (currentUser != "admin" && currentDir == "/") {
        if (target == "shared" || target == "personal") {
            std::string newPath = "/" + target;
            std::string realPath = resolvePath(newPath);
            if (!Ops::FileOps::directoryExists(realPath)) {
                Ops::FileOps::makeDirectory(realPath);
            }
            currentDir = newPath;
            return;
        }
    }

    // Admin in filesystem view.
    if (currentUser == "admin" && isAdminFSMode) {
        if (target == "..") {
            std::cout << "Already at filesystem view, can't go higher.\n";
            return;
        }
        if (target == "admin") {
            viewedUser.clear();
            isAdminFSMode = false;
            currentDir = "/";
            return;
        }
        std::string adminMappingFile = SecOps::SecurityOps::sha256("admin_mapping.json");
        std::string adminMappingPath = FILESYSTEM_DIR + "/" + adminMappingFile;
        json admMap;
        if (Ops::FileOps::fileExists(adminMappingPath)) {
            std::string adminPriv = UOps::UserOps::getUser("admin").privateKey;
            std::string key = adminPriv.substr(0, 32);
            std::string enc = Ops::FileOps::readFile(adminMappingPath);
            try {
                std::string dec = SecOps::SecurityOps::aesDecrypt(enc, key);
                admMap = json::parse(dec);
            } catch(...) {
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

    // Admin viewing a user: "cd .." from "/" returns to filesystem view.
    if (currentUser == "admin" && !viewedUser.empty()) {
        if (target == ".." && currentDir == "/") {
            viewedUser.clear();
            isAdminFSMode = true;
            currentDir = "/";
            return;
        }
    }

    // Normal users: prevent moving above root.
    if (currentUser != "admin" && currentDir == "/" && target == "..") {
        std::cout << "Access denied: You cannot move above your root.\n";
        return;
    }
    if (target == "/" && currentUser != "admin") {
        std::cout << "Access denied: You cannot cd to system root (/).\n";
        return;
    }

    // Perform normal path resolution.
    std::string newPath;
    if (target[0] == '/') newPath = normalizePath(target);
    else newPath = normalizePath(currentDir + "/" + target);

    std::string realPath = resolvePath(newPath);
    if (Ops::FileOps::directoryExists(realPath)) {
        currentDir = newPath;
    } else {
        std::cout << "Directory does not exist.\n";
    }
}

/**
 * handle_pwd:
 * - If admin is in filesystem view, prints "filesystem".
 * - If admin is viewing a user, prints "/<user>".
 * - Otherwise, prints currentDir.
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
 * Implements the ls command:
 * - If admin is in filesystem view, lists users from admin_mapping.json.
 * - If at a user's root ("/"), displays only:
 *      d -> .
 *      d -> ..
 *      personal
 *      shared
 * - In the shared folder, consults global_mapping.json to list shared file original names.
 * - In the personal folder, loads the user_file_mapping (via loadUserFileMappingPublic) and lists original names from the "entries" subobject.
 * - Otherwise, falls back to listing hashed names.
 */
void InteractiveShell::handle_ls() {
    // Admin in filesystem view.
    if (currentUser == "admin" && isAdminFSMode) {
        std::string adminMappingFile = SecOps::SecurityOps::sha256("admin_mapping.json");
        std::string adminMappingPath = FILESYSTEM_DIR + "/" + adminMappingFile;
        json admMap;
        if (Ops::FileOps::fileExists(adminMappingPath)) {
            std::string adminPriv = UOps::UserOps::getUser("admin").privateKey;
            std::string enc = Ops::FileOps::readFile(adminMappingPath);
            try {
                // Use hybridDecrypt with admin's private key to decrypt the mapping.
                std::string dec = SecOps::SecurityOps::hybridDecrypt(enc, adminPriv);
                admMap = json::parse(dec);
            } catch(...) {
                admMap = json::object();
            }
        }
        std::cout << "Users:\n";
        for (auto it = admMap.begin(); it != admMap.end(); ++it) {
            std::cout << " - " << it.key() << "\n";
        }
        return;
    }

    // At root for normal user or admin in own root view.
    if (currentDir == "/" || (currentUser == "admin" && isAdminFSMode && !viewedUser.empty())) {
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

    // In shared directory, list from global_mapping.
    if (isInSharedDirectory(currentDir)) {
        json global = loadGlobalMapping();
        if (global.contains(activeUser) && global[activeUser].contains("shared_files")) {
            for (auto &item : global[activeUser]["shared_files"].items()) {
                std::string displayName = item.value(); // original name
                std::cout << displayName << "\n";
            }
        }
        return;
    }
    // In personal directory, load user_file_mapping to list original names.
    if (isInPersonalDirectory(currentDir)) {
        json filemap = UOps::UserOps::loadUserFileMappingPublic(activeUser, UOps::UserOps::getUser(activeUser).privateKey);
        if (filemap.empty() || !filemap.contains("entries")) {
            for (auto &entry : std::filesystem::directory_iterator(realDir)) {
                std::cout << entry.path().filename().string() << "\n";
            }
            return;
        }
        for (auto &item : filemap["entries"].items()) {
            if (item.value().contains("name") && item.value().contains("type")) {
                std::string name = item.value()["name"];
                std::string type = item.value()["type"];
                if (type == "d")
                    std::cout << "d -> " << name << "\n";
                else
                    std::cout << "f -> " << name << "\n";
            }
        }
        return;
    }
}

/**
 * handle_cat:
 * Uses existing logic to display file contents.
 */
void InteractiveShell::handle_cat(const std::string &filename) {
    if (filename.empty()) return;
    if (!isInPersonalDirectory(currentDir) && !isInSharedDirectory(currentDir)) {
        std::cout << "Access denied: cat is allowed only in personal or shared directories.\n";
        return;
    }
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
    std::string hashedName;
    bool found = false;
    if (isInSharedDirectory(currentDir)) {
        json global = loadGlobalMapping();
        if (global.contains(activeUser) && global[activeUser].contains("shared_files")) {
            for (auto &it : global[activeUser]["shared_files"].items()) {
                if (it.value() == filename) {
                    hashedName = it.key();
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            std::cout << filename << " doesn't exist\n";
            return;
        }
        std::string realDir = resolvePath("/shared");
        std::string realFile = realDir + "/" + hashedName;
        if (!Ops::FileOps::fileExists(realFile)) {
            std::cout << filename << " doesn't exist on disk\n";
            return;
        }
        std::string userPriv = UOps::UserOps::getUser(activeUser).privateKey;
        try {
            std::string dec = SecOps::SecurityOps::hybridDecrypt(Ops::FileOps::readFile(realFile), userPriv);
            std::cout << dec << "\n";
        } catch(...) {
            std::cout << "Error decrypting file.\n";
        }
    } else {
        std::string hashed = SecOps::SecurityOps::sha256(filename);
        std::string realDir = resolvePath(currentDir);
        std::string realFile = realDir + "/" + hashed;
        if (!Ops::FileOps::fileExists(realFile)) {
            std::cout << filename << " doesn't exist\n";
            return;
        }
        std::string userPriv = UOps::UserOps::getUser(activeUser).privateKey;
        try {
            std::string dec = SecOps::SecurityOps::hybridDecrypt(Ops::FileOps::readFile(realFile), userPriv);
            std::cout << dec << "\n";
        } catch(...) {
            std::cout << "Error decrypting file.\n";
        }
    }
}

/**
 * handle_share:
 * Shares a file from the user's personal directory to another user's shared folder.
 * The process is as follows:
 * 1. Read the file from the current user's personal directory.
 * 2. Decrypt the file using hybridDecrypt with the source user's private key.
 * 3. Encrypt the plaintext using hybridEncrypt with the target user's public key.
 * 4. Write the resulting ciphertext into the target user's shared folder.
 * 5. Update global_mapping.json with the shared file entry.
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
        std::cout << "Share command allowed only in personal directory.\n";
        return;
    }
    std::string hashed = SecOps::SecurityOps::sha256(filename);
    std::string realDir = resolvePath(currentDir);
    std::string realFile = realDir + "/" + hashed;
    if (!Ops::FileOps::fileExists(realFile)) {
        std::cout << "File " << filename << " doesn't exist\n";
        return;
    }
    // First, decrypt the file using the source user's private key.
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
    std::string sourcePriv = UOps::UserOps::getUser(activeUser).privateKey;
    std::string plaintext;
    try {
        plaintext = SecOps::SecurityOps::hybridDecrypt(Ops::FileOps::readFile(realFile), sourcePriv);
    } catch(std::exception &e) {
        std::cout << "Error decrypting file for sharing.\n";
        return;
    }
    // Obtain the target user's public key from PUBLIC_KEYS_DIR.
    std::string targetPubFile = "public_keys/" + targetUser + "_public.pem";
    std::ifstream targetPubStream(targetPubFile);
    if (!targetPubStream) {
        std::cout << "Target user public key not found.\n";
        return;
    }
    std::stringstream targetPubBuf;
    targetPubBuf << targetPubStream.rdbuf();
    std::string targetPub = targetPubBuf.str();
    targetPubStream.close();
    // Encrypt the plaintext with the target user's public key using hybrid encryption.
    std::string newCipher;
    try {
        newCipher = SecOps::SecurityOps::hybridEncrypt(plaintext, targetPub);
    } catch(std::exception &e) {
        std::cout << "Error encrypting file for target user.\n";
        return;
    }
    // Update global mapping: add the shared file entry.
    json global = loadGlobalMapping();
    std::string hashedName = SecOps::SecurityOps::sha256(filename);
    global[targetUser]["shared_files"][hashedName] = filename;
    saveGlobalMapping(global);
    // Write the new ciphertext to the target user's shared folder.
    std::string targetSharedHash;
    if (global.contains(targetUser) && global[targetUser].contains("shared"))
        targetSharedHash = global[targetUser]["shared"];
    else
        targetSharedHash = SecOps::SecurityOps::sha256("shared");
    std::string targetDir = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(targetUser) + "/" + targetSharedHash;
    if (!Ops::FileOps::directoryExists(targetDir)) {
        Ops::FileOps::makeDirectory(targetDir);
    }
    std::string targetFile = targetDir + "/" + hashedName;
    Ops::FileOps::writeFile(targetFile, newCipher);
    std::cout << "Shared file with " << targetUser << " at /shared/" << filename << "\n";
}

/**
 * handle_mkdir:
 * Creates a new directory in the user's personal folder.
 */
void InteractiveShell::handle_mkdir(const std::string &dirname) {
    if (dirname.empty()) {
        std::cout << "Usage: mkdir <directory_name>\n";
        return;
    }
    if (currentUser == "admin" && (isAdminFSMode || !viewedUser.empty())) {
        std::cout << "Admin is read-only in user directories. mkdir not allowed.\n";
        return;
    }
    if (!isInPersonalDirectory(currentDir)) {
        std::cout << "mkdir allowed only in personal.\n";
        return;
    }
    std::string realDir = resolvePath(currentDir);
    if (!Ops::FileOps::directoryExists(realDir)) {
        std::cout << "Directory does not exist.\n";
        return;
    }
    std::string hashed = SecOps::SecurityOps::sha256(dirname);
    std::string newPath = realDir + "/" + hashed;
    if (Ops::FileOps::directoryExists(newPath)) {
        std::cout << "Directory already exists\n";
        return;
    }
    if (!Ops::FileOps::makeDirectory(newPath)) {
        std::cout << "Failed to create directory\n";
        return;
    }
    std::cout << "Created directory " << dirname << "\n";
    // Update the user_file_mapping "entries" for the active user.
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
    json mapping = UOps::UserOps::loadUserFileMappingPublic(activeUser, UOps::UserOps::getUser(activeUser).privateKey);
    mapping["entries"][hashed] = { {"name", dirname}, {"type", "d"} };
    if (!UOps::UserOps::saveUserFileMappingPublic(activeUser, UOps::UserOps::getUser(activeUser).publicKey, mapping)) {
        std::cout << "Warning: Failed to update directory mapping.\n";
    }
}

/**
 * handle_mkfile:
 * Creates a new file in the user's personal folder using hybrid encryption.
 * The file content is encrypted with a random AES key which is RSA-encrypted with the user's public key.
 * The resulting ciphertext is stored on disk, and the user_file_mapping is updated.
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
    if (!content.empty() && content[0] == ' ')
        content.erase(content.begin());
    if (!isInPersonalDirectory(currentDir)) {
        std::cout << "mkfile allowed only in personal.\n";
        return;
    }
    if (currentUser == "admin" && (isAdminFSMode || !viewedUser.empty())) {
        std::cout << "Admin is read-only in user directories. mkfile not allowed.\n";
        return;
    }
    std::string hashed = SecOps::SecurityOps::sha256(filename);
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;
    // Get target user's public key for hybrid encryption.
    std::string userPub = UOps::UserOps::getUser(activeUser).publicKey;
    std::string enc;
    try {
        enc = SecOps::SecurityOps::hybridEncrypt(content, userPub);
    } catch(...) {
        std::cout << "Error encrypting file.\n";
        return;
    }
    std::string realDir = resolvePath(currentDir);
    if (!Ops::FileOps::directoryExists(realDir)) {
        std::cout << "Directory does not exist.\n";
        return;
    }
    std::string realFile = realDir + "/" + hashed;
    Ops::FileOps::writeFile(realFile, enc);
    std::cout << "Created file " << filename << "\n";
    // Update the user_file_mapping "entries" for the active user.
    json mapping = UOps::UserOps::loadUserFileMappingPublic(activeUser, UOps::UserOps::getUser(activeUser).privateKey);
    mapping["entries"][hashed] = { {"name", filename}, {"type", "f"} };
    if (!UOps::UserOps::saveUserFileMappingPublic(activeUser, UOps::UserOps::getUser(activeUser).publicKey, mapping)) {
        std::cout << "Warning: Failed to update file mapping.\n";
    }
}

/**
 * handle_adduser:
 * Admin-only command to create a new user.
 */
void InteractiveShell::handle_adduser(const std::string &username) {
    if (currentUser != "admin") {
        std::cout << "Forbidden: only admin can add users\n";
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
    std::string userPriv = UOps::UserOps::getUser(username).privateKey;
    if (!UOps::UserOps::updateAdminMapping(username, userPriv, adminPriv)) {
        std::cout << "Failed to update admin mapping.\n";
    }
    std::cout << "User " << username << " created.\n";
}

/**
 * showHelp:
 * Displays available commands based on the user's role and current directory.
 */
void InteractiveShell::showHelp() {
    if (currentUser == "admin") {
        if (isAdminFSMode) {
            std::cout << "Commands in filesystem view:\n"
                      << "  cd <username>          - Enter that user's root (read-only). 'cd admin' => back to admin root.\n"
                      << "  ls                     - List all known users\n"
                      << "  pwd                    - Show 'filesystem'\n"
                      << "  adduser <user>         - Create new user\n"
                      << "  exit                   - Quit\n"
                      << "  help                   - Show help\n";
        } else if (!viewedUser.empty()) {
            std::cout << "Commands in user(" << viewedUser << ") view (read-only):\n"
                      << "  cd <dir>               - Navigate within the user's personal/shared folders\n"
                      << "  ls                     - List files with original names\n"
                      << "  cat <file>             - Display file contents\n"
                      << "  pwd                    - Show '/" << viewedUser << "'\n"
                      << "  cd ..                  - Return to filesystem view\n"
                      << "  exit                   - Quit\n"
                      << "  help                   - Show help\n";
        } else {
            std::cout << "Commands in admin's own root:\n"
                      << "  cd <dir>               - e.g., 'personal' or 'shared'\n"
                      << "  ls                     - List files/folders in root\n"
                      << "  cat <file>             - Display file contents\n"
                      << "  mkfile <file> <text>   - Create file in personal\n"
                      << "  mkdir <dir>            - Create directory in personal\n"
                      << "  share <file> <user>    - Share file\n"
                      << "  pwd                    - Show current directory\n"
                      << "  adduser <user>         - Create new user\n"
                      << "  cd ..                  - Switch to filesystem view (only if you're at '/')\n"
                      << "  exit                   - Quit\n"
                      << "  help                   - Show help\n";
        }
    } else {
        if (currentDir == "/") {
            std::cout << "Commands at user root:\n"
                      << "  cd personal            - Enter personal\n"
                      << "  cd shared              - Enter shared\n"
                      << "  ls                     - List contents (personal/shared)\n"
                      << "  pwd                    - Show current directory\n"
                      << "  exit                   - Quit\n"
                      << "  help                   - Show help\n";
        } else if (isInPersonalDirectory(currentDir)) {
            std::cout << "Commands in personal:\n"
                      << "  ls                     - List files/folders\n"
                      << "  cat <file>             - Display file contents\n"
                      << "  mkfile <file> <text>   - Create file\n"
                      << "  mkdir <dir>            - Create directory\n"
                      << "  share <file> <user>    - Share file with another user\n"
                      << "  cd ..                  - Return to '/'\n"
                      << "  pwd                    - Show current directory\n"
                      << "  exit                   - Quit\n"
                      << "  help                   - Show help\n";
        } else if (isInSharedDirectory(currentDir)) {
            std::cout << "Commands in shared:\n"
                      << "  ls                     - List shared files\n"
                      << "  cat <file>             - Display file contents\n"
                      << "  cd ..                  - Return to '/'\n"
                      << "  pwd                    - Show current directory\n"
                      << "  exit                   - Quit\n"
                      << "  help                   - Show help\n";
        } else {
            std::cout << "Commands in subdirectory:\n"
                      << "  ls, cat, cd, etc.\n"
                      << "  cd ..                  - Move up one level\n"
                      << "  exit                   - Quit\n"
                      << "  help                   - Show help\n";
        }
    }
}

/**
 * start:
 * The main interactive loop: reads commands and dispatches them.
 */
void InteractiveShell::start() {
    std::unordered_map<std::string,int> cmdMap = {
        {"cd", CMD_CD}, {"pwd", CMD_PWD}, {"ls", CMD_LS},
        {"cat", CMD_CAT}, {"share", CMD_SHARE}, {"mkdir", CMD_MKDIR},
        {"mkfile", CMD_MKFILE}, {"adduser", CMD_ADDUSER},
        {"exit", CMD_EXIT}, {"help", CMD_HELP}
    };
    while (true) {
        std::cout << "[" << currentUser << " @filesystem:" << currentDir << "]$ ";
        std::string line;
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;
        Command command = getCommand(cmd);
        switch (command) {
            case CMD_CD: {
                std::string arg;
                std::getline(iss, arg);
                if (!arg.empty() && arg[0]==' ') arg.erase(arg.begin());
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
                std::string fn;
                iss >> fn;
                handle_cat(fn);
                break;
            }
            case CMD_SHARE: {
                std::string rest;
                std::getline(iss, rest);
                if (!rest.empty() && rest[0]==' ') rest.erase(rest.begin());
                handle_share(rest);
                break;
            }
            case CMD_MKDIR: {
                std::string dn;
                iss >> dn;
                handle_mkdir(dn);
                break;
            }
            case CMD_MKFILE: {
                std::string rest;
                std::getline(iss, rest);
                if (!rest.empty() && rest[0]==' ') rest.erase(rest.begin());
                handle_mkfile(rest);
                break;
            }
            case CMD_ADDUSER: {
                std::string un;
                iss >> un;
                handle_adduser(un);
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