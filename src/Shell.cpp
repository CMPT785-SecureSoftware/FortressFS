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

    // load global mapping from "global_mapping.json"
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

    // isInPersonalDirectory => check if path is "/personal" or starts with "/personal/"
    bool isInPersonalDirectory(const std::string &vpath) {
        if (vpath == "/personal") return true;
        return (vpath.rfind("/personal/", 0) == 0);
    }

    // isInSharedDirectory => check if path is "/shared" or starts with "/shared/"
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
 * Constructor remains the same:
 * - Admin starts in his own view (isAdminFSMode=false, viewedUser="").
 * - Normal user is also in "/" with isAdminFSMode=false.
 */
InteractiveShell::InteractiveShell(const std::string &username)
    : currentUser(username), currentDir("/") {
    if (currentUser == "admin") {
        isAdminFSMode = false; // start in own view
        viewedUser.clear();
    } else {
        isAdminFSMode = false;
        viewedUser.clear();
    }
}

/**
 * resolvePath:
 * Converts a virtual path ("/shared/docs") to the hashed on-disk path
 * using either currentUser or viewedUser if admin is in user view.
 * - If path starts with "/shared", it consults global_mapping to find
 *   <hash_of_user>'s <hash_of("shared")> directory.
 * - Otherwise it uses a fallback approach for personal or subdirectories.
 */
std::string InteractiveShell::resolvePath(const std::string &vpath) {
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;

    // If path starts with "/shared", use global mapping to find the shared folder
    if (vpath.rfind("/shared", 0) == 0) {
        json global = loadGlobalMapping();
        std::string sharedHash = global[activeUser]["shared"];
        std::string base = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(activeUser) + "/" + sharedHash;
        std::istringstream iss(vpath);
        std::string token;
        std::string path = base;
        std::getline(iss, token, '/'); // skip "shared"
        while (std::getline(iss, token, '/')) {
            if (token.empty() || token == ".") continue;
            if (token == "..") {
                size_t pos = path.find_last_of('/');
                if (pos != std::string::npos) path = path.substr(0, pos);
            } else {
                path += "/" + SecOps::SecurityOps::sha256(token);
            }
        }
        return path;
    } else {
        // else handle personal or root
        std::string base = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(activeUser);
        if (vpath.empty() || vpath == "/") {
            return base;
        }
        std::istringstream iss(vpath);
        std::string token;
        std::string path = base;
        while (std::getline(iss, token, '/')) {
            if (token.empty() || token == ".") continue;
            if (token == "..") {
                size_t pos = path.find_last_of('/');
                if (pos != std::string::npos) path = path.substr(0, pos);
            } else {
                path += "/" + SecOps::SecurityOps::sha256(token);
            }
        }
        return path;
    }
}

/**
 * normalizePath:
 * Splits on '/', handles '.' and '..'
 * so "cd ../foo" moves up then down, etc.
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
 * Updated logic:
 *  1) The "cd" command is available in all directories (no restriction).
 *  2) We consult:
 *     - admin_mapping.json if we are in filesystem view and trying "cd <username>".
 *     - global_mapping.json if we do "cd shared" from user root or subdir to ensure shared is valid.
 *  3) Admin can do "cd .." from his own root "/" => filesystem view. If in filesystem view, "cd <username>" => that user's directory. "cd admin" => revert to admin's own root.
 *  4) Normal users can't go above "/" (their root).
 */
void InteractiveShell::handle_cd(const std::string &arg) {
    if (arg.empty()) return;
    std::string target = arg;

    // Admin special logic:
    // If admin is in his own root ("/"), "cd .." => filesystem view
    if (currentUser == "admin" && !isAdminFSMode && viewedUser.empty()) {
        if (target == "..") {
            // Switch to filesystem view
            isAdminFSMode = true;
            currentDir = "/";
            return;
        }
    }
    // If admin is in filesystem view => "cd <username>" => we see if it's "admin" or some other user
    if (currentUser == "admin" && isAdminFSMode) {
        if (target == "..") {
            std::cout << "Already at filesystem view, can't go higher.\n";
            return;
        }
        // check admin_mapping.json
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
        // If user typed "cd admin" => go back to admin's own root
        if (target == "admin") {
            // revert to admin's root, isAdminFSMode=false
            viewedUser.clear();
            isAdminFSMode = false;
            currentDir = "/";
            return;
        }
        // else see if it's another user
        if (admMap.contains(target)) {
            // enter that user's directory read-only
            viewedUser = target;
            isAdminFSMode = false;
            currentDir = "/";
            return;
        } else {
            std::cout << "User " << target << " not found in admin mapping.\n";
            return;
        }
    }
    // If admin is viewing another user => "cd .." => go back to filesystem
    if (currentUser == "admin" && !viewedUser.empty()) {
        if (target == "..") {
            viewedUser.clear();
            isAdminFSMode = true;
            currentDir = "/";
            return;
        }
    }

    // For normal user or admin in own root do normal resolution
    if (target == "/" && currentUser != "admin") {
        std::cout << "Access denied: You cannot cd to system root (/).\n";
        return;
    }
    std::string newPath;
    if (target[0] == '/') newPath = normalizePath(target);
    else newPath = normalizePath(currentDir + "/" + target);

    // normal user can't go above "/"
    if (currentUser != "admin" && currentDir == "/" && target == "..") {
        std::cout << "Access denied: You cannot move above your root.\n";
        return;
    }

    // Now check if the real path is valid
    std::string realPath = resolvePath(newPath);
    if (Ops::FileOps::directoryExists(realPath)) {
        currentDir = newPath;
    } else {
        std::cout << "Directory does not exist.\n";
    }
}

/**
 * handle_pwd:
 * - admin FS => "filesystem"
 * - admin in user => "/<user>"
 * - otherwise => currentDir
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
 * - admin in FS => list admin_mapping
 * - if at "/" => show . .. personal shared
 * - if in shared => read from global
 * - if in personal => fallback
 */
void InteractiveShell::handle_ls() {
    // (unchanged logic)
    // ...
    // (No changes needed for the cd improvements.)
    // ...
    // Below is the rest of the function exactly as before:
    
    // admin FS
    if (currentUser == "admin" && isAdminFSMode) {
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
        std::cout << "Users:\n";
        for (auto it = admMap.begin(); it != admMap.end(); ++it) {
            std::cout << " - " << it.key() << "\n";
        }
        return;
    }
    // if at "/" (root) and not in FS/admin user view => show personal, shared
    if (currentDir == "/" && (currentUser != "admin" || (currentUser=="admin" && !isAdminFSMode && viewedUser.empty()))) {
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
    std::string activeUser = (currentUser=="admin" && !viewedUser.empty()) ? viewedUser : currentUser;
    if (isInSharedDirectory(currentDir)) {
        json global = loadGlobalMapping();
        if (global.contains(activeUser) && global[activeUser].contains("shared_files")) {
            for (auto &item : global[activeUser]["shared_files"].items()) {
                std::string displayName = item.value();
                std::cout << displayName << "\n";
            }
        }
        return;
    }
    for (auto &entry : std::filesystem::directory_iterator(realDir)) {
        std::cout << entry.path().filename().string() << "\n";
    }
}

/**
 * handle_cat, handle_share, handle_mkdir, handle_mkfile, handle_adduser, showHelp
 * remain unchanged with respect to cd logic.
 * No additional changes needed. 
 * The following definitions are left as-is to preserve existing comments and logic.
 */

void InteractiveShell::handle_cat(const std::string &filename) {
    // (unchanged)
    if (filename.empty()) return;
    if (!isInPersonalDirectory(currentDir) && !isInSharedDirectory(currentDir)) {
        std::cout << "Access denied: cat is allowed only in personal or shared directories.\n";
        return;
    }
    std::string activeUser = (currentUser=="admin" && !viewedUser.empty()) ? viewedUser : currentUser;
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
        std::string userKey = UOps::UserOps::getUser(activeUser).privateKey;
        std::string aesKey = userKey.substr(0,32);
        std::string enc = Ops::FileOps::readFile(realFile);
        try {
            std::string dec = SecOps::SecurityOps::aesDecrypt(enc, aesKey);
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
        std::string userKey = UOps::UserOps::getUser(activeUser).privateKey;
        std::string aesKey = userKey.substr(0, 32);
        std::string enc = Ops::FileOps::readFile(realFile);
        try {
            std::string dec = SecOps::SecurityOps::aesDecrypt(enc, aesKey);
            std::cout << dec << "\n";
        } catch(...) {
            std::cout << "Error decrypting file.\n";
        }
    }
}

void InteractiveShell::handle_share(const std::string &args) {
    // (unchanged)
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
    json global = loadGlobalMapping();
    if (!global.contains(targetUser)) {
        std::cout << "User " << targetUser << " doesn't exist in global mapping.\n";
        return;
    }
    std::string data = Ops::FileOps::readFile(realFile);
    std::string hashedName = SecOps::SecurityOps::sha256(filename);
    global[targetUser]["shared_files"][hashedName] = filename;
    saveGlobalMapping(global);

    std::string targetSharedHash = global[targetUser]["shared"];
    std::string targetDir = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(targetUser) + "/" + targetSharedHash;
    Ops::FileOps::makeDirectory(targetDir);
    std::string targetFile = targetDir + "/" + hashedName;
    Ops::FileOps::writeFile(targetFile, data);

    std::cout << "Shared file with " << targetUser << " at /shared/" << filename << "\n";
}

void InteractiveShell::handle_mkdir(const std::string &dirname) {
    // (unchanged)
    if (dirname.empty()) {
        std::cout << "Usage: mkdir <directory_name>\n";
        return;
    }
    if (currentUser=="admin" && (isAdminFSMode || !viewedUser.empty())) {
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
}

void InteractiveShell::handle_mkfile(const std::string &args) {
    // (unchanged)
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
    if (currentUser=="admin" && (isAdminFSMode || !viewedUser.empty())) {
        std::cout << "Admin is read-only in user directories. mkfile not allowed.\n";
        return;
    }
    std::string hashed = SecOps::SecurityOps::sha256(filename);
    std::string activeUser = (currentUser=="admin" && !viewedUser.empty()) ? viewedUser : currentUser;
    std::string userKey = UOps::UserOps::getUser(activeUser).privateKey;
    std::string aesKey = userKey.substr(0, 32);
    std::string enc;
    try {
        enc = SecOps::SecurityOps::aesEncrypt(content, aesKey);
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
}

void InteractiveShell::handle_adduser(const std::string &username) {
    // (unchanged)
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
    // store user's private key in admin mapping
    std::string adminPriv = UOps::UserOps::getUser("admin").privateKey;
    std::string userPriv = UOps::UserOps::getUser(username).privateKey;
    if (!UOps::UserOps::updateAdminMapping(username, userPriv, adminPriv)) {
        std::cout << "Failed to update admin mapping.\n";
    }
    std::cout << "User " << username << " created.\n";
}

/**
 * showHelp:
 * Provide commands based on user role / directory
 * (No changes needed for the revised cd logic, but we keep the existing commentary.)
 */
void InteractiveShell::showHelp() {
    if (currentUser=="admin") {
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
                      << "  cd <dir>               - Move around read-only\n"
                      << "  ls                     - List decrypted\n"
                      << "  cat <file>             - Show file content\n"
                      << "  pwd                    - Show '/" << viewedUser << "'\n"
                      << "  cd ..                  - Return to filesystem view\n"
                      << "  exit                   - Quit\n"
                      << "  help                   - Show help\n";
        } else {
            std::cout << "Commands in admin's own root:\n"
                      << "  cd <dir>               - e.g. 'personal' or 'shared'\n"
                      << "  ls                     - List\n"
                      << "  cat <file>             - Show file\n"
                      << "  mkfile <file> <text>   - Create file in personal\n"
                      << "  mkdir <dir>            - Create directory in personal\n"
                      << "  share <file> <user>    - Share file\n"
                      << "  pwd                    - Print\n"
                      << "  adduser <user>         - Create new user\n"
                      << "  cd ..                  - Switch to filesystem view\n"
                      << "  exit                   - Quit\n"
                      << "  help                   - Show help\n";
        }
    } else {
        // normal user
        if (currentDir=="/") {
            std::cout << "Commands at user root:\n"
                      << "  cd personal            - Enter personal\n"
                      << "  cd shared              - Enter shared\n"
                      << "  ls                     - Show personal, shared\n"
                      << "  pwd                    - Print dir\n"
                      << "  exit                   - Quit\n"
                      << "  help                   - Show help\n";
        } else if (isInPersonalDirectory(currentDir)) {
            std::cout << "Commands in personal:\n"
                      << "  ls                     - List\n"
                      << "  cat <file>             - Show file\n"
                      << "  mkfile <file> <text>   - Create file\n"
                      << "  mkdir <dir>            - Create directory\n"
                      << "  share <file> <user>    - Share file\n"
                      << "  cd ..                  - Return to '/'\n"
                      << "  pwd                    - Print dir\n"
                      << "  exit                   - Quit\n"
                      << "  help                   - Show help\n";
        } else if (isInSharedDirectory(currentDir)) {
            std::cout << "Commands in shared:\n"
                      << "  ls                     - List shared files\n"
                      << "  cat <file>             - Show file\n"
                      << "  cd ..                  - Return to '/'\n"
                      << "  pwd                    - Print dir\n"
                      << "  exit                   - Quit\n"
                      << "  help                   - Show help\n";
        } else {
            std::cout << "Commands in subdirectory:\n"
                      << "  ls, cat, cd, etc.\n"
                      << "  cd ..                  - go up\n"
                      << "  exit                   - quit\n"
                      << "  help                   - help\n";
        }
    }
}

/**
 * start:
 * The main interactive loop 
 * (unchanged, so no additional changes here, but we keep the existing logic and comments).
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
        int command = CMD_UNKNOWN;
        if (cmdMap.find(cmd)!=cmdMap.end()) {
            command=cmdMap[cmd];
        }
        switch(command){
            case CMD_CD: {
                std::string arg;
                std::getline(iss, arg);
                if(!arg.empty()&& arg[0]==' ') arg.erase(arg.begin());
                handle_cd(arg);
                break;
            }
            case CMD_PWD:
                handle_pwd();
                break;
            case CMD_LS:
                handle_ls();
                break;
            case CMD_CAT:{
                std::string fn;
                iss>>fn;
                handle_cat(fn);
                break;
            }
            case CMD_SHARE:{
                std::string rest;
                std::getline(iss, rest);
                if(!rest.empty()&& rest[0]==' ') rest.erase(rest.begin());
                handle_share(rest);
                break;
            }
            case CMD_MKDIR:{
                std::string dn;
                iss>>dn;
                handle_mkdir(dn);
                break;
            }
            case CMD_MKFILE:{
                std::string rest;
                std::getline(iss, rest);
                if(!rest.empty()&& rest[0]==' ') rest.erase(rest.begin());
                handle_mkfile(rest);
                break;
            }
            case CMD_ADDUSER:{
                std::string un;
                iss>>un;
                handle_adduser(un);
                break;
            }
            case CMD_EXIT:
                return;
            case CMD_HELP:
                showHelp();
                break;
            default:
                std::cout<<"Unknown command. Type 'help' for usage.\n";
                break;
        }
    }
}

} // namespace Shell