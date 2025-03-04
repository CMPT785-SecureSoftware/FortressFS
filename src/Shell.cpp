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
 * InteractiveShell constructor:
 * - If user is "admin", isAdminFSMode=false, viewedUser=""
 * - Otherwise normal user
 */
InteractiveShell::InteractiveShell(const std::string &username)
    : currentUser(username), currentDir("/") {
    if (currentUser == "admin") {
        isAdminFSMode = false;
        viewedUser.clear();
    } else {
        isAdminFSMode = false;
        viewedUser.clear();
    }
}

/**
 * resolvePath:
 * If path is "/shared" or starts with "/shared", we consult global_mapping to find
 * <hash_of("shared")>. Otherwise, it's personal or subdirectories. The resulting
 * real path is under filesystem/<hash_of_user> or <hash_of_user>/<hash_of("shared")>.
 */
std::string InteractiveShell::resolvePath(const std::string &vpath) {
    std::string activeUser = (currentUser == "admin" && !viewedUser.empty()) ? viewedUser : currentUser;

    // if vpath starts with "/shared"
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
        // personal or subdir
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
 * Splits on '/', interprets '.' and '..'
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
 * - If admin is at root "/" (not filesystem mode, not viewing user) and user does "cd shared" or "cd personal",
 *   we ensure hashed directory physically exists, then set currentDir to "/shared" or "/personal".
 * - If admin is at root "/" and does "cd ..", we go to filesystem mode.
 * - If admin in filesystem => "cd <username>" => see if user in admin_mapping, else error.
 * - If admin is viewing user => "cd .." at root => back to filesystem.
 * - Otherwise normal path resolution.
 */
void InteractiveShell::handle_cd(const std::string &arg) {
    if (arg.empty()) return;
    std::string target = arg;

    // 1) If admin at own root "/" and not in filesystem or user view
    if (currentUser == "admin" && !isAdminFSMode && viewedUser.empty() && currentDir == "/") {
        // a) "cd .." => filesystem mode
        if (target == "..") {
            isAdminFSMode = true;
            currentDir = "/";
            return;
        }
        // b) "cd shared" or "cd personal"
        if (target == "shared" || target == "personal") {
            // We'll forcibly ensure the hashed directory exists, then do currentDir = "/shared"
            std::string userHash = SecOps::SecurityOps::sha256("admin");
            std::string dirHash = SecOps::SecurityOps::sha256(target); // "shared" or "personal"
            std::string realPath = FILESYSTEM_DIR + "/" + userHash + "/" + dirHash;
            if (!Ops::FileOps::directoryExists(realPath)) {
                // Create it if missing
                Ops::FileOps::makeDirectory(realPath);
            }
            // Now set currentDir to "/shared" or "/personal"
            std::string newDir = "/" + target; 
            currentDir = newDir;
            return;
        }
    }

    // 2) If admin is in filesystem mode => "cd <username>"
    if (currentUser == "admin" && isAdminFSMode) {
        if (target == "..") {
            std::cout << "Already at filesystem view, can't go higher.\n";
            return;
        }
        // "cd admin" => revert to admin root
        if (target == "admin") {
            viewedUser.clear();
            isAdminFSMode = false;
            currentDir = "/";
            return;
        }
        // else check admin_mapping for <username>
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

    // 3) If admin is viewing a user => "cd .." from user root => back to filesystem
    if (currentUser == "admin" && !viewedUser.empty()) {
        if (target == ".." && currentDir == "/") {
            viewedUser.clear();
            isAdminFSMode = true;
            currentDir = "/";
            return;
        }
    }

    // 4) Normal path resolution for everything else
    // If a normal user is at "/" and does "cd ..", block
    if (currentUser != "admin" && currentDir == "/" && target == "..") {
        std::cout << "Access denied: You cannot move above your root.\n";
        return;
    }
    // block normal user from "cd /"
    if (target == "/" && currentUser != "admin") {
        std::cout << "Access denied: You cannot cd to system root (/).\n";
        return;
    }

    // generate new virtual path
    std::string newPath;
    if (target[0] == '/') newPath = normalizePath(target);
    else newPath = normalizePath(currentDir + "/" + target);

    // see if physically exists
    std::string realPath = resolvePath(newPath);
    if (Ops::FileOps::directoryExists(realPath)) {
        currentDir = newPath;
    } else {
        std::cout << "Directory does not exist.\n";
    }
}

/**
 * handle_pwd, handle_ls, handle_cat, etc. are unchanged
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

void InteractiveShell::handle_ls() {
    // (same as before)
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

void InteractiveShell::handle_cat(const std::string &filename) {
    // (same as before)
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
    // (same as before)
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
    // (same as before)
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
    // (same as before)
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

/**
 * handle_adduser:
 * - admin only
 * - calls createUser
 * - update admin mapping
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
                      << "  cd ..                  - Return to filesystem view if at '/'\n"
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
                      << "  cd ..                  - Switch to filesystem view (only if you're at '/')\n"
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
        if (cmdMap.find(cmd)!=cmdMap.end()){
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