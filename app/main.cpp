#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include "UserOps.h"
#include "Shell.h"
#include "FileOps.h"
#include "SecurityOps.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

static const std::string FILESYSTEM_DIR = "filesystem";
static const std::string PRIVATE_KEYS_DIR = "private_keys";
static const std::string ADMIN_KEYS_DIR = "admin_keys";
static const std::string PUBLIC_KEYS_DIR = "public_keys";
static const std::string ADMIN_KEYFILE = "admin_keyfile.pem";

/**
 * initFortress:
 * - Creates the necessary folder structure.
 * - If the admin keyfile does not exist, generates admin keys,
 *   creates admin's hashed directories, creates admin's per-user mapping file
 *   (named as sha256("admin_file_mapping.json")) in admin's root,
 *   updates the global mapping, and creates admin_mapping.json (filename = sha256("admin_mapping.json"))
 *   in FILESYSTEM_DIR. The admin_mapping file maps usernames to their private keys (encrypted using AES).
 * - Then exits.
 */
static void initFortress() {
    if (!std::filesystem::exists(FILESYSTEM_DIR))
        std::filesystem::create_directories(FILESYSTEM_DIR);
    
    if (!std::filesystem::exists(PRIVATE_KEYS_DIR))
        std::filesystem::create_directories(PRIVATE_KEYS_DIR);
    
    if (!std::filesystem::exists(ADMIN_KEYS_DIR))
        std::filesystem::create_directories(ADMIN_KEYS_DIR);
    
    if (!std::filesystem::exists(PUBLIC_KEYS_DIR))
        std::filesystem::create_directories(PUBLIC_KEYS_DIR);
    
    std::string adminPath = ADMIN_KEYS_DIR + "/" + ADMIN_KEYFILE;
    if (!std::filesystem::exists(adminPath)) {
        if (!SecOps::SecurityOps::generateRSAKeyPair("admin")) {
            std::cerr << "Failed to generate admin key pair\n";
            exit(1);
        }
        std::ifstream ifs("admin_private.pem");
        std::stringstream ss;
        ss << ifs.rdbuf();
        std::string adminPriv = ss.str();
        std::ofstream ofs(adminPath, std::ios::binary);
        ofs << adminPriv;
        ofs.close();
        std::filesystem::remove("admin_private.pem");
        std::string pubSrc = "admin_public.pem";
        std::string pubDst = PUBLIC_KEYS_DIR + "/admin_public.pem";
        std::filesystem::rename(pubSrc, pubDst);
        // Create admin's hashed directories.
        std::string adminDir = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256("admin");
        std::string personalDir = adminDir + "/" + SecOps::SecurityOps::sha256("personal");
        std::string sharedDir = adminDir + "/" + SecOps::SecurityOps::sha256("shared");
        std::filesystem::create_directories(adminDir);
        std::filesystem::create_directories(personalDir);
        std::filesystem::create_directories(sharedDir);
        UOps::UserOps::users["admin"] = UOps::User{"admin", adminPriv, "", true};
        // Create admin's per-user mapping file.
        json adminMapping;
        adminMapping["username"] = "admin";
        adminMapping["files"] = json::object();
        std::string mappingStr = adminMapping.dump(4);
        std::ifstream pubFile(pubDst);
        std::stringstream pubSS;
        pubSS << pubFile.rdbuf();
        std::string adminPub = pubSS.str();
        std::string mappingFileName = SecOps::SecurityOps::sha256("admin_file_mapping.json");
        std::string mappingFilePath = adminDir + "/" + mappingFileName;
        std::string encryptedMapping = SecOps::SecurityOps::rsaEncrypt(mappingStr, adminPub);
        Ops::FileOps::writeFile(mappingFilePath, encryptedMapping);
        // Update global mapping for admin.
        UOps::UserOps::mapUser("admin", adminPub);
        // Create admin_mapping.json in FILESYSTEM_DIR.
        json admMap;
        admMap["admin"] = adminPriv;  // Initially only admin is present.
        std::string admMapStr = admMap.dump(4);
        std::string key = adminPriv.substr(0, 32);
        std::string encryptedAdmMap = SecOps::SecurityOps::aesEncrypt(admMapStr, key);
        std::string adminMappingFile = SecOps::SecurityOps::sha256("admin_mapping.json");
        std::string adminMappingPath = FILESYSTEM_DIR + "/" + adminMappingFile;
        Ops::FileOps::writeFile(adminMappingPath, encryptedAdmMap);
        std::cout << "Admin user created.\n";
        std::cout << "Admin private key stored in " << adminPath << "\n";
        std::cout << "Admin public key stored in " << pubDst << "\n";
        std::cout << "Please secure your admin keyfile. Exiting now. (Re-run the program with a valid keyfile.)\n";
        exit(0);
    }
}

/**
 * main:
 * - Initializes the fortress.
 * - Expects a keyfile as a command-line argument.
 * - Logs in the user and launches the interactive shell.
 */
int main(int argc, char **argv) {
    initFortress();

    if (argc < 2) {
        std::cout << "Usage: ./fileserver <keyfile_name>\n";
        return 1;
    }

    std::string keyfileName = argv[1];
    std::string user = UOps::UserOps::login(keyfileName);
    if (user.empty()) {
        std::cout << "Invalid keyfile\n";
        return 1;
    }
    std::cout << "Logged in as " << user << "\n";

    std::string userDir = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(user);
    if (!std::filesystem::exists(userDir)) {
        std::string personalDir = userDir + "/" + SecOps::SecurityOps::sha256("personal");
        std::string sharedDir = userDir + "/" + SecOps::SecurityOps::sha256("shared");
        std::filesystem::create_directories(userDir);
        std::filesystem::create_directories(personalDir);
        std::filesystem::create_directories(sharedDir);
    }

    Shell::InteractiveShell shell(user);
    shell.start();

    return 0;
}