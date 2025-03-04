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

static const std::string FILESYSTEM_DIR   = "filesystem";
static const std::string PRIVATE_KEYS_DIR = "private_keys";
static const std::string ADMIN_KEYS_DIR   = "admin_keys";
static const std::string PUBLIC_KEYS_DIR  = "public_keys";
static const std::string ADMIN_KEYFILE    = "admin_keyfile.pem";

/**
 * initFortress:
 * - Creates needed directories.
 * - If admin_keyfile.pem not found => first run => generate "admin_keyfile.pem" + "admin_public.pem", hashed directories for admin, exit(0).
 * - If found => do nothing.
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
        // first run => create admin
        std::cout << "No admin keyfile found. Generating admin keypair...\n";
        if (!SecOps::SecurityOps::generateRSAKeyPair("admin")) {
            std::cerr << "Failed to generate admin key pair\n";
            exit(1);
        }
        // read "admin_keyfile.pem"
        std::ifstream ifs("admin_keyfile.pem");
        if (!ifs) {
            std::cerr << "Failed to read admin_keyfile.pem\n";
            exit(1);
        }
        std::stringstream ss;
        ss << ifs.rdbuf();
        std::string adminPriv = ss.str();
        ifs.close();

        // move it to adminKeys dir
        std::ofstream ofs(adminPath, std::ios::binary);
        if (!ofs) {
            std::cerr << "Failed to write " << adminPath << "\n";
            exit(1);
        }
        ofs << adminPriv;
        ofs.close();
        std::filesystem::remove("admin_keyfile.pem");

        // rename admin_public.pem => public_keys/admin_public.pem
        std::string pubSrc = "admin_public.pem";
        std::string pubDst = PUBLIC_KEYS_DIR + "/admin_public.pem";
        std::filesystem::rename(pubSrc, pubDst);

        // create hashed "admin" folder
        std::string adminDir = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256("admin");
        std::filesystem::create_directories(adminDir);
        std::string personalDir = adminDir + "/" + SecOps::SecurityOps::sha256("personal");
        std::string sharedDir   = adminDir + "/" + SecOps::SecurityOps::sha256("shared");
        std::filesystem::create_directories(personalDir);
        std::filesystem::create_directories(sharedDir);

        // put admin in memory
        UOps::UserOps::users["admin"] = UOps::User{"admin", adminPriv, "", true};

        // create admin's per-user mapping
        json adminMapping;
        adminMapping["username"] = "admin";
        adminMapping["files"]    = json::object();
        std::string mappingStr = adminMapping.dump(4);

        // read the new admin_public.pem
        std::ifstream pubF(pubDst);
        if (!pubF) {
            std::cerr << "Failed to read " << pubDst << "\n";
            exit(1);
        }
        std::stringstream pubSS;
        pubSS << pubF.rdbuf();
        std::string adminPub = pubSS.str();
        pubF.close();

        // encrypt & store in adminDir
        std::string mappingFileName = SecOps::SecurityOps::sha256("admin_file_mapping.json");
        std::string mappingFilePath = adminDir + "/" + mappingFileName;
        std::string encMapping = SecOps::SecurityOps::rsaEncrypt(mappingStr, adminPub);
        Ops::FileOps::writeFile(mappingFilePath, encMapping);

        // update global mapping
        UOps::UserOps::mapUser("admin", adminPub);

        // create admin_mapping.json => AES with adminPriv
        json admMap;
        admMap["admin"] = adminPriv;
        std::string admMapStr = admMap.dump(4);
        std::string key = adminPriv.substr(0, 32); 
        std::string encAdmMap = SecOps::SecurityOps::aesEncrypt(admMapStr, key);
        std::string adminMappingFile = SecOps::SecurityOps::sha256("admin_mapping.json");
        std::string adminMappingPath = FILESYSTEM_DIR + "/" + adminMappingFile;
        Ops::FileOps::writeFile(adminMappingPath, encAdmMap);

        std::cout << "Admin user created.\n";
        std::cout << "Admin private key stored in " << adminPath << "\n";
        std::cout << "Admin public key stored in " << pubDst << "\n";
        std::cout << "Please secure your admin keyfile.\n";
        std::cout << "Exiting now. Next run: ./<program> <admin_keyfile_path>\n";
        exit(0);
    }

    // subsequent run => do nothing
}

int main(int argc, char** argv) {
    // ensure fortress structure, possibly create admin
    initFortress();

    // subsequent run => need keyfile
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <keyfile_name>\n";
        return 1;
    }

    // Attempt login
    std::string keyfileName = argv[1];
    std::string user = UOps::UserOps::login(keyfileName);
    if (user.empty()) {
        std::cout << "Invalid keyfile\n";
        return 1;
    }
    std::cout << "Logged in as " << user << "\n";

    // ensure hashed personal & shared exist
    std::string userDir = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(user);
    if (!std::filesystem::exists(userDir)) {
        std::filesystem::create_directories(userDir);
    }
    std::string personalDir = userDir + "/" + SecOps::SecurityOps::sha256("personal");
    if (!std::filesystem::exists(personalDir)) {
        std::filesystem::create_directories(personalDir);
    }
    std::string sharedDir = userDir + "/" + SecOps::SecurityOps::sha256("shared");
    if (!std::filesystem::exists(sharedDir)) {
        std::filesystem::create_directories(sharedDir);
    }

    Shell::InteractiveShell shell(user);
    shell.start();

    return 0;
}