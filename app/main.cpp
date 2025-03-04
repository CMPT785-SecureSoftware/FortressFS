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
 * - If the admin keyfile does not exist (first run), generates admin keys, creates admin's hashed directories,
 *   creates admin's per-user mapping file, updates the global mapping, writes out admin_mapping.json,
 *   then prints instructions and **exits**.
 * - On subsequent runs (when admin keyfile already exists), does nothing except ensure directories exist.
 */
static void initFortress() {
    // Ensure the main directories exist.
    if (!std::filesystem::exists(FILESYSTEM_DIR))
        std::filesystem::create_directories(FILESYSTEM_DIR);

    if (!std::filesystem::exists(PRIVATE_KEYS_DIR))
        std::filesystem::create_directories(PRIVATE_KEYS_DIR);

    if (!std::filesystem::exists(ADMIN_KEYS_DIR))
        std::filesystem::create_directories(ADMIN_KEYS_DIR);

    if (!std::filesystem::exists(PUBLIC_KEYS_DIR))
        std::filesystem::create_directories(PUBLIC_KEYS_DIR);

    // Check if admin keyfile exists. If not, this is the first run.
    std::string adminPath = ADMIN_KEYS_DIR + "/" + ADMIN_KEYFILE;
    if (!std::filesystem::exists(adminPath)) {
        // First run: generate admin keys and exit.
        std::cout << "No admin keyfile found. Generating admin keypair...\n";
        if (!SecOps::SecurityOps::generateRSAKeyPair("admin")) {
            std::cerr << "Failed to generate admin key pair\n";
            exit(1);
        }
        // Read admin_private.pem
        std::ifstream ifs("admin_keyfile.pem");
        if (!ifs) {
            std::cerr << "Failed to open newly generated admin_keyfile.pem\n";
            exit(1);
        }
        std::stringstream ss;
        ss << ifs.rdbuf();
        std::string adminPriv = ss.str();
        ifs.close();

        // Write admin private key into admin_keys/admin_keyfile.pem
        std::ofstream ofs(adminPath, std::ios::binary);
        if (!ofs) {
            std::cerr << "Failed to write admin keyfile\n";
            exit(1);
        }
        ofs << adminPriv;
        ofs.close();
        // Remove the original unencrypted private file.
        std::filesystem::remove("admin_keyfile.pem");

        // Move admin public key to public_keys/admin_public.pem
        std::string pubSrc = "admin_public.pem";
        std::string pubDst = PUBLIC_KEYS_DIR + "/admin_public.pem";
        std::filesystem::rename(pubSrc, pubDst);

        // Create admin's hashed directories.
        std::string adminDir = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256("admin");
        std::string personalDir = adminDir + "/" + SecOps::SecurityOps::sha256("personal");
        std::string sharedDir   = adminDir + "/" + SecOps::SecurityOps::sha256("shared");
        std::filesystem::create_directories(adminDir);
        std::filesystem::create_directories(personalDir);
        std::filesystem::create_directories(sharedDir);

        // Cache admin in memory with isAdmin=true.
        UOps::UserOps::users["admin"] = UOps::User{"admin", adminPriv, "", true};

        // Create admin's per-user mapping file.
        json adminMapping;
        adminMapping["username"] = "admin";
        adminMapping["files"]    = json::object();
        std::string mappingStr = adminMapping.dump(4);

        // Read the newly moved admin public key.
        std::ifstream pubFile(pubDst);
        if (!pubFile) {
            std::cerr << "Failed to read admin public key from " << pubDst << "\n";
            exit(1);
        }
        std::stringstream pubSS;
        pubSS << pubFile.rdbuf();
        std::string adminPub = pubSS.str();
        pubFile.close();

        // Encrypt the mapping and write it to adminDir.
        std::string mappingFileName = SecOps::SecurityOps::sha256("admin_file_mapping.json");
        std::string mappingFilePath = adminDir + "/" + mappingFileName;
        std::string encryptedMapping = SecOps::SecurityOps::rsaEncrypt(mappingStr, adminPub);
        Ops::FileOps::writeFile(mappingFilePath, encryptedMapping);

        // Update global mapping for admin.
        UOps::UserOps::mapUser("admin", adminPub);

        // Create admin_mapping.json in FILESYSTEM_DIR, storing the private key, encrypted with AES-256.
        json admMap;
        admMap["admin"] = adminPriv;
        std::string admMapStr = admMap.dump(4);
        std::string key = adminPriv.substr(0, 32); // Must be >= 32 bytes in adminPriv
        std::string encryptedAdmMap = SecOps::SecurityOps::aesEncrypt(admMapStr, key);
        std::string adminMappingFile = SecOps::SecurityOps::sha256("admin_mapping.json");
        std::string adminMappingPath = FILESYSTEM_DIR + "/" + adminMappingFile;
        Ops::FileOps::writeFile(adminMappingPath, encryptedAdmMap);

        // Print instructions & exit
        std::cout << "Admin user created.\n";
        std::cout << "Admin private key stored in " << adminPath << "\n";
        std::cout << "Admin public key stored in " << pubDst << "\n";
        std::cout << "Please secure your admin keyfile.\n";
        std::cout << "Exiting now. Next time, re-run the program with a valid keyfile.\n";
        exit(0);
    }

    // If admin keyfile already exists, that means subsequent run. Just do nothing here.
    // (We've already created the necessary directories.)
}

int main(int argc, char **argv) {
    // This ensures the fortress directory structure & admin user on first run,
    // and does nothing if admin keyfile already exists.
    initFortress();

    // If this is a subsequent run (admin keyfile already exists), we now expect a user keyfile argument.
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <keyfile_name>\n";
        std::cerr << "No keyfile provided, exiting.\n";
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

    // Possibly ensure hashed personal/shared directories exist if user was created at some earlier time.
    std::string userDir = FILESYSTEM_DIR + "/" + SecOps::SecurityOps::sha256(user);
    if (!std::filesystem::exists(userDir)) {
        std::filesystem::create_directories(userDir);
        std::filesystem::create_directories(userDir + "/" + SecOps::SecurityOps::sha256("personal"));
        std::filesystem::create_directories(userDir + "/" + SecOps::SecurityOps::sha256("shared"));
    }

    // Start the shell
    Shell::InteractiveShell shell(user);
    shell.start();
    return 0;
}
