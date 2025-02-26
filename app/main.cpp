#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include "UserOps.h"
#include "Shell.h"
#include "FileOps.h"
#include "SecurityOps.h"
#include <nlohmann/json.hpp>


// Define folder structure constants.
static const std::string FILESYSTEM_DIR = "filesystem";              // The encrypted filesystem folder for file data
static const std::string PRIVATE_KEYS_DIR = "private_keys";            // Where user private keys (plaintext PEM) are stored
static const std::string ADMIN_KEYS_DIR = "admin_keys";                // Where admin keys (plaintext PEM) are stored
static const std::string PUBLIC_KEYS_DIR = "public_keys";              // Where public key files are stored (outside the filesystem)
static const std::string ADMIN_KEYFILE = "admin_keyfile.pem";          // Admin private key filename in ADMIN_KEYS_DIR

// initFortress() creates the necessary folder structure.
// On first execution (if the admin keyfile is not present), it generates the admin key pair,
// stores the admin private key in ADMIN_KEYS_DIR and the public key in PUBLIC_KEYS_DIR,
// creates the filesystem folder for admin, and then exits.
static void initFortress() {
    // Create the main filesystem folder.
    if (!std::filesystem::exists(FILESYSTEM_DIR))
        std::filesystem::create_directories(FILESYSTEM_DIR);
    
    // Create the private_keys folder.
    if (!std::filesystem::exists(PRIVATE_KEYS_DIR))
        std::filesystem::create_directories(PRIVATE_KEYS_DIR);
    
    // Create the admin_keys folder.
    if (!std::filesystem::exists(ADMIN_KEYS_DIR))
        std::filesystem::create_directories(ADMIN_KEYS_DIR);
    
    // Create the public_keys folder.
    if (!std::filesystem::exists(PUBLIC_KEYS_DIR))
        std::filesystem::create_directories(PUBLIC_KEYS_DIR);
    
    // Admin keyfile is stored in admin_keys.
    std::string adminPath = ADMIN_KEYS_DIR + "/" + ADMIN_KEYFILE;
    if (!std::filesystem::exists(adminPath)) {
        // Generate admin's RSA key pair.
        if (!SecOps::SecurityOps::generateRSAKeyPair("admin")) {
            std::cerr << "Failed to generate admin key pair\n";
            exit(1);
        }
        // Read admin's private key from "admin_private.pem".
        std::ifstream ifs("admin_private.pem");
        std::stringstream ss;
        ss << ifs.rdbuf();
        std::string adminPriv = ss.str();
        // Write the admin private key (plaintext) to the admin_keys folder.
        std::ofstream ofs(adminPath, std::ios::binary);
        ofs << adminPriv;
        ofs.close();
        std::filesystem::remove("admin_private.pem");
        // Move the admin public key to the public_keys folder.
        std::string pubSrc = "admin_public.pem";
        std::string pubDst = PUBLIC_KEYS_DIR + "/admin_public.pem";
        std::filesystem::rename(pubSrc, pubDst);
        // Create admin's filesystem folder (under FILESYSTEM_DIR).
        std::filesystem::create_directories(FILESYSTEM_DIR + "/admin/personal");
        std::filesystem::create_directories(FILESYSTEM_DIR + "/admin/shared");

        std::ifstream pubIfs(pubDst);
        std::stringstream pubSS;
        pubSS << pubIfs.rdbuf();
        std::string adminPub = pubSS.str();

        // Use UserOps to map admin in user_mapping.json.
        if (!UOps::UserOps::mapUser("admin", adminPub)) {
            std::cerr << "Failed to map admin in user_mapping.json\n";
        }
    
        // Add admin to the in-memory user table.
        UOps::UserOps::users["admin"] = UOps::User{"admin", adminPriv, "", true};
        std::cout << "Admin user created.\n";
        std::cout << "Admin private key stored in " << adminPath << "\n";
        std::cout << "Admin public key stored in " << pubDst << "\n";
        std::cout << "Please secure your admin keyfile. Exiting now. (Re-run the program with a valid keyfile.)\n";
        exit(0);
    }
}

int main(int argc, char **argv) {
    // First, initialize the fortress folder structure and admin keys.
    initFortress();

    // Expect usage: ./fileserver <keyfile_name>
    if (argc < 2) {
        std::cout << "Usage: ./fileserver <keyfile_name>\n";
        return 1;
    }

    // Attempt login using the provided keyfile.
    std::string keyfileName = argv[1];
    std::string user = UOps::UserOps::login(keyfileName);
    if (user.empty()) {
        std::cout << "Invalid keyfile\n";
        return 1;
    }
    std::cout << "Logged in as " << user << "\n";

    // Ensure the user's filesystem folder exists.
    std::string userDir = FILESYSTEM_DIR + "/" + user;
    if (!std::filesystem::exists(userDir)) {
        std::filesystem::create_directories(userDir + "/personal");
        std::filesystem::create_directories(userDir + "/shared");
    }

    // Start the interactive shell.
    Shell::InteractiveShell shell(user);
    shell.start();

    return 0;
}