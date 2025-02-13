#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include "UserOps.h"
#include "Shell.h"
#include "FileOps.h"
#include "SecurityOps.h"

// New folder constants:
static const std::string FILESYSTEM_DIR = "filesystem";
static const std::string ENCRYPTED_KEYS_DIR = FILESYSTEM_DIR + "/EncryptedKeys";
static const std::string ADMIN_KEYS_DIR = "admin_keys";
static const std::string PUBLIC_KEYS_DIR = "public_keys";
static const std::string ADMIN_KEYFILE = "admin_keyfile";

// initFortress() now creates the filesystem directory, EncryptedKeys folder, admin_keys folder, 
// and public_keys folder. It also generates the admin keypair (if not present) and moves the admin’s 
// private key to admin_keys.
static void initFortress() {
    // Create the main filesystem directory.
    if (!std::filesystem::exists(FILESYSTEM_DIR))
        std::filesystem::create_directories(FILESYSTEM_DIR);

    // Create folder for encrypted user keyfiles.
    if (!std::filesystem::exists(ENCRYPTED_KEYS_DIR))
        std::filesystem::create_directories(ENCRYPTED_KEYS_DIR);

    // Create folder for admin keys.
    if (!std::filesystem::exists(ADMIN_KEYS_DIR))
        std::filesystem::create_directories(ADMIN_KEYS_DIR);

    // Create folder for public keys.
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
        // Read admin's private key from the generated file ("admin_private.pem").
        std::ifstream ifs("admin_private.pem");
        std::stringstream ss;
        ss << ifs.rdbuf();
        std::string adminPriv = ss.str();
        // Write admin's private key (plaintext) to the admin_keys folder.
        std::ofstream ofs(adminPath, std::ios::binary);
        ofs << adminPriv;
        ofs.close();
        // Create admin's folder structure inside the filesystem.
        std::filesystem::create_directories(FILESYSTEM_DIR + "/admin/personal");
        std::filesystem::create_directories(FILESYSTEM_DIR + "/admin/shared");
        // Add admin to the in-memory user table.
        UOps::UserOps::users["admin"] = UOps::User{"admin", adminPriv, "", true};
        std::cout << "Admin user created. Admin keys stored in " << adminPath << "\n";

        // Move admin's public key to the public_keys folder.
        std::filesystem::rename("admin_public.pem", PUBLIC_KEYS_DIR + "/admin_public.pem");
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cout << "Usage: ./fileserver <keyfile_name>\n";
        return 1;
    }
    initFortress();

    // Attempt login using the provided keyfile.
    std::string keyfileName = argv[1];
    std::string user = UOps::UserOps::login(keyfileName);
    if (user.empty()) {
        std::cout << "Invalid keyfile\n";
        return 1;
    }
    std::cout << "Logged in as " << user << "\n";

    // Ensure the user's folder exists in the filesystem.
    std::string userDir = FILESYSTEM_DIR + "/" + user;
    if (!std::filesystem::exists(userDir)) {
        std::filesystem::create_directories(userDir + "/personal");
        std::filesystem::create_directories(userDir + "/shared");
    }

    Shell::InteractiveShell shell(user);
    shell.start();

    return 0;
}