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
 * - Creates the necessary folder structure.
 * - If admin keyfile does not exist, we unify logic by calling UserOps::createUser("admin").
 *   That function will generate admin_keyfile.pem, move it to admin_keys, etc.
 * - Then we exit to let the user re-run with admin's key.
 */
static void initFortress() {
    // Ensure the main directories exist
    if (!std::filesystem::exists(FILESYSTEM_DIR))
        std::filesystem::create_directories(FILESYSTEM_DIR);

    if (!std::filesystem::exists(PRIVATE_KEYS_DIR))
        std::filesystem::create_directories(PRIVATE_KEYS_DIR);

    if (!std::filesystem::exists(ADMIN_KEYS_DIR))
        std::filesystem::create_directories(ADMIN_KEYS_DIR);

    if (!std::filesystem::exists(PUBLIC_KEYS_DIR))
        std::filesystem::create_directories(PUBLIC_KEYS_DIR);

    // Check if admin's keyfile is present
    std::string adminPath = ADMIN_KEYS_DIR + "/" + ADMIN_KEYFILE;
    if (!std::filesystem::exists(adminPath)) {
        std::cout << "No admin keyfile found. Creating admin user.\n";

        // We call createUser("admin") in unified logic
        if (!UOps::UserOps::createUser("admin")) {
            Ops::FileOps::appendErrorLog("[Debug] Failed to create admin user!");
            std::cerr << "Failed to create admin user!\n";
            exit(1);
        }

        std::string keyfileFrom = PRIVATE_KEYS_DIR + "/admin_keyfile.pem";
        if (!std::filesystem::exists(keyfileFrom)) {
            Ops::FileOps::appendErrorLog("[Debug] admin_keyfile.pem was not generated in private_keys for some reason.");
            std::cerr << "admin_keyfile.pem was not generated in private_keys for some reason.\n";
            exit(1);
        }
        // Move it to admin_keys
        std::filesystem::rename(keyfileFrom, adminPath);

        std::cout << "Admin user created.\n";
        std::cout << "Admin private key stored in " << adminPath << "\n";
        std::cout << "Please secure your admin keyfile. Exiting now.\n";
        exit(0);
    }
}

int main(int argc, char** argv) {
    // Initialize fortress
    initFortress();

    // On subsequent runs, we expect a keyfile argument
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <keyfile_name>\n";
        return 1;
    }

    // Attempt login
    std::string keyfileName = argv[1];
    std::string user = UOps::UserOps::login(keyfileName);
    if (user.empty()) {
        // We only print "Invalid keyfile" to the user, while details go to error.log
        std::cout << "Invalid keyfile\n";
        return 1;
    }

    std::cout << "Logged in as " << user << "\n";

    // For convenience, ensure hashed personal/shared exist
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

    // Start the interactive shell
    Shell::InteractiveShell shell(user);
    shell.start();

    return 0;
}