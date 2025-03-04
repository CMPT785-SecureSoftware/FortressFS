#ifndef USER_OPS_H
#define USER_OPS_H

#include <string>
#include <unordered_map>

namespace UOps {

    /**
     * The User structure holds the information for a user:
     * - username, decrypted private key, public key, and an admin flag.
     */
    struct User {
        std::string username;
        std::string privateKey;  // Loaded from keyfile (decrypted).
        std::string publicKey;   // Loaded from the public_keys directory.
        bool isAdmin;
    };

    /**
     * UserOps provides functions to create users, log in, and manage global mappings.
     * It also caches the currently logged-in user.
     */
    class UserOps {
    public:
        // Creates a new user (used by admin) and sets up the per-user mapping file.
        static bool createUser(const std::string &username);

        // Logs in a user by reading and decrypting the per-user mapping file.
        static std::string login(const std::string &keyfilePath);

        // Returns the User record from the in-memory cache.
        static User getUser(const std::string &username);

        // Checks whether a user exists in the in-memory cache.
        static bool userExists(const std::string &username);

        // Updates the global mapping file (global_mapping.json) with base directory info for the user.
        static bool mapUser(const std::string &username, const std::string &publicKey);

        // Updates the admin mapping (admin_mapping.json) with a new user's private key.
        // admin_mapping.json is stored in FILESYSTEM_DIR and encrypted using admin's private key.
        static bool updateAdminMapping(const std::string &username, const std::string &userPrivateKey, const std::string &adminPrivateKey);

        // In-memory cache for the user (only one user per session).
        static std::unordered_map<std::string, User> users;
    };
}

#endif