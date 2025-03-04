#ifndef USER_OPS_H
#define USER_OPS_H

#include <string>
#include <unordered_map>

namespace UOps {

    /**
     * User structure represents a user with a username, private key, public key,
     * and an admin flag.
     */
    struct User {
        std::string username;
        std::string privateKey;  // Decrypted private key loaded from keyfile.
        std::string publicKey;   // Loaded from public_keys directory.
        bool isAdmin;
    };

    /**
     * UserOps handles creation and login for users. It also manages the global
     * mapping for user base directories.
     */
    class UserOps {
    public:
        // Creates a new user, sets up RSA keys, and creates a per-user mapping file.
        static bool createUser(const std::string &username);

        // Logs in a user by reading and decrypting the per-user mapping file.
        static std::string login(const std::string &keyfilePath);

        // Returns the in-memory User record for a given username.
        static User getUser(const std::string &username);

        // Updates the global mapping file (global_mapping.json) for the given user.
        static bool mapUser(const std::string &username, const std::string &publicKey);

        // In-memory cache for the user (only one user exists per run).
        static std::unordered_map<std::string, User> users;
    };
}

#endif