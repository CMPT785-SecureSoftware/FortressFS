#ifndef USER_OPS_H
#define USER_OPS_H

#include <string>
#include <unordered_map>

namespace UOps {

    struct User {
        std::string username;
        std::string privateKey;  // The decrypted private key (used for file decryption)
        std::string publicKey;   // Public key (if needed)
        bool isAdmin;
    };

    class UserOps {
    public:
        // Create a new user (used by admin command adduser)
        // This generates a new key pair (using SecurityOps) and then encrypts the user's private key
        // with the admin's key (via AES). The resulting keyfile is stored in the EncryptedKeys folder.
        static bool createUser(const std::string &username);

        // Check if a user exists in memory
        static bool userExists(const std::string &username);

        // Retrieve a user record
        static User getUser(const std::string &username);

        // Load a user from a keyfile (given the decrypted key)
        static std::string login(const std::string &keyfilePath);

        // In-memory user table
        static std::unordered_map<std::string, User> users;

        // In UserOps.h, inside the UOps namespace and UserOps class
        static bool mapUser(const std::string &username, const std::string &publicKey);

    };
}

#endif