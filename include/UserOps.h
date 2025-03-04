#ifndef USER_OPS_H
#define USER_OPS_H

#include <string>
#include <unordered_map>
<<<<<<< HEAD

/**
 * Namespace UOps encapsulates operations related to user management,
 * such as creating users, logging in, and updating mappings.
 */
namespace UOps {

    /**
     * User structure contains:
     *  - username
     *  - privateKey (the actual RSA private key content)
     *  - publicKey
     *  - isAdmin (true for admin)
     */
=======
#include <iostream>

#define USER_OPS_VERSION "1.0.1"

// Minimal user manager that stores usernames -> public/private keys
namespace UOps
{
>>>>>>> 8874a9cf4754fcd8b285cc15a9acf5c728818402
    struct User {
        std::string username;
        std::string privateKey;
        std::string publicKey;
        bool isAdmin;
<<<<<<< HEAD
    };

    /**
     * UserOps provides:
     *  - createUser
     *  - login
     *  - mapUser / updateAdminMapping
     *  - getUser / userExists
     * and keeps an in-memory cache of User objects.
     */
    class UserOps {
    public:
        // createUser: generates keys, moves them, updates global mapping, etc.
        static bool createUser(const std::string &username);

        // login: logs in using <username>_keyfile.pem content, decrypts mapping, verifies username.
        static std::string login(const std::string &keyfilePath);

        // getUser: returns the user from in-memory cache.
        static User getUser(const std::string &username);

        // userExists: checks if user is in the in-memory cache.
        static bool userExists(const std::string &username);

        // mapUser: updates global_mapping.json with user root, shared, etc.
        static bool mapUser(const std::string &username, const std::string &publicKey);

        // updateAdminMapping: updates admin_mapping.json with user private key, encrypted with admin's private key.
        static bool updateAdminMapping(const std::string &username, const std::string &userPrivateKey, const std::string &adminPrivateKey);

        // The in-memory cache of users. Key is username.
=======
        int loginAttempts = 0;
    };

    class UserOps {
    public:
        // Get version of the UserOps system
        static std::string getVersion() {
            return USER_OPS_VERSION;
        }

        // Create new user, generate RSA pair
        static bool createUser(const std::string& username, bool admin=false);

        // Add existing user (if keys already exist)
        static bool addUserFromKeys(const std::string& username,
                                    const std::string& privateKey,
                                    const std::string& publicKey,
                                    bool admin=false);

        // Check if user exists
        static bool userExists(const std::string& username);

        // Retrieve user by username
        static User getUser(const std::string& username);

        // Attempt login by providing path to private key file
        // Returns the username if login is successful, empty otherwise
        static std::string login(const std::string& privateKeyPath);
        
        // Display all users (for debugging purposes)
        static void listUsers() {
            for (const auto& pair : users) {
                std::cout << "User: " << pair.first << ", Admin: " << (pair.second.isAdmin ? "Yes" : "No") << std::endl;
            }
        }

    private:
>>>>>>> 8874a9cf4754fcd8b285cc15a9acf5c728818402
        static std::unordered_map<std::string, User> users;
    };
}

<<<<<<< HEAD
#endif
=======
#endif
>>>>>>> 8874a9cf4754fcd8b285cc15a9acf5c728818402
