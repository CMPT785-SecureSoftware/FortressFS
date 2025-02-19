#ifndef USER_OPS_H
#define USER_OPS_H

#include <string>
#include <unordered_map>

// Minimal user manager that stores usernames -> public/private keys
namespace UOps
{
    struct User {
        std::string username;
        std::string privateKey;
        std::string publicKey;
        bool isAdmin;
    };

    class UserOps {
    public:
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

    private:
        static std::unordered_map<std::string, User> users;
    };
}

#endif