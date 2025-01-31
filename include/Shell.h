#ifndef SHELL_H
#define SHELL_H

#include <string>

/**
 * The Shell namespace contains the InteractiveShell class which implements
 * the command-line interface for the file system.
 */
namespace Shell {

    /**
     * InteractiveShell provides the interactive command-line interface.
     * It supports commands like cd, pwd, ls, cat, share, mkdir, mkfile, and adduser,
     * and enforces role-based and directory-based restrictions.
     */
    class InteractiveShell {
    public:
        // Constructor accepts the logged-in user's plaintext username.
        InteractiveShell(const std::string &username);

        // Starts the interactive shell loop.
        void start();
    private:
        std::string currentUser;  // Plaintext username.
        std::string currentDir;   // Virtual current directory.
                                  // For normal users, "/" represents their root (showing only "personal" and "shared").
                                  // For admin, "/" is a special view ("filesystem") listing all users.

        // Converts a virtual (plaintext) path to the on-disk path using hashed names.
        std::string resolvePath(const std::string &vpath);

        // Normalizes a path string by resolving "." and "..".
        std::string normalizePath(const std::string &path);

        // Command handler functions.
        void handle_cd(const std::string &arg);
        void handle_pwd();
        void handle_ls();
        void handle_cat(const std::string &filename);
        void handle_share(const std::string &args);
        void handle_mkdir(const std::string &dirname);
        void handle_mkfile(const std::string &args);
        void handle_adduser(const std::string &username);
        void showHelp();
    };
}

#endif