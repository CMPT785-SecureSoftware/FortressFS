#ifndef SHELL_H
#define SHELL_H

#include <string>

namespace Shell {

    /**
     * InteractiveShell provides the command-line interface for the file system.
     * It supports commands like cd, pwd, ls, cat, share, mkdir, mkfile, and adduser.
     */
    class InteractiveShell {
    public:
        // Constructor: takes the logged-in user's plaintext username.
        InteractiveShell(const std::string &username);

        // Start the interactive shell loop.
        void start();

    private:
        std::string currentUser;  // Plaintext username.
        std::string currentDir;   // Virtual current directory (e.g., "/", "/shared", etc.).

        // Converts a virtual (plaintext) path to the on-disk path (using hashed names).
        std::string resolvePath(const std::string &vpath);

        // Normalizes a path, handling "." and "..".
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