#ifndef SHELL_H
#define SHELL_H

#include <string>

namespace Shell {

    /**
     * InteractiveShell provides the interactive command-line interface.
     * It supports commands: cd, pwd, ls, cat, share, mkdir, mkfile, adduser, and exit.
     * It enforces restrictions based on the user's role and current directory.
     */
    class InteractiveShell {
    public:
        // Constructor: accepts the logged-in user's plaintext username.
        InteractiveShell(const std::string &username);

        // Starts the shell loop.
        void start();
    private:
        std::string currentUser;  // Plaintext username.
        std::string currentDir;   // Virtual current directory (e.g., "/", "/personal", "/shared", or a user's folder).

        // Converts a virtual (plaintext) path to the actual on-disk path (using hashed names).
        std::string resolvePath(const std::string &vpath);

        // Normalizes a path string (resolving '.' and '..').
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