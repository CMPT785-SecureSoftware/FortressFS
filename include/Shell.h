#ifndef SHELL_H
#define SHELL_H

#include <string>

/**
 * Namespace Shell contains the InteractiveShell class which implements the
 * interactive command-line interface for the fortress file system.
 */
namespace Shell {

    /**
     * InteractiveShell provides the interactive CLI.
     * It supports commands such as cd, pwd, ls, cat, share, mkdir, mkfile, and adduser,
     * and enforces restrictions based on the user's role and current directory.
     *
     * For normal users, "/" represents their root (showing only "personal" and "shared").
     * For admin, additional functionality is provided:
     *   - Admin starts at his own root.
     *   - If admin does "cd .." at his own root, he enters the filesystem view
     *     where pwd outputs "filesystem" and ls lists all users (from admin_mapping.json).
     *   - In filesystem view, "cd <username>" allows admin to view that user's directory (read-only).
     *   - Admin cannot modify (mkdir/mkfile/share) files in other users' directories.
     */
    class InteractiveShell {
    public:
        // Constructor takes the logged-in user's plaintext username.
        InteractiveShell(const std::string &username);

        // Starts the interactive shell loop.
        void start();
    private:
        std::string currentUser;  // The logged-in user's username.
        std::string currentDir;   // Virtual current directory.
                                  // For normal users, "/" is their root.
                                  // For admin, "/" is initially his root; however, admin may switch
                                  // between his own view and a filesystem view.
        // Additional admin state:
        bool isAdminFSMode;       // true if admin is in the filesystem view (listing all users).
        std::string viewedUser;   // If non-empty, admin is viewing a specific user's directory (read-only).

        // Converts a virtual (plaintext) path to an on-disk path using hashed names.
        std::string resolvePath(const std::string &vpath);

        // Normalizes a path by resolving "." and ".." components.
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

} // namespace Shell

#endif