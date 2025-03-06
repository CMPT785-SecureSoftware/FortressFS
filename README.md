# FortressFS
A secure filesystem with key-based authentication, enforced access control, and encryption. Users manage their own files, while admins have read-only oversight. Supports both real and simulated filesystems.
# Requirements
- Operating System: Linux (tested on latest Ubuntu)
- Compiler: A C++17 compatible compiler (e.g., g++ 7 or later)
- Libraries:
  - STL (C++ Standard Template Library)
  - OpenSSL (for RSA, AES, SHA-256, and hybrid encryption)
  - nlohmann/json (for JSON parsing)
  - C++17 filesystem library
- Build System: "fortressfs"

# How to Build
Follow these steps to build a standalone static executable for Ubuntu:

1. **Install Dependencies**

   Ensure you have the required dependencies installed. For Ubuntu, you may need:
   - A C++ compiler with C++17 support (e.g., `g++`)
   - OpenSSL development libraries (for static linking, ensure static libraries are installed):
```bash
     sudo apt-get update
     sudo apt-get install g++ libssl-dev
```
   - Since [nlohmann/json](https://github.com/nlohmann/json) is header-only, you can install it in the system via:
```bash
     sudo apt-get install nlohmann-json3-dev
```

2. **Clone the Repository**

   Clone or download your project repository and navigate to the project directory:
   ```bash
   git clone <your-repo-url>
   cd <your-repo-directory>
   ```

3. **Compile with Static Linking**

   Use the following command to build the executable with static linking:
   ```bash
   g++ -static -static-libgcc -static-libstdc++ -I include src/*.cpp app/main.cpp -lssl -lcrypto -o fortresses
   ```


# How to Run
## First Run (Admin Setup):
On the first run, if no admin keyfile exists, the program creates the necessary folder structure and generates the admin key pair. Run:
```bash
./fortressfs <any_keyfile>
```
The program will create the admin user, move the generated keyfile to the admin_keys directory, and then exit. Secure the admin keyfile found in admin_keys/admin_keyfile.pem.

## Subsequent Runs (User Login):
Log in with your keyfile. For example:

### For admin:
```bash
./fortressfs .<location>/admin_keyfile.pem
```
For a regular user:
```bash
./fortressfs .<location>/<username>_keyfile.pem
```
# Available Commands
Once logged in, the interactive shell provides the following commands:

- cd <directory>
Change the current directory. Supports . for current directory and .. for parent directory.

  - Users: Can navigate within their own root (which contains only personal and shared folders).
  - Admin: Can switch between their own root and a read-only filesystem view of other users.

- pwd
Display the current directory path.

- ls
List directory contents:

  - At user root (/): displays only personal and shared.
  - Within personal: lists files and directories with their original names (using the stored user mapping).
  - Within shared: lists shared files as recorded in the global mapping.
  - Admin: In filesystem view, lists all known users.

- cat <filename>
Decrypt and display the contents of a specified file (allowed only in the personal or shared directories).

- mkfile <filename> <contents>
Create or update a file in the personal directory. File contents are encrypted using a hybrid encryption scheme (AES-256-CBC with a randomly generated AES key, with the AES key protected by RSA).

- mkdir <directory_name>
Create a new directory in the personal folder and update the user's file mapping.

- share <filename> <targetUser>
Share a file from your personal directory with another user. The file is decrypted with your private key and re-encrypted with the target user’s public key, then stored in the target user’s shared folder. The global mapping is updated with the shared file entry.

- adduser <username> (Admin only)
Create a new user. This command generates the user’s key pair, sets up their directory structure, creates their encrypted file mapping, and updates the global mapping.

- exit
Terminate the program.

- help
Display a help message listing the available commands.