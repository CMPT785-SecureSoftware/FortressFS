#include <iostream>
#include "UserOps.h"
#include "Shell.h"

int main(int argc, char** argv) {
    // For demonstration, let's create an admin user "admin" with RSA keys
    if (!UOps::UserOps::createUser("admin", true)) {
        std::cout << "Admin user might already exist. Proceeding...\n";
    } else {
        std::cout << "Admin user 'admin' created.\n";
    }

    // Create a normal user "alice"
    if (!UOps::UserOps::createUser("alice")) {
        std::cout << "User 'alice' might already exist.\n";
    } else {
        std::cout << "User 'alice' created.\n";
    }

    // We start an interactive shell as 'admin' for demonstration:
    Shell::InteractiveShell shell("admin");
    shell.start();

    return 0;
}