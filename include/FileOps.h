#ifndef FILE_OPS_H
#define FILE_OPS_H

#include <string>
#include <filesystem>
#include <fstream>
#include <sstream>

/**
 * The Ops namespace encapsulates basic file and directory operations.
 */
namespace Ops {

    /**
     * FileOps provides static methods for reading and writing files,
     * as well as creating directories and checking for file/directory existence.
     */
    class FileOps {
    public:
        /**
         * writeFile:
         * Writes the given data (in binary mode) to the specified file path.
         * Returns true if the operation is successful.
         */
        static bool writeFile(const std::string &path, const std::string &data) {
            std::ofstream ofs(path, std::ios::binary);
            if (!ofs) return false;
            ofs.write(data.data(), data.size());
            return ofs.good();
        }

        /**
         * readFile:
         * Reads the entire content of the file specified by path and returns it as a string.
         */
        static std::string readFile(const std::string &path) {
            std::ifstream ifs(path, std::ios::binary);
            if (!ifs) return "";
            std::stringstream buffer;
            buffer << ifs.rdbuf();
            return buffer.str();
        }

        /**
         * makeDirectory:
         * Creates a directory (and all necessary parent directories) specified by path.
         * Returns true if the directory is successfully created.
         */
        static bool makeDirectory(const std::string &path) {
            try {
                std::filesystem::create_directories(path);
                return true;
            } catch (...) {
                return false;
            }
        }

        /**
         * fileExists:
         * Checks if a file exists at the specified path.
         */
        static bool fileExists(const std::string &path) {
            return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
        }

        /**
         * directoryExists:
         * Checks if a directory exists at the specified path.
         */
        static bool directoryExists(const std::string &path) {
            return std::filesystem::exists(path) && std::filesystem::is_directory(path);
        }
    };

} // namespace Ops

#endif