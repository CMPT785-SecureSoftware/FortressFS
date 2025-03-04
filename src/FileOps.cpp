#include "FileOps.h"
#include <fstream>
<<<<<<< HEAD
#include <sstream>
=======
>>>>>>> 8874a9cf4754fcd8b285cc15a9acf5c728818402
#include <filesystem>

namespace Ops {

bool FileOps::writeFile(const std::string &path, const std::string &data) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    ofs.write(data.data(), data.size());
<<<<<<< HEAD
    return ofs.good();
=======
    return true;
>>>>>>> 8874a9cf4754fcd8b285cc15a9acf5c728818402
}

std::string FileOps::readFile(const std::string &path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return "";
<<<<<<< HEAD
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    return buffer.str();
=======
    return std::string((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
>>>>>>> 8874a9cf4754fcd8b285cc15a9acf5c728818402
}

bool FileOps::makeDirectory(const std::string &path) {
    try {
        std::filesystem::create_directories(path);
        return true;
    } catch (...) {
        return false;
    }
}

bool FileOps::fileExists(const std::string &path) {
    return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
}

bool FileOps::directoryExists(const std::string &path) {
    return std::filesystem::exists(path) && std::filesystem::is_directory(path);
}

} // namespace Ops