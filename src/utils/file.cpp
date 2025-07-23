#include <string>
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For stat, S_ISREG
#include <cstdio>      // For std::FILE
#include <cstdlib>     // For realpath (POSIX)
#include <limits.h>    // For PATH_MAX
#include <unistd.h>    // For getcwd (POSIX)
#include <algorithm>   // For std::transform
#include <cctype>      // For std::tolower

#include "utils/string.h"  // Assuming startsWith is defined here

#ifdef _WIN32
    #include <windows.h>
    #include <shlwapi.h>      // For PathCanonicalize
    #pragma comment(lib, "shlwapi.lib")  // Link automatically
#endif

// Disable file access safety by default.
// Define FILE_READ_SAFE to enable path restrictions (limit to subdirectories).
#ifdef FILE_READ_SAFE
#pragma message("FILE_READ_SAFE is enabled: access is restricted to subdirectories only")
#else
#define FILE_READ_UNSAFE
#pragma message("FILE_READ_UNSAFE is enabled: access is NOT restricted (unsafe)")
#endif

// Check if a given path is within ./config or ./rules (only when FILE_READ_SAFE is defined)
static bool isInScope(const std::string& path)
{
#ifdef FILE_READ_SAFE
    #ifdef _WIN32
        char real_target_buf[MAX_PATH];
        DWORD len = GetFullPathNameA(path.c_str(), MAX_PATH, real_target_buf, nullptr);
        if (len == 0 || len >= MAX_PATH) {
            return false; 
        }
        std::string s_real_target = real_target_buf;

        char cwd_buf[MAX_PATH];
        DWORD cwd_len = GetCurrentDirectoryA(MAX_PATH, cwd_buf);
        if (cwd_len == 0 || cwd_len >= MAX_PATH) {
            return false; 
        }
        std::string s_cwd = cwd_buf;

        std::transform(s_real_target.begin(), s_real_target.end(), s_real_target.begin(),
                       [](unsigned char c){ return static_cast<unsigned char>(std::tolower(c)); });
        std::transform(s_cwd.begin(), s_cwd.end(), s_cwd.begin(),
                       [](unsigned char c){ return static_cast<unsigned char>(std::tolower(c)); });
        std::replace(s_real_target.begin(), s_real_target.end(), '\\', '/');
        std::replace(s_cwd.begin(), s_cwd.end(), '\\', '/');

        if (s_real_target.rfind(s_cwd, 0) != 0) { 
            return false; 
        }

        if (s_real_target == s_cwd) {
            return false;
        }

        DWORD attr = GetFileAttributesA(real_target_buf);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            return false;
        }
        bool is_dir = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;

        if (is_dir) {
            return true; 
        } else {
            std::string relative_path = s_real_target.substr(s_cwd.length());
            return relative_path.length() > 1 && relative_path[0] == '/' && relative_path.find('/', 1) != std::string::npos;
        }
    #else 
        char real_target_buf[PATH_MAX];
        if (!realpath(path.c_str(), real_target_buf)) {
            return false; 
        }
        std::string s_real_target = real_target_buf;

     
        char cwd_buf[PATH_MAX];
        if (!getcwd(cwd_buf, sizeof(cwd_buf))) {
            return false;
        }
        std::string s_cwd = cwd_buf;

        if (s_real_target.rfind(s_cwd, 0) != 0) { 
            return false; 
        }

        if (s_real_target == s_cwd) {
            return false;
        }

        struct stat st;
        if (stat(real_target_buf, &st) != 0) {
            return false; 
        }
        bool is_dir = S_ISDIR(st.st_mode);

        if (is_dir) {
            return true; 
        } else {
            std::string relative_path = s_real_target.substr(s_cwd.length());
            return relative_path.length() > 1 && relative_path[0] == '/' && relative_path.find('/', 1) != std::string::npos;
        }
    #endif

#else
    #ifdef _WIN32
        if (path.find(":\\") != std::string::npos || path.find(":/") != std::string::npos  ||path.find("..") != std::string::npos)
            return false;
    #else
        if (path.find("/") == 0 || path.find("..") != std::string::npos)
            return false;
        const std::string filename = path.substr(path.find_last_of("/\\") + 1);
        if (filename.rfind("pref.", 0) == 0)
            return false;
        const std::vector<std::string> blacklist = {
            "/etc", "/proc", "/sys", "/var", "/dev"
        };
        for (const auto& dir : blacklist) {
            if (path.rfind(dir) != std::string::npos)
                return false;
        }
    #endif
    return true;
#endif
}

static bool hasDisallowedExtension(const std::string& path) {
    static const std::vector<std::string> disallowed = {".exe", ".dll", ".so", ".bin"};
    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    for (const auto& ext : disallowed) {
        if (lower.size() >= ext.size() &&
            lower.compare(lower.size() - ext.size(), ext.size(), ext) == 0)
            return true;
    }
    return false;
}
// Read the content of a file as string
std::string fileGet(const std::string& path, bool scope_limit)
{
    if (scope_limit && !isInScope(path))
        return "";

    std::ifstream infile(path, std::ios::binary);
    if (!infile)
        return "";

    std::ostringstream buffer;
    buffer << infile.rdbuf();
    return buffer.str();
}

// Check if a file exists and is a regular file
bool fileExist(const std::string& path, bool scope_limit)
{
    if (scope_limit && !isInScope(path))
        return false;

    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

// Copy contents from one file to another
bool fileCopy(const std::string &source, const std::string &dest)
{
    std::ifstream infile(source, std::ios::binary);
    if (!infile)
        return false;

    std::ofstream outfile(dest, std::ios::binary);
    if (!outfile)
        return false;

    try {
        outfile << infile.rdbuf();
    } catch (...) {
        return false;
    }

    return true;
}

// Write content to a file (overwrite or append mode)
int fileWrite(const std::string &path, const std::string &content, bool overwrite)
{
    std::ios_base::openmode mode = std::ios::binary | (overwrite ? std::ios::trunc : std::ios::app);
    std::ofstream outfile(path, mode);
    if (!outfile)
        return -1;

    outfile.write(content.c_str(), content.size());
    return outfile.good() ? 0 : -2;
}
