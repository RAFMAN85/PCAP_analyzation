#include "Ignore_list.h"

IgnoreList::IgnoreList(const std::string& filename) {
    std::ifstream file(filename);
    std::string line;

    if (!file.is_open()) {
        std::cerr << "Warning: Ignore list file '" << filename << "' not found. No IPs will be ignored." << std::endl;
        return;
    }

    while (std::getline(file, line)) {
        ignoreIPs.insert(line);
    }
}

bool IgnoreList::shouldIgnore(const std::string& ip) const {
    return ignoreIPs.find(ip) != ignoreIPs.end();
}