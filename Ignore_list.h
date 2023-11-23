#include <set>
#include <string>
#include <fstream>
#include <iostream>

#ifndef PCAP_TEST_IGNORE_LIST_H
#define PCAP_TEST_IGNORE_LIST_H

class IgnoreList {
private:
    std::set<std::string> ignoreIPs;

public:
    IgnoreList(const std::string& filename);

    bool shouldIgnore(const std::string& ip) const;
};



#endif //PCAP_TEST_IGNORE_LIST_H
