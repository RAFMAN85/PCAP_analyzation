#include <iostream>
#include <vector>
#include <map>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <ctime>
#include <iomanip>
#include <sstream>
#include "pcap_input.h"

#ifndef PCAP_TEST_IP_STATISTICS_H
#define PCAP_TEST_IP_STATISTICS_H

class IPPacketStatistics {
private:
    std::map<std::string, std::vector<std::string>> srcIpToTimestamps;
    std::map<std::string, std::vector<std::string>> dstIpToTimestamps;

public:
    IPPacketStatistics(const std::vector<PcapReader::Packet>& packets);

    void printStatistics();
};



#endif
