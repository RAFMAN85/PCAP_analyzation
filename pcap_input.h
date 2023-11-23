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

#ifndef PCAP_TEST_PCAP_INPUT_H
#define PCAP_TEST_PCAP_INPUT_H

class PcapReader {
public:
    struct Packet {
        struct pcap_pkthdr header;
        const u_char *data;
        std::string src_ip;
        std::string dst_ip;
        struct timeval timestamp;
    };

private:
    std::vector<Packet> packets;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

public:
    PcapReader(const std::string& filename);

    const std::vector<Packet>& getPackets() const;
};

#endif //PCAP_TEST_PCAP_INPUT_H
