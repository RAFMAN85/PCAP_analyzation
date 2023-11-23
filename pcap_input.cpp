#include "pcap_input.h"


PcapReader::PcapReader(const std::string& filename) {
    handle = pcap_open_offline(filename.c_str(), errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return;
    }

    struct pcap_pkthdr *header;
    const u_char *data;
    while (int returnValue = pcap_next_ex(handle, &header, &data) >= 0) {
        if (returnValue == 0) break;

        if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
            continue;
        }

        struct ether_header *eth_header = (struct ether_header *)data;
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            struct ip *ip_header = (struct ip*)(data + sizeof(struct ether_header));
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

            std::stringstream ss;
            ss << header->ts.tv_sec << "." << std::setfill('0') << std::setw(6) << header->ts.tv_usec;

            packets.push_back({*header, data, src_ip, dst_ip, ss.str()});
        }
    }

    pcap_close(handle);
}

const std::vector<PcapReader::Packet>& PcapReader::getPackets() const {
    return packets;
}

void PcapReader::printFirst10Packets() {
    int count = 0;
    for (const auto& packet : packets) {
        if (count >= 10) break;
        std::cout << "Packet " << count + 1 << ": Time: " << packet.timestamp
                  << ", Source IP: " << packet.src_ip
                  << ", Destination IP: " << packet.dst_ip << std::endl;
        count++;
    }
}