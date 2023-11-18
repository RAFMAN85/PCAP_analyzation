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

class PcapReader {
public:
    struct Packet {
        struct pcap_pkthdr header;
        const u_char *data;
        std::string src_ip;
        std::string dst_ip;
        std::string timestamp;
    };

private:
    std::vector<Packet> packets;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

public:
    PcapReader(const std::string& filename) {
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

    const std::vector<Packet>& getPackets() const {
        return packets;
    }

    void printFirst10Packets() {
        int count = 0;
        for (const auto& packet : packets) {
            if (count >= 10) break;
            std::cout << "Packet " << count + 1 << ": Time: " << packet.timestamp
                      << ", Source IP: " << packet.src_ip
                      << ", Destination IP: " << packet.dst_ip << std::endl;
            count++;
        }
    }
};

class IPPacketStatistics {
private:
    std::map<std::string, std::vector<std::string>> srcIpToTimestamps;
    std::map<std::string, std::vector<std::string>> dstIpToTimestamps;

public:
    IPPacketStatistics(const std::vector<PcapReader::Packet>& packets) {
        for (const auto& packet : packets) {
            srcIpToTimestamps[packet.src_ip].push_back(packet.timestamp);
            dstIpToTimestamps[packet.dst_ip].push_back(packet.timestamp);
        }
    }

    void printStatistics() {
        // Пример вывода статистики для Source IP
        std::cout << "Source IP Statistics:" << std::endl;
        for (const auto& entry : srcIpToTimestamps) {
            std::cout << "Source IP: " << entry.first << ", Packet Times: ";
            for (const auto& time : entry.second) {
                std::cout << time << " ";
            }
            std::cout << std::endl;
        }

        // Пример вывода статистики для Destination IP
        std::cout << "Destination IP Statistics:" << std::endl;
        for (const auto& entry : dstIpToTimestamps) {
            std::cout << "Destination IP: " << entry.first << ", Packet Times: ";
            for (const auto& time : entry.second) {
                std::cout << time << " ";
            }
            std::cout << std::endl;
        }
    }
};

int main() {
    PcapReader reader("111.pcap");
    reader.printFirst10Packets();

    IPPacketStatistics stats(reader.getPackets());
    stats.printStatistics();

    return 0;
}
