#include <iostream>
#include <vector>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

class PcapReader {
private:
    struct Packet {
        struct pcap_pkthdr header;
        const u_char *data;
        std::string src_ip;
        std::string dst_ip;
    };

    std::vector<Packet> packets;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

public:
    PcapReader(const std::string& filename) {
        // Open the PCAP file
        handle = pcap_open_offline(filename.c_str(), errbuf);
        if (handle == nullptr) {
            std::cerr << "Error opening pcap file: " << errbuf << std::endl;
            return;
        }

        // Read packets into the vector
        struct pcap_pkthdr *header;
        const u_char *data;
        while (int returnValue = pcap_next_ex(handle, &header, &data) >= 0) {
            // Check if the packet is the last one
            if (returnValue == 0) {
                // Timeout elapsed
                break;
            }

            // Ensure that the packet is long enough to contain an Ethernet and IP header
            if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
                continue; // Packet is too short to process
            }

            // Check the Ethernet header for the type field to ensure it's an IP packet
            struct ether_header *eth_header = (struct ether_header *)data;
            if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
                // Skip the Ethernet header
                struct ip *ip_header = (struct ip*)(data + sizeof(struct ether_header));
                char src_ip[INET_ADDRSTRLEN];
                char dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

                // Add packet to the vector
                packets.push_back({*header, data, src_ip, dst_ip});
            }
        }

        pcap_close(handle);
    }

    void printFirst10Packets() {
        int count = 0;
        for (const auto& packet : packets) {
            if (count >= 10) break;
            std::cout << "Packet " << count + 1 << ": Source IP: " << packet.src_ip
                      << ", Destination IP: " << packet.dst_ip << std::endl;
            count++;
        }
    }
};

int main() {
    PcapReader reader("111.pcap");
    reader.printFirst10Packets();
    return 0;
}