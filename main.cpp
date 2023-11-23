#include <iostream>
#include "pcap_input.h"
#include "Fourier.h"


int main() {
    std::string pcapFile = "111.pcap";
    std::string ignoreListFile = "ignore_ips.txt";
    double threshold = 1.0;

    PcapReader reader(pcapFile);
    FourierTransform ft;
    IgnoreList ignoreList(ignoreListFile);

    auto pseudoperiodPackets = ft.findPseudoperiodPackets(reader.getPackets(), threshold, ignoreList);


    for (const auto& packet : pseudoperiodPackets) {
        char timestampStr[64];
        struct tm *ltime;
        time_t local_tv_sec = packet.timestamp.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestampStr, sizeof timestampStr, "%Y-%m-%d %H:%M:%S", ltime);
        std::cout << "Pseudoperiod Packet: Source IP: " << packet.src_ip
                  << ", Destination IP: " << packet.dst_ip
                  << ", Timestamp: " << timestampStr << "." << packet.timestamp.tv_usec
                  << std::endl;
    }

    return 0;
}
