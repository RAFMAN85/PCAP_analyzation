#include <iostream>
#include "pcap_input.h"
#include "Fourier.h"


int main(int argc, char* argv[]) {

//    if(argc==1){
//        std::cout<<"Usage: ./pseudo-pcap-analyze your_pcap threshold\n";
//        std::cout<<"or ./pseudo-pcap-analyze your_pcap threshold list_ignore_ips\n";
//        return 0;
//    }

    std::string pcapFile = argv[1];
    double threshold = atof(argv[2]);
    std::string ignoreListFile = (argc>3) ? argv[3] : "";

    PcapReader reader(pcapFile);
    FourierTransform ft;
    IgnoreList ignoreList(ignoreListFile);

    auto pseudoperiodPackets = ft.findPseudoperiodPackets(reader.getPackets(), threshold, ignoreList);

    double mean, variance;
    computeTimestampStatistics(pseudoperiodPackets, mean, variance);

    std::cout << "Среднее значение временных меток: " << mean << "\n";
    std::cout << "Дисперсия временных меток: " << variance << "\n";


//    for (const auto& packet : pseudoperiodPackets) {
//        char timestampStr[64];
//        struct tm *ltime;
//        time_t local_tv_sec = packet.timestamp.tv_sec;
//        ltime = localtime(&local_tv_sec);
//        strftime(timestampStr, sizeof timestampStr, "%Y-%m-%d %H:%M:%S", ltime);
//        std::cout << "Pseudoperiod Packet: Source IP: " << packet.src_ip
//                  << ", Destination IP: " << packet.dst_ip
//                  << ", Timestamp: " << timestampStr << "." << packet.timestamp.tv_usec
//                  << std::endl;
//    }

    return 0;
}
