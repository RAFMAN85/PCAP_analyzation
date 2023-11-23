#include "ip_statistics.h"

IPPacketStatistics::IPPacketStatistics(const std::vector<PcapReader::Packet>& packets) {
    for (const auto& packet : packets) {
        srcIpToTimestamps[packet.src_ip].push_back(packet.timestamp);
        dstIpToTimestamps[packet.dst_ip].push_back(packet.timestamp);
    }
}

void IPPacketStatistics::printStatistics() {
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