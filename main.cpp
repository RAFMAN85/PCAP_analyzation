#include <iostream>
#include <vector>
#include <map>
#include "pcap_input.h"
#include "ip_statistics.h"


int main() {
    PcapReader reader("111.pcap");
    reader.printFirst10Packets();

    IPPacketStatistics stats(reader.getPackets());
    stats.printStatistics();

    return 0;
}
