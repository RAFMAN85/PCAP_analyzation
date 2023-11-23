//
// Created by Raf Modzgvrishvili on 23.11.2023.
//

#include "Fourier.h"

std::vector<PcapReader::Packet> FourierTransform::findPseudoperiodPackets(const std::vector<PcapReader::Packet>& packets, double threshold, const IgnoreList& ignoreList) {
    std::vector<double> timestamps;

    for (const auto& packet : packets) {
        if (!ignoreList.shouldIgnore(packet.src_ip) && !ignoreList.shouldIgnore(packet.dst_ip)) {
            double time = packet.timestamp.tv_sec + packet.timestamp.tv_usec / 1e6;
            timestamps.push_back(time);
        }
    }

    auto fftResult = computeFFT(timestamps);
    std::vector<double> amplitudes(fftResult.size());

    std::transform(fftResult.begin(), fftResult.end(), amplitudes.begin(), [](std::complex<double> c) {
        return std::abs(c);
    });

    std::vector<PcapReader::Packet> pseudoperiodPackets;
    for (size_t i = 0; i < amplitudes.size(); ++i) {
        if (amplitudes[i] > threshold && i < packets.size()) {
            pseudoperiodPackets.push_back(packets[i]);
        }
    }

    return pseudoperiodPackets;
}