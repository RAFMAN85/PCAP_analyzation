#include "Fourier.h"

std::vector<PcapReader::Packet> FourierTransform::findPseudoperiodPackets(const std::vector<PcapReader::Packet>& packets, double threshold, const IgnoreList& ignoreList) {
    std::vector<double> timestamps;

    for (const auto& packet : packets) {
        if (!ignoreList.shouldIgnore(packet.src_ip) && !ignoreList.shouldIgnore(packet.dst_ip)) {
            //double timeInMonths = (packet.timestamp.tv_sec / (86400.0 * 30.44));//с учетом месяцев
            //double timeInWeeks = (packet.timestamp.tv_sec / (86400.0 * 7));//с учетом недель
            //double timeInDays = (packet.timestamp.tv_sec / 86400.0);//с учетом дней
            //double time = (packet.timestamp.tv_sec / 3600.0); //с учетом часов
            //double time = (packet.timestamp.tv_sec / 60.0); //с учетом минут
            double time = packet.timestamp.tv_sec + packet.timestamp.tv_usec / 1e6; //с учетом милисекунд
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