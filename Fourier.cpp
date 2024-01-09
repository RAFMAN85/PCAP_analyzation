#include "Fourier.h"

std::vector<PcapReader::Packet> FourierTransform::findPseudoperiodPackets(const std::vector<PcapReader::Packet>& packets, double threshold, const IgnoreList& ignoreList, int* peakCount) {
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


    *peakCount = std::count_if(amplitudes.begin(), amplitudes.end(), [threshold](double amp) {
        return amp > threshold;
    });



    std::vector<PcapReader::Packet> pseudoperiodPackets;
    for (size_t i = 0; i < amplitudes.size(); ++i) {
        if (amplitudes[i] > threshold && i < packets.size()) {
            pseudoperiodPackets.push_back(packets[i]);
        }
    }




    return pseudoperiodPackets;
}

void computeTimestampStatistics(const std::vector<PcapReader::Packet>& packets, double& mean, double& variance) {
    if (packets.empty()) {
        mean = 0;
        variance = 0;
        return;
    }

    std::vector<double> timestamps;
    for (const auto& packet : packets) {
        double time = packet.timestamp.tv_sec + packet.timestamp.tv_usec / 1e6; // С учетом микросекунд
        timestamps.push_back(time);
    }

    double sum = 0.0;
    for (double time : timestamps) {
        sum += time;
    }
    mean = sum / timestamps.size();

    double sq_sum = 0.0;
    for (double time : timestamps) {
        sq_sum += std::pow(time - mean, 2);
    }
    variance = sq_sum / (timestamps.size() - 1);

}



