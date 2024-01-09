#include "pcap_input.h"
#include "Ignore_list.h"
#include <vector>
#include <complex>
#include <cmath>
#include <sstream>
#include <numeric>

#ifndef PCAP_TEST_FOURIER_H
#define PCAP_TEST_FOURIER_H


class FourierTransform {
private:
    std::vector<std::complex<double>> computeFFT(const std::vector<double>& data) {
        int n = data.size();
        std::vector<std::complex<double>> output(n);

        for (int k = 0; k < n; ++k) {
            std::complex<double> sum(0.0, 0.0);
            for (int t = 0; t < n; ++t) {
                double angle = 2 * M_PI * t * k / n;
                sum += data[t] * std::complex<double>(cos(angle), -sin(angle));
            }
            output[k] = sum;
        }

        return output;
    }

public:
    std::vector<PcapReader::Packet> findPseudoperiodPackets(const std::vector<PcapReader::Packet>& packets, double threshold, const IgnoreList& ignoreList);
};

void computeTimestampStatistics(const std::vector<PcapReader::Packet>& packets, double& mean, double& variance);


#endif //PCAP_TEST_FOURIER_H
