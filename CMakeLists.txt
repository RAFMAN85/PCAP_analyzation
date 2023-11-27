cmake_minimum_required(VERSION 3.25)
project(pseudo-pcap-analyze VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 23)

add_executable(pseudo-pcap-analyze main.cpp
        pcap_input.h
        pcap_input.h
        pcap_input.cpp
        pcap_input.cpp
        Fourier.cpp
        Fourier.h
        Ignore_list.cpp
        Ignore_list.h
)

target_link_libraries(pseudo-pcap-analyze pcap)