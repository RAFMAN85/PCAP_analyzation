cmake_minimum_required(VERSION 3.25)
project(PCAP_test)

set(CMAKE_CXX_STANDARD 23)

add_executable(PCAP_test main.cpp
        pcap_input.h
        pcap_input.h
        pcap_input.cpp
        pcap_input.cpp
        Fourier.cpp
        Fourier.h
        Ignore_list.cpp
        Ignore_list.h
)

target_link_libraries(PCAP_test pcap)