#include "pcap.h"

#include <iostream>
#include <string>

void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    printf("Packet captured length: %d\n", header->len);
    printf("Packet total length: %d\n", header->caplen);
    printf("Received at: %s", ctime((const time_t*)&header->ts.tv_sec));
    printf("\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];  // Error buffer
    pcap_if_t* alldevs, * device;    // List of devices
    pcap_t* handle;                 // Session handle

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Couldn't find default device: " << errbuf << std::endl;
        std::cin.get();
        return 2;
    }

    // Use the first device in the list
    device = alldevs;

    // Open the device for capturing
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Couldn't open device: " << device->name << " " << errbuf << std::endl;
        std::cin.get();
        return 2;
    }

    pcap_freealldevs(alldevs);
    pcap_loop(handle, 10, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
