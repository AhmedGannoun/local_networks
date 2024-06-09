#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wpcap.lib")

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ARP_HWTYPE_ETHERNET 1
#define ARP_PROTOCOL_IP 0x0800
#define HW_ADDR_LEN 6
#define IP_ADDR_LEN 4

struct arp_header {
    unsigned short hw_type;
    unsigned short protocol_type;
    unsigned char hw_addr_len;
    unsigned char protocol_addr_len;
    unsigned short opcode;
    unsigned char sender_mac[HW_ADDR_LEN];
    unsigned char sender_ip[IP_ADDR_LEN];
    unsigned char target_mac[HW_ADDR_LEN];
    unsigned char target_ip[IP_ADDR_LEN];
};

void get_mac_address(const char *iface, unsigned char *mac_address) {
    PIP_ADAPTER_INFO adapter_info = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    ULONG size = sizeof(IP_ADAPTER_INFO);
    if (GetAdaptersInfo(adapter_info, &size) == ERROR_BUFFER_OVERFLOW) {
        adapter_info = (IP_ADAPTER_INFO *)malloc(size);
    }

    if (GetAdaptersInfo(adapter_info, &size) == NO_ERROR) {
        PIP_ADAPTER_INFO adapter = adapter_info;
        while (adapter) {
            if (strcmp(adapter->AdapterName, iface) == 0) {
                memcpy(mac_address, adapter->Address, HW_ADDR_LEN);
                break;
            }
            adapter = adapter->Next;
        }
    }

    free(adapter_info);
}

void create_arp_request(struct arp_header *arp_req, unsigned char *source_mac, unsigned char *source_ip, unsigned char *target_ip) {
    arp_req->hw_type = htons(ARP_HWTYPE_ETHERNET);
    arp_req->protocol_type = htons(ARP_PROTOCOL_IP);
    arp_req->hw_addr_len = HW_ADDR_LEN;
    arp_req->protocol_addr_len = IP_ADDR_LEN;
    arp_req->opcode = htons(ARP_REQUEST);
    memcpy(arp_req->sender_mac, source_mac, HW_ADDR_LEN);
    memcpy(arp_req->sender_ip, source_ip, IP_ADDR_LEN);
    memset(arp_req->target_mac, 0x00, HW_ADDR_LEN);
    memcpy(arp_req->target_ip, target_ip, IP_ADDR_LEN);
}

void print_mac_address(unsigned char *mac) {
    for (int i = 0; i < HW_ADDR_LEN; i++) {
        printf("%02x", mac[i]);
        if (i < HW_ADDR_LEN - 1) printf(":");
    }
}

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *adhandle;

    // Retrieve the device list
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    // Print the list and choose the first available device
    int i = 0;
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description) printf(" (%s)\n", d->description);
        else printf(" (No description available)\n");
    }

    if (i == 0) {
        printf("\nNo interfaces found! Make sure WinPcap/Npcap is installed.\n");
        return -1;
    }

    // Open the first available device
    adhandle = pcap_open_live(alldevs->name, 65536, 1, 1000, errbuf);
    if (adhandle == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", alldevs->name);
        pcap_freealldevs(alldevs);
        return -1;
    }

    unsigned char mac_address[HW_ADDR_LEN];
    get_mac_address(alldevs->name, mac_address);

    unsigned char source_ip[IP_ADDR_LEN] = {192, 168, 1, 100}; // Replace with your IP
    unsigned char target_ip[IP_ADDR_LEN] = {192, 168, 1, 1}; // Replace with the target IP

    unsigned char packet[42];
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct arp_header *arp_req = (struct arp_header *)(packet + 14);

    memset(eth->h_dest, 0xff, HW_ADDR_LEN);
    memcpy(eth->h_source, mac_address, HW_ADDR_LEN);
    eth->h_proto = htons(ETH_P_ARP);

    create_arp_request(arp_req, mac_address, source_ip, target_ip);

    if (pcap_sendpacket(adhandle, packet, 42) != 0) {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
        return -1;
    }

    struct pcap_pkthdr *header;
    const unsigned char *recv_packet;

    while (pcap_next_ex(adhandle, &header, &recv_packet) >= 0) {
        struct ethhdr *recv_eth = (struct ethhdr *)recv_packet;
        struct arp_header *arp_resp = (struct arp_header *)(recv_packet + 14);

        if (ntohs(recv_eth->h_proto) == ETH_P_ARP && ntohs(arp_resp->opcode) == ARP_REPLY) {
            printf("IP: %d.%d.%d.%d, MAC: ", arp_resp->sender_ip[0], arp_resp->sender_ip[1], arp_resp->sender_ip[2], arp_resp->sender_ip[3]);
            print_mac_address(arp_resp->sender_mac);
            printf("\n");
        }
    }

    pcap_freealldevs(alldevs);
    pcap_close(adhandle);

    return 0;
}
