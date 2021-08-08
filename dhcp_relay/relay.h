
#include <iostream>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <pcap.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <err.h>
#include <string>
#include <vector>
#include <thread>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <bits/stdc++.h>
#include <syslog.h>
#include <map>

#ifndef RELAY_HEADER
#define RELAY_HEADER

#define PCAP_ERRBUF_SIZE 256
#define ETHERNETHDR_LENGTH 14
#define IPV6HDR_LENGTH 40
#define UDPHDR_NUMB 17
#define UDPHDR_LENGTH 8
#define SERVER_PORT 547
#define CLIENT_PORT 546
#define IANA 3
#define IATA 4
#define IA 5
#define IAPD 25
#define IAPREFIX 26

using namespace std;

    //extern char *serverip;
    struct ipv6_header
    {
        unsigned int
            version : 4,
            traffic_class : 8,
            flow_label : 20;
        uint16_t length;
        uint8_t next_header;
        uint8_t hop_limit;
        struct in6_addr src;
        struct in6_addr dst;
    };

    struct dhcpv6_relay
    {
        uint8_t relay_flag;
        uint8_t hop_count;
        in6_addr link_address;
        in6_addr peer_address;
    } __attribute__((packed));

    struct options
    {
        uint16_t client_linklayer_flag;
        uint16_t option_length;
        uint16_t link_layer_type;
        uint8_t mac_addr[6];
    } __attribute__((packed));

    struct relay_message
    {
        uint16_t relay_messsage;
        uint16_t length_dhcp;
    } __attribute__((packed));

    struct interface_id
    {
        uint16_t option;
        uint16_t length_id;
        uint8_t id[20];
    } __attribute__((packed));
    ;

    void start_relay(vector<string> interfaces, char *server, bool debug_bool, bool log_bool);
    int get_iplength(const u_char *payload);
    void capture_dhcp(string interface);
    void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body);
    int forward_dhcp(char *mac, char *dhcpdata, int dhcpsize, char *ipv6src, char *interfaceip, char *dev);
    char* getipofinterface(char *interface);
    void packet_handler(struct pcap_pkthdr *header, const u_char *packetdata, char *interfaceip, char *dev);
    int forward_toclient(char *dhcpdata);
    int getindexofinterface(char *ip, char *interface);
    void capturefromserver();

#endif