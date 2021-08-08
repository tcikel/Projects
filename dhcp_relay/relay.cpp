
#include "relay.h"
//Global variable for all threads
char *serverip = NULL;
map<string, string> macmap;
bool debug;
bool mylog;

char *getipofinterface(char *interface)
{
    //Allocate field for ip
    char *interfaceipfield = (char *)malloc(INET6_ADDRSTRLEN);
    struct ifaddrs *ifa, *ifa_tmp;
    if (getifaddrs(&ifa) == -1)
    {
        cerr << "Failed to check adress if interface\n";
        exit(-1);
    }
    ifa_tmp = ifa;
    //loop through field
    while (ifa_tmp)
    {
        //if we find interface and it has ipv6 we store it
        if (strcmp(ifa_tmp->ifa_name, interface) == 0 && ifa_tmp->ifa_addr->sa_family == AF_INET6)
        {
            struct sockaddr_in6 *ip6addr = (struct sockaddr_in6 *)ifa_tmp->ifa_addr;
            inet_ntop(AF_INET6, &ip6addr->sin6_addr, interfaceipfield, INET6_ADDRSTRLEN);
            break;
        }
        ifa_tmp = ifa_tmp->ifa_next;
    }
    return interfaceipfield;
}

//get index of interface which has ip
int getindexofinterface(char *ip, char *interface)
{
    struct ifaddrs *ifa, *ifa_tmp;
    char interfaceip[INET6_ADDRSTRLEN];
    if (getifaddrs(&ifa) == -1)
    {
        cerr << "Failed to check adress if interface\n";
        return -1;
    }
    ifa_tmp = ifa;
    //loop through fielff
    while (ifa_tmp)
    {
        //if interface has ipv6
        if (ifa_tmp->ifa_addr->sa_family == AF_INET6)
        {
            struct sockaddr_in6 *ip6addr = (struct sockaddr_in6 *)ifa_tmp->ifa_addr;
            inet_ntop(AF_INET6, &ip6addr->sin6_addr, interfaceip, INET6_ADDRSTRLEN);
            //compare interface names
            if (strncmp(ip, interfaceip, INET6_ADDRSTRLEN) == 0)
            {
                strncpy(interface, ifa_tmp->ifa_name, strlen(ifa_tmp->ifa_name));
                //return index of interface
                return if_nametoindex(ifa_tmp->ifa_name);
            }
        }
        ifa_tmp = ifa_tmp->ifa_next;
    }
    return -1;
}

void start_relay(vector<string> interfaces, char *server, bool debug_bool, bool log_bool)
{
    //create thread array
    thread relay_threads[interfaces.size() + 1];
    serverip = server;
    debug = debug_bool;
    mylog = log_bool;
    unsigned int i = 0;

    //Start new thread for every interfaces which we want to sniff
    for (; i < interfaces.size(); i++)
    {
        relay_threads[i] = thread(capture_dhcp, interfaces[i]);
    }
    //Thread for recieving packets from server
    relay_threads[i] = thread(capturefromserver);

    //Join threads back together
    for (unsigned int y = 0; y < interfaces.size() + 1; y++)
    {
        relay_threads[y].join();
    }
}

void capture_dhcp(string interface)
{
    //field for interface name
    char dev[20];
    strcpy(dev, interface.c_str());
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    char *interfaceip = getipofinterface(dev);
    pcap_t *handle;
    struct bpf_program filter;
    const u_char *packetdata;
    //filter to only catch DHCPv6
    const char filter_exp[] = "udp and port 547";

    //Open interface
    if ((handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL)
    {
        cerr << "Failed to open interface for sniffing" << dev;
        exit(-1);
    }
    //compile filter
    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        cerr << "Couldnt apply filter";
        exit(-1);
    }
    //Set filter
    if (pcap_setfilter(handle, &filter) == -1)
    {
        cerr << "Error during setting the filter";
        exit(-1);
    }

    //listen all the time call handler fucntion if packet is recieved
    while (1)
    {
        if ((packetdata = pcap_next(handle, &header)) != NULL)
        {
            packet_handler(&header, packetdata, interfaceip, dev);
        }
    }
    return;
}

int get_iplength(const u_char *payload)
{
    int size = IPV6HDR_LENGTH;
    int i = 0;
    //if next header is udp just return defualt length of ipv6
    if (payload[i] == 17)
    {
        return size;
    }
    else
    {
        i = i + size;
        while (payload[size] != 17)
        {
            size = size + payload[size] + 8;
        }
        return size;
    }
}

void packet_handler(struct pcap_pkthdr *packet_header, const u_char *packet_body, char *interfaceip, char *dev)
{
    //Map packet on structures
    const struct pcap_pkthdr pckt_header = *packet_header;
    struct ether_header *eptr = (struct ether_header *)packet_body;
    struct ipv6_header *ipheader = (struct ipv6_header *)(packet_body + ETHERNETHDR_LENGTH);
    const u_char *payload;
    //create buffers
    char ipv6src[INET6_ADDRSTRLEN];
    char *dhcpdata;
    //get length of ipv6 header and its extensions
    int ipv6length = get_iplength(packet_body + ETHERNETHDR_LENGTH + 6);
    //CLear array,just to amke sure its all clean, for debug
    memset(ipv6src, 0, sizeof(ipv6src));
    inet_ntop(AF_INET6, &ipheader->src, ipv6src, sizeof(ipv6src));

    int cut = ETHERNETHDR_LENGTH + UDPHDR_LENGTH + ipv6length;
    //calculate dhcpsize
    int dhcpsize = pckt_header.caplen - cut;
    //Jump to start of dhcpmessage
    payload = packet_body + cut;
    //Check if message is type which we are supposed to forward
    if (payload[0] == 1 || payload[0] == 3 || payload[0] == 4 || payload[0] == 5 || payload[0] == 6 || payload[0] == 8 || payload[0] == 9 || payload[0] == 11)
    {
        //Allocate buffer for data

        dhcpdata = (char *)malloc(sizeof(char) * (pckt_header.caplen - cut));
        memcpy(dhcpdata, payload, dhcpsize);
        forward_dhcp(ether_ntoa((const struct ether_addr *)&eptr->ether_shost), dhcpdata, dhcpsize, ipv6src, interfaceip, dev);
    }
}

int forward_dhcp(char *mac, char *dhcpdata, int dhcpsize, char *ipv6src, char *interfaceip, char *dev)
{
    struct sockaddr_in6 server;
    int sock;
    int struct_size;
    struct dhcpv6_relay dhcp_struct;
    struct options dhcpoptions;
    struct relay_message re_message;
    struct interface_id interfaceoption;
    uint8_t *options;

    //If message is Solicit add pair to map
    if (dhcpdata[0] == 1)
    {
        macmap.insert(make_pair(ipv6src, mac));
    }

    //FIll dhcp structs
    dhcp_struct.hop_count = 0;
    inet_pton(AF_INET6, ipv6src, &dhcp_struct.peer_address);
    inet_pton(AF_INET6, interfaceip, &dhcp_struct.link_address);
    dhcp_struct.relay_flag = 12;

    //Allocate space for options buffer
    options = (uint8_t *)malloc(sizeof(uint8_t) * 12);
    dhcpoptions.client_linklayer_flag = htons(79);
    dhcpoptions.option_length = htons(8);
    dhcpoptions.link_layer_type = htons(1);
    re_message.relay_messsage = htons(9);
    re_message.length_dhcp = htons(dhcpsize);
    interfaceoption.option = htons(18);
    interfaceoption.length_id = htons(20);
    memcpy(interfaceoption.id, dev, 20);

    //interfaceoption.length_id=htons()

    //copy Mac address
    sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dhcpoptions.mac_addr[0], &dhcpoptions.mac_addr[1], &dhcpoptions.mac_addr[2], &dhcpoptions.mac_addr[3], &dhcpoptions.mac_addr[4], &dhcpoptions.mac_addr[5]);
    memcpy(options, &dhcpoptions, sizeof(dhcpoptions));

    //copy struct to buffer
    char buffer[sizeof(dhcp_struct) + dhcpsize + 16];
    memcpy(buffer, &dhcp_struct, sizeof(dhcp_struct));
    memcpy(buffer + sizeof(dhcp_struct), options, 12);
    memcpy(buffer + sizeof(dhcp_struct) + 12, &re_message, 4);
    memcpy(buffer + sizeof(dhcp_struct) + 16, dhcpdata, dhcpsize);
    memcpy(buffer + sizeof(dhcp_struct) + 16 + dhcpsize, &interfaceoption, sizeof(interfaceoption));
    //Size of the final message
    struct_size = sizeof(dhcp_struct) + 16 + dhcpsize + sizeof(interfaceoption);

    //create socket
    if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
    {
        cerr << "socket() failed\n";
        exit(-1);
    }

    //fill the adress and destination port
    inet_pton(AF_INET6, serverip, &server.sin6_addr);
    server.sin6_family = AF_INET6;
    server.sin6_port = htons(SERVER_PORT);

    //Send message to server
    if (sendto(sock, buffer, struct_size, 0, (struct sockaddr *)&server, sizeof(server)) == -1)
    {

        cerr << "sednto() failed: Destination might be unreachable, check if you have inserted the correct ipv6 address";
        exit(-1);
    }

    free(dhcpdata);
    free(options);

    return 0;
}

int forward_toclient(char *dhcpdata)
{
    struct sockaddr_in6 client;
    struct sockaddr_in6 interface;
    struct dhcpv6_relay *dhcp = (struct dhcpv6_relay *)dhcpdata;
    int sock;

    char interfaceip[INET6_ADDRSTRLEN];
    char destinationip[INET6_ADDRSTRLEN];
    char clienip[INET6_ADDRSTRLEN];
    char interfacename[100];
    uint16_t dhcpsize;

    //clear buffer...for debug
    memset(interfacename, 0, sizeof(interfacename));
    inet_ntop(AF_INET6, &dhcp->link_address, interfaceip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &dhcp->peer_address, destinationip, INET6_ADDRSTRLEN);
    uint16_t dhcpoption;

    //This will be our byte "pointer"
    int i = 34;

    //get option number
    dhcpoption = ntohs(*(uint16_t *)(dhcpdata + i));

    //loop while we done get relay message
    while (dhcpoption != 9)
    {
        i = i + 2;
        uint16_t size = ntohs(*(uint16_t *)(dhcpdata + i));
        i = i + size + 2;
        dhcpoption = ntohs(*(uint16_t *)(dhcpdata + i));
    }

    i = i + 2;
    //get option number
    dhcpsize = ntohs(*(uint16_t *)(dhcpdata + i));
    //Create buffer for message without relay-reply part
    char dhcpmessage[dhcpsize];
    memcpy(dhcpmessage, dhcpdata + i + 2, dhcpsize);
    i = i + 2;
    //check if it a replay message
    if (dhcpdata[i] == 7)
    {
        //check if we want to display anything and if we didnt already display it(after that we removed it)
        if ((debug == true || mylog == true) && (macmap.count(destinationip)))
        {
            i = i + 4;
            dhcpoption = ntohs(*(uint16_t *)(dhcpdata + i));
            int y = 0;
            //Find option which we want to display
            //MAYBE REWORK THIS if there is time
            while (dhcpoption != 3 && dhcpoption != 4 && dhcpoption != 26)
            {
                i = i + ntohs(*(uint16_t *)(dhcpdata + i));
                y = y + ntohs(*(uint16_t *)(dhcpdata + i));
                if (y > dhcpsize)
                {
                    break;
                }
                dhcpoption = ntohs(*(uint16_t *)(dhcpdata + i));
            }

            if (dhcpoption == IANA || dhcpoption == IAPD)
            {
                uint16_t sizeofthisoption = ntohs(*(uint16_t *)(dhcpdata + i + 2)) - 16;
                //jump over stuff we dont care about
                i = i + 16;
                dhcpoption = ntohs(*(uint16_t *)(dhcpdata + i));
                //jump over option while we dont find the ones we want
                while (dhcpoption != IAPREFIX && dhcpoption != IA)
                {
                    //add size of this option so we move to next option
                    i = i + 4 + ntohs(*(uint16_t *)(dhcpdata + 2 + i));
                    sizeofthisoption = sizeofthisoption - 4 - ntohs(*(uint16_t *)(dhcpdata + 2 + i) + 4);
                    dhcpoption = ntohs(*(uint16_t *)(dhcpdata + i + 2));
                    //check if we are too far
                    if (sizeofthisoption <= 0)
                    {
                        break;
                    }
                }
                //Print data from specified option
                if (dhcpoption == IA)
                {
                    inet_ntop(AF_INET6, dhcpdata + i + 4, clienip, INET6_ADDRSTRLEN);
                    if (debug == true)
                    {
                        cout << "CLIENT IP: " << clienip << endl;
                        cout << "MAC ADDRESS: " << macmap.find(destinationip)->second.c_str() << endl;
                    }
                    if (mylog == true)
                    {
                        syslog(LOG_INFO, "CLIENT IP: %s", clienip);
                        syslog(LOG_INFO, "MAC ADDRESS: %s", macmap.find(destinationip)->second.c_str());
                    }
                }
                //Print data from specified option
                else if (dhcpoption == IAPREFIX)
                {
                    i = i + 12;
                    int prefix_length = atoi(dhcpdata + i);
                    char ipv6_prefix[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, ipv6_prefix, dhcpdata + i + 1, INET6_ADDRSTRLEN);
                    if (debug == true)
                    {
                        cout << ipv6_prefix << "/" << prefix_length << endl;
                        cout << "MAC ADDRESS: " << macmap.find(destinationip)->second.c_str() << endl;
                    }
                    if (mylog == true)
                    {
                        syslog(LOG_INFO, " CLIENT IP: %s/%d", ipv6_prefix, prefix_length);
                        syslog(LOG_INFO, " MAC ADDRESS: %s", macmap.find(destinationip)->second.c_str());
                    }
                }
            }

            if (dhcpoption == IATA)
            {
                uint16_t sizeofthisoption = ntohs(*(uint16_t *)(dhcpdata + i + 2)) - 8;
                i = i + 8;
                dhcpoption = ntohs(*(uint16_t *)(dhcpdata + i));
                //jump over option while we dont find the ones we want
                while (dhcpoption != IAPREFIX && dhcpoption != IA)
                {
                    i = i + 4 + ntohs(*(uint16_t *)(dhcpdata + 2 + i));
                    sizeofthisoption = sizeofthisoption - 4 - ntohs(*(uint16_t *)(dhcpdata + 2 + i));
                    dhcpoption = ntohs(*(uint16_t *)(dhcpdata + i + 2));
                    if (sizeofthisoption <= 0)
                    {
                        break;
                    }
                }
                //Print data from specified option
                if (dhcpoption == IA)
                {
                    inet_ntop(AF_INET6, dhcpdata + i + 4, clienip, INET6_ADDRSTRLEN);
                    if (debug == true)
                    {
                        cout << "CLIENT IP: " << clienip << endl;
                        cout << "MAC ADDRESS: " << macmap.find(destinationip)->second << endl;
                    }
                    if (mylog == true)
                    {
                        syslog(LOG_INFO, "CLIENT IP:%s", clienip);
                        syslog(LOG_INFO, "MAC ADDRESS: %s", macmap.find(destinationip)->second.c_str());
                    }
                }
            }
            //remove key so we dont print it more than once
            macmap.erase(destinationip);
        }
    }

    //create socket for sending to client
    if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
    {
        cerr << "socket() fauled" << endl;
        exit(-1);
    }

    //fill the adress

    inet_pton(AF_INET6, destinationip, &client.sin6_addr);
    client.sin6_family = AF_INET6;
    client.sin6_port = htons(CLIENT_PORT);
    //if address is link local we need index
    client.sin6_scope_id = getindexofinterface(interfaceip, interfacename);

    interface.sin6_family = AF_INET6;
    inet_pton(AF_INET6, interfaceip, (void *)&interface.sin6_addr.s6_addr);
    interface.sin6_port = 0; // 0 means the OS picks the port
    //if address is link local we need index
    interface.sin6_scope_id = getindexofinterface(interfaceip, interfacename);

    //bind to specific interface
    if (bind(sock, (struct sockaddr *)&interface, sizeof(interface)) == -1)
    {
        cerr << "Failed to bind socket to its interface" << endl;
        exit(1);
    }

    // check if data was sent correctly
    if (sendto(sock, dhcpmessage, dhcpsize, 0, (struct sockaddr *)&client, sizeof(client)) == -1)
    {
        perror("sendto() failed");
    }

    return 0;
}

void capturefromserver()
{
    struct sockaddr_in6 relay; //Struct to bind interface to port
    int recieve_sock;
    char recvbuffer[2000];
    memset(recvbuffer, 0, sizeof(recvbuffer));

    //Create socket
    if ((recieve_sock = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
    {
        cerr << "socket() fauled" << endl;
        exit(-1);
    }

    //fill the struct to bind
    relay.sin6_family = AF_INET6;
    relay.sin6_addr = in6addr_any;
    relay.sin6_port = htons(SERVER_PORT);
    //bind socket to interface
    int bind_check = bind(recieve_sock, (struct sockaddr *)&relay, sizeof(relay));
    if (bind_check == -1)
    {
        cerr << " Recv bind() failed" << endl;
    }
    //Recv messages from server
    while (1)
    {
        recvfrom(recieve_sock, (char *)recvbuffer, 2000, 0, (struct sockaddr *)&relay, (socklen_t *)sizeof(relay));
        forward_toclient(recvbuffer);
    }
    return;
}