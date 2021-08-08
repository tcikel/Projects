//Name: Tomas Cikel
//Login: xcikel00
//Date: 21.4.2019

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <linux/if_link.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <cstring>
#include <bits/stdc++.h>
#include <signal.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include "Arguments.h"

#define IP4_HDRLEN 20 // IPv4 header length
#define TCP_HDRLEN 20 // TCP header length
#define UDP_HDRLEN 8	// UDP header length
using namespace std;

//global variables which we are gonna use for handaling pcap and output
pcap_t *handle;
struct pcap_pkthdr packet_header;
vector<vector<string>> outputtcp;
vector<vector<string>> outputudp;
vector<string> info;
string portinfo;
struct bpf_program f;

//alarm handling function to stop pcap_loop
static void alarmhandler(int signo)
{
	pcap_breakloop(handle);
}

//function to check captured TCP packet
void my_packet_handler_tcp(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{
	struct tcphdr *tcphdrecv = NULL;											//create tcpheader
	tcphdrecv = (struct tcphdr *)(packet_body + 14 + 20); //insert tcp header from packet into struct
	if ((tcphdrecv->th_flags & TH_RST) and (tcphdrecv->th_flags & TH_ACK))
	{														//check flags
		portinfo = "CLOSED PORT"; //insert into output
		info.push_back(portinfo);
	}
	else
	{
		portinfo = "OPEN PORT";
		info.push_back(portinfo);
	}
	return;
}

//function to handle captured ICMP packet
void my_packet_handler_udp(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{
	portinfo = "CLOSED PORT";
	info.push_back(portinfo);
	return;
}

/*
@citation
licence=GNU Genereal Public License
title=tcp4.c
author= P.D. Buchan (pdbuchan@yahoo.com)
date=2011-2015
source=http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
*/

uint16_t checksum(uint16_t *addr, int len)
{
	int count = len;
	register uint32_t sum = 0;
	uint16_t answer = 0;
	while (count > 1)
	{
		sum += *(addr++);
		count -= 2;
	}
	if (count > 0)
	{
		sum += *(uint8_t *)addr;
	}
	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}
	answer = ~sum;
	return (answer);
}

/*
@citation
licence=GNU Genereal Public License
title=tcp4.c
author= P.D. Buchan (pdbuchan@yahoo.com)
date=2011-2015
source=http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
*/
uint16_t tcp4_checksum(struct ip iphdr, struct tcphdr tcphdr)
{
	uint16_t svalue;
	char buf[IP_MAXPACKET], cvalue;
	char *ptr;
	int chksumlen = 0;
	ptr = &buf[0];
	memcpy(ptr, &iphdr.ip_src.s_addr, sizeof(iphdr.ip_src.s_addr));
	ptr += sizeof(iphdr.ip_src.s_addr);
	chksumlen += sizeof(iphdr.ip_src.s_addr);
	memcpy(ptr, &iphdr.ip_dst.s_addr, sizeof(iphdr.ip_dst.s_addr));
	ptr += sizeof(iphdr.ip_dst.s_addr);
	chksumlen += sizeof(iphdr.ip_dst.s_addr);
	*ptr = 0;
	ptr++;
	chksumlen += 1;
	memcpy(ptr, &iphdr.ip_p, sizeof(iphdr.ip_p));
	ptr += sizeof(iphdr.ip_p);
	chksumlen += sizeof(iphdr.ip_p);
	svalue = htons(sizeof(tcphdr));
	memcpy(ptr, &svalue, sizeof(svalue));
	ptr += sizeof(svalue);
	chksumlen += sizeof(svalue);
	memcpy(ptr, &tcphdr.th_sport, sizeof(tcphdr.th_sport));
	ptr += sizeof(tcphdr.th_sport);
	chksumlen += sizeof(tcphdr.th_sport);
	memcpy(ptr, &tcphdr.th_dport, sizeof(tcphdr.th_dport));
	ptr += sizeof(tcphdr.th_dport);
	chksumlen += sizeof(tcphdr.th_dport);
	memcpy(ptr, &tcphdr.th_seq, sizeof(tcphdr.th_seq));
	ptr += sizeof(tcphdr.th_seq);
	chksumlen += sizeof(tcphdr.th_seq);
	memcpy(ptr, &tcphdr.th_ack, sizeof(tcphdr.th_ack));
	ptr += sizeof(tcphdr.th_ack);
	chksumlen += sizeof(tcphdr.th_ack);
	cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
	memcpy(ptr, &cvalue, sizeof(cvalue));
	ptr += sizeof(cvalue);
	chksumlen += sizeof(cvalue);
	memcpy(ptr, &tcphdr.th_flags, sizeof(tcphdr.th_flags));
	ptr += sizeof(tcphdr.th_flags);
	chksumlen += sizeof(tcphdr.th_flags);
	memcpy(ptr, &tcphdr.th_win, sizeof(tcphdr.th_win));
	ptr += sizeof(tcphdr.th_win);
	chksumlen += sizeof(tcphdr.th_win);
	*ptr = 0;
	ptr++;
	*ptr = 0;
	ptr++;
	chksumlen += 2;
	memcpy(ptr, &tcphdr.th_urp, sizeof(tcphdr.th_urp));
	ptr += sizeof(tcphdr.th_urp);
	chksumlen += sizeof(tcphdr.th_urp);
	return checksum((uint16_t *)buf, chksumlen);
}

/*
@citation
licence=GNU Genereal Public License
title=udp4.c
author= P.D. Buchan (pdbuchan@yahoo.com)
date=2011-2015
source=http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
*/
uint16_t udp4_checksum(struct ip iphdr, struct udphdr udphdr)
{
	char buf[IP_MAXPACKET];
	char *ptr;
	int chksumlen = 0;
	int i;
	ptr = &buf[0];
	memcpy(ptr, &iphdr.ip_src.s_addr, sizeof(iphdr.ip_src.s_addr));
	ptr += sizeof(iphdr.ip_src.s_addr);
	chksumlen += sizeof(iphdr.ip_src.s_addr);
	memcpy(ptr, &iphdr.ip_dst.s_addr, sizeof(iphdr.ip_dst.s_addr));
	ptr += sizeof(iphdr.ip_dst.s_addr);
	chksumlen += sizeof(iphdr.ip_dst.s_addr);
	*ptr = 0;
	ptr++;
	chksumlen += 1;
	memcpy(ptr, &iphdr.ip_p, sizeof(iphdr.ip_p));
	ptr += sizeof(iphdr.ip_p);
	chksumlen += sizeof(iphdr.ip_p);
	memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
	ptr += sizeof(udphdr.len);
	chksumlen += sizeof(udphdr.len);
	memcpy(ptr, &udphdr.source, sizeof(udphdr.source));
	ptr += sizeof(udphdr.source);
	chksumlen += sizeof(udphdr.source);
	memcpy(ptr, &udphdr.dest, sizeof(udphdr.dest));
	ptr += sizeof(udphdr.dest);
	chksumlen += sizeof(udphdr.dest);
	memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
	ptr += sizeof(udphdr.len);
	chksumlen += sizeof(udphdr.len);
	*ptr = 0;
	ptr++;
	*ptr = 0;
	ptr++;
	chksumlen += 2;
	return checksum((uint16_t *)buf, chksumlen);
}

//check if ip address is valid
int checkip(char *ipAddress)
{
	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
	return result;
}

char *getdomainip(char *domain)
{
	static char domainip[INET_ADDRSTRLEN]; //string for ip address
	int status;
	struct addrinfo hints;
	struct addrinfo *getaddr;
	void *addr;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; //only IPV4
	hints.ai_socktype = SOCK_STREAM;
	if ((status = getaddrinfo(domain, NULL, &hints, &getaddr)) != 0)
	{ //check
		cout << "Wrong format of ip address,only IPV4 adress is supported " << endl;
		exit(-1);
	}
	struct sockaddr_in *ipv4 = (struct sockaddr_in *)getaddr->ai_addr;
	addr = &(ipv4->sin_addr);
	inet_ntop(getaddr->ai_family, addr, domainip, sizeof domainip); //translate ip to readeable string
	return domainip;
}

char *getsourceip(char *interface)
{
	int fd;
	char *sourceip;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0); //create socket
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1); //copy interface into socket
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	sourceip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr); //translate address to readeable format
	return sourceip;
}

//loop through interfaces and find firt which doesnt have loopback address
char *findinterface(char **interface)
{
	struct ifaddrs *ifaddr, *ifa;
	int family, s, n;
	static char host[INET_ADDRSTRLEN]; //buffer for my interface

	if (getifaddrs(&ifaddr) == -1)
	{
		cout << "Internal Error: Unable to find interface";
		exit(-1);
	}

	//loop through interfaces
	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++)
	{
		if (ifa->ifa_addr == NULL)
			continue;

		int iIsLoopBack = (0 != (ifa->ifa_flags & IFF_LOOPBACK));
		family = ifa->ifa_addr->sa_family; //store flag
		if ((ifa->ifa_addr->sa_family == AF_INET) && iIsLoopBack == 0)
		{																																																				 //if address is IPV4 and not loopback
			s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST); //get name of interface which owns this ip address
			if (s != 0)
			{
				cout << "Internal Error: Unable to find interface";
				exit(-1);
			}
			break;
		}
	}
	freeifaddrs(ifaddr);
	*interface = ifa->ifa_name;
	return host;
}

//Setup pcap
void setuppcap(char **interface, const char *f_exp, char *ipaddr)
{
	char error_buffer[PCAP_ERRBUF_SIZE]; //error buffer
	int lookuperr;
	const u_char *packet;
	struct pcap_pkthdr packet_header;
	handle = pcap_open_live(*interface, BUFSIZ, 1, 10, error_buffer); //setup pcap
	if (handle == NULL)
	{
		cout << "Port which you have inserted is not valid" << endl;
		exit(-1);
	}
	if (pcap_compile(handle, &f, f_exp, 0, stoi(ipaddr)) == -1)
	{
		cout << "Internal Error: Unable to prepare filter" << endl;
		exit(-1);
	}
	if (pcap_setfilter(handle, &f) == -1)
	{ //insert filter inside pcap
		cout << "Internal Error: Unable to set filter " << endl;
		exit(-1);
	}
}

//TCP SCAN
void tcp(char *domainip, char *sourceip, vector<string> ports, char **interface)
{
	const char *srcport = "60";										 //source port
	const char *f_exp = "inbound and tcp port 60"; //rule for pcap_filter
	setuppcap(interface, f_exp, sourceip);	 //setuppcap for tcp scanning
	int tcp_flags[8];												 //array for flags
	int status;
	//create memory for mypacket buffer
	uint8_t mypacket[IP_MAXPACKET];
	memset(mypacket, 0, IP_MAXPACKET);
	//structs for ip and tcp header
	struct ip iphdr;
	struct tcphdr tcphdr;

	//adress of socket
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(atoi(srcport));
	sin.sin_addr.s_addr = inet_addr(domainip);
	int sd;
	int y;
	int one = 1;
	const int *val = &one;

	//insert data into ip header
	iphdr.ip_hl = 5; //length of header
	iphdr.ip_v = 4;
	iphdr.ip_tos = 0;
	iphdr.ip_len = htons(IP4_HDRLEN + TCP_HDRLEN);
	iphdr.ip_id = htons(0);
	iphdr.ip_off = 0;
	if ((status = inet_pton(AF_INET, sourceip, &(iphdr.ip_src))) != 1)
	{ //translate and insert source ip
		cout << "Internal Error: Unable to translate IP address";
		exit(-1);
	}
	if ((status = inet_pton(AF_INET, domainip, &(iphdr.ip_dst))) != 1)
	{ //translate and insert destination ip
		cout << "Internal Error: Unable to translate IP address";
		exit(-1);
	}
	iphdr.ip_ttl = 255;
	iphdr.ip_p = IPPROTO_TCP;
	iphdr.ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN); //calculate checksum

	//for every port in vector
	for (auto y = ports.begin(); y != ports.end(); ++y)
	{
		string port;
		port.assign(*y);
		info.push_back(port); //push port into output

		//create socket
		sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
		if (sd < 0)
		{
			cout << "Internal Error: Unable to create soscket";
			exit(-1);
		}

		//insert data into tcp header
		tcphdr.th_sport = htons(60);
		tcphdr.th_dport = htons(atoi(port.c_str()));
		tcphdr.th_seq = htonl(0);
		tcphdr.th_ack = htonl(0);
		tcphdr.th_x2 = 0;
		tcphdr.th_off = TCP_HDRLEN / 4;
		tcp_flags[0] = 0;
		tcp_flags[1] = 1; //SYN flag
		tcp_flags[2] = 0;
		tcp_flags[3] = 0;
		tcp_flags[4] = 0;
		tcp_flags[5] = 0;
		tcp_flags[6] = 0;
		tcp_flags[7] = 0;
		tcphdr.th_flags = 0;
		for (int i = 0; i < 8; i++)
		{
			tcphdr.th_flags += (tcp_flags[i] << i); //Set TCP flags
		}
		tcphdr.th_win = htons(65535);
		tcphdr.th_urp = htons(0);
		tcphdr.th_sum = 0;
		tcphdr.th_sum = tcp4_checksum(iphdr, tcphdr);						//calculate checksum
		memcpy(mypacket, &iphdr, IP4_HDRLEN * sizeof(uint8_t)); //copy to mypacket  buffer
		memcpy((mypacket + IP4_HDRLEN), &tcphdr, TCP_HDRLEN * sizeof(uint8_t));

		if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
		{ //preprae socket
			cout << "Internal Error: Unable to prepare socket" << endl;
			exit(-1);
		}
		else
			for (int a = 0; a < 2; a++)
			{
				if (sendto(sd, mypacket, IP4_HDRLEN + TCP_HDRLEN, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)
				{ //SEND packet to destination ip
					cout << "Internal Error: Unable to send packet to destination port" << endl;
					exit(-1);
				}
				else
					//set alarm so we can cancel pcap_loop
					alarm(3);
				signal(SIGALRM, alarmhandler);										 //send signal to alarmhandler
				pcap_loop(handle, 1, my_packet_handler_tcp, NULL); //capture incoming traffic
				if (!portinfo.empty())
				{ //if we captured packet break
					break;
				}
				if (a == 1)
				{ //if we sent 2 packets without resposne we can say port is filtered
					portinfo = "Filtered";
					info.push_back(portinfo); //push info to output
				}
			}
		close(sd); //close socket
		outputtcp.push_back(info);
		info.clear(); //clear strings so we next port can use them
		portinfo.clear();
	}
	pcap_close(handle); //close  pcap
	return;
}

//UDP SCAN
void udp(char *domainip, char *sourceip, vector<string> ports, char **interface)
{
	const char *srcport = "60";
	const char *filter = "inbound and icmp[icmptype] == 3"; //filter for incoming ICMP Packets
	setuppcap(interface, filter, sourceip);						//setuppcap for capturing incoming packets
	struct sockaddr_in sin;														//create ip adress for socket
	sin.sin_family = AF_INET;
	sin.sin_port = htons(atoi(srcport));
	sin.sin_addr.s_addr = inet_addr(domainip);
	int status;
	int sd1;												//int to store socket
	uint8_t mypacket[IP_MAXPACKET]; //buffer for packet
	memset(mypacket, 0, IP_MAXPACKET);
	struct ip iphdr; //headers for ip and udp
	struct udphdr udphdr;
	int y;
	int one = 1;
	const int *val = &one;

	//insert data to ip header
	iphdr.ip_hl = 5;
	iphdr.ip_v = 4;
	iphdr.ip_tos = 0;
	iphdr.ip_len = htons(IP4_HDRLEN + UDP_HDRLEN); //calculate size
	iphdr.ip_id = htons(0);
	iphdr.ip_off = 0;
	iphdr.ip_ttl = 255;
	if ((status = inet_pton(AF_INET, sourceip, &(iphdr.ip_src))) != 1)
	{ //translate and insert source ip
		cout << "Internal Error: Unable to translate IP address";
		exit(-1);
	}
	if ((status = inet_pton(AF_INET, domainip, &(iphdr.ip_dst))) != 1)
	{ //translate and insert destination ip
		cout << "Internal Error: Unable to translate IP address";
		exit(-1);
	}

	iphdr.ip_p = IPPROTO_UDP; //udp protocol
	iphdr.ip_sum = 0;
	iphdr.ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN); //calculate checksum

	//for every UDP port
	for (auto y = ports.begin(); y != ports.end(); ++y)
	{
		sd1 = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
		if (sd1 < 0)
		{
			cout << "Internal Error: Unable create socket" << endl;
			exit(-1);
		}

		string port;
		port.assign(*y);
		info.push_back(port);
		udphdr.source = htons(4950);
		udphdr.dest = htons(atoi(port.c_str()));
		udphdr.len = htons(UDP_HDRLEN);
		udphdr.check = udp4_checksum(iphdr, udphdr); //calculate checksum

		memcpy(mypacket, &iphdr, IP4_HDRLEN * sizeof(uint8_t));
		memcpy((mypacket + IP4_HDRLEN), &udphdr, UDP_HDRLEN * sizeof(uint8_t));
		if (setsockopt(sd1, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
		{ //prepare socket
			cout << "Internal Error: Unable prepare socket" << endl;
			exit(-1);
		}
		else
		{
			for (int i = 0; i < 3; i++)
			{ //send multiple packets in case some of them fail to reach its destination
				if (sendto(sd1, mypacket, IP4_HDRLEN + UDP_HDRLEN, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)
				{ //send socket to its destination
					cout << "Internal Error: Unable to send socket to its destination" << endl;
					exit(-1);
				}
				else
				{
					alarm(3); //set alarm to cancel pcap_loop
					signal(SIGALRM, alarmhandler);
					pcap_loop(handle, 1, my_packet_handler_udp, NULL); //capture incoming packets
					if (!portinfo.empty())
					{ //if we captured packet we can break,else send another
						break;
					}
				}
			}
			if (portinfo.empty())
			{
				portinfo = "OPEN PORT";
				info.push_back(portinfo);
			}
			close(sd1);								 //close socket
			outputudp.push_back(info); //push results into output vector
			info.clear();							 //claer strings for another port
			portinfo.clear();
		}
	}
	pcap_close(handle); //close pcap
}

int main(int argc, char **argv)
{
	Arguments arguments;
	arguments.checkarguments(argc, argv);
	char *domainip, *sourceip, **interface;
	interface = &arguments.interface;

	//check if ip adrres was given and if it is valid
	if (checkip(arguments.domain) != 1)
	{
		//if not check if domain was given
		domainip = getdomainip(arguments.domain);
	}
	else
	{
		//if ip is valid insert it into char*
		domainip = arguments.domain;
	}
	//if port was given get the ip address of port
	if (*interface != NULL)
	{
		sourceip = getsourceip(*interface);
	}
	//else find first port with ipaddres which is not loopback
	else
	{
		sourceip = findinterface(interface);
	}
	//if tcp ports were given call tcp scan
	if (!arguments.pt.empty())
	{
		tcp(domainip, sourceip, arguments.pt, interface);
	}

	//if udp ports were given call udp scan
	if (!arguments.pu.empty())
	{
		udp(domainip, sourceip, arguments.pu, interface);
	}

	//print results of scans
	cout << "PORTS   "
			 << "STATUS" << endl;

	if (!outputtcp.empty())
	{
		cout << "#########################" << endl;
		cout << "TCP" << endl;
		for (int i = 0; i < outputtcp.size(); i++)
		{
			for (int j = 0; j < outputtcp[i].size(); j++)
			{
				cout << outputtcp[i][j];
				cout << "    ";
			}
			cout << endl;
		}
	}
	if (!outputudp.empty())
	{
		cout << "#########################" << endl;
		cout << "UDP" << endl;
		for (int i = 0; i < outputudp.size(); i++)
		{
			for (int j = 0; j < outputudp[i].size(); j++)
			{
				cout << outputudp[i][j];
				cout << "    ";
			}
			cout << endl;
		}
	}
	return 0;
}
