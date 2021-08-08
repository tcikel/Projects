
#include "argument.h"

int checkinterface(char *intrface, vector<string> &interfaces)
{
    //struct ifreq ifr;
    char ipv6addres[INET6_ADDRSTRLEN];
    //strncpy(ifr.ifr_name, intrface, IFNAMSIZ-1);
    struct ifaddrs *ifa, *ifa_tmp;
    if (getifaddrs(&ifa) == -1)
    {
        cerr << "Failed to check adress if interface\n";
        exit(-1);
    }
    ifa_tmp = ifa;
    while (ifa_tmp)
    {
        if (ifa_tmp->ifa_addr->sa_family == AF_INET6 && ifa_tmp->ifa_flags)
        {
            struct sockaddr_in6 *ip6addr = (struct sockaddr_in6 *)ifa_tmp->ifa_addr;
            inet_ntop(AF_INET6, &ip6addr->sin6_addr, ipv6addres, sizeof(ipv6addres));
            if (find(interfaces.begin(), interfaces.end(), ifa_tmp->ifa_name) != interfaces.end())
            {
            }
            else
            {
                if (strlen(ifa_tmp->ifa_name) < 20)
                {
                    interfaces.push_back(ifa_tmp->ifa_name);
                }
            }
        }
        ifa_tmp = ifa_tmp->ifa_next;
    }
    return 0;
}

int checkserver(char *srvr)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET6, srvr, &sa.sin_addr);
    if (result == 0)
    {
        cerr << "Non valid ip address please insert correct IPV6 address";
        exit(-1);
    }
    return 0;
}
