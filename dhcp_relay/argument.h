
#ifndef ARGUMENT_H
#define ARGUMENT_H
#include <iostream>
#include <unistd.h> 
#include <stdio.h>
#include <string>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <vector> 
#include <algorithm>




using namespace std;
   

    int parseinput(int argc, char *argv[]);
    int checkinterface(char *intrface,vector <string>  &interfaces);
    int checkserver(char *srvr);

#endif