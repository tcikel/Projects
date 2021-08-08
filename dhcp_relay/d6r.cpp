
#include "argument.h"
#include <syslog.h>
#include <netinet/ip6.h>
#include "relay.h"
#include <pthread.h>

using namespace std;

int startsyslog()
{
    openlog(NULL, LOG_PID, LOG_DEBUG);
    syslog(LOG_INFO, "START LOGGING");
    return 0;
}

int main(int argc, char *argv[])
{
    char *server = NULL;
    bool debug = false;
    bool log = false;
    bool i_param = false;
    vector<string> interfaces;
    int opt;

    //ADD help message
    if (argc < 2 || argc > 7)
    {
        cerr << "Wrong amount of arguments,  use only arguments -d,-s,-l,-i" << endl;
        exit(-1);
    }
    //Check arguments
    while ((opt = getopt(argc, argv, "ldis")) != -1)
    {
        switch (opt)
        {
        case 'l':
            log = true;
            break;
        case 'd':
            debug = true;
            break;
        case 'i':
            //checkinterface(argv[optind]);
            i_param = true;
            interfaces.push_back(argv[optind]);
            break;
        case 's':
            checkserver(argv[optind]);
            server = argv[optind];
            break;
        }
        if (server == NULL)
        {
            cerr << "No server was given, insert proper IPV6 server address by using paramater -s" << endl;
            exit(-1);
        }
    }
    //If no parameter was given we listen on all interfaces
    if (i_param == false)
    {

        checkinterface(argv[optind], interfaces);
    }

    if (log == true)
    {
        startsyslog();
    }

    syslog(LOG_INFO, "Starting relay");
    start_relay(interfaces, server, debug, log);

    syslog(LOG_INFO, "CANCEL LOGGING");
    closelog();

    return 0;
}