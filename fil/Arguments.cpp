
#include "Arguments.h"
//function to seperate pt ports and insert them into vectors
void Arguments::seperateportsput(string pu_pt, int check)
{
    stringstream s(pu_pt);
    string port;
    int count = 0;
    if (pu_pt.find('-') != string::npos)
    {
        while (getline(s, port, '-'))
        {
            long converted = strtol(port.c_str(), &p, 10); //check if numbers or ports are valid
            if (*p)
            {
                cout << "Wrong format of udp port number";
                exit(-1);
            }
            pt.push_back(port);
            if (pt.size() > 2)
            {
                cout << "Wrong PT arugment";
            }
        }
    }
    else
    {
        while (getline(s, port, ','))
        {
            long converted = strtol(port.c_str(), &p, 10);
            if (*p)
            {
                cout << "Wrong format of tcp port  number" << endl;
                exit(-1);
            }
            pt.push_back(port);
        }
    }
}
//function to seperate pu ports and insert them into vectors
void Arguments::seperateportspu(string pus)
{
    stringstream s(pus);
    string port;
    int count = 0;
    if (pus.find('-') != string::npos)
    {
        while (getline(s, port, '-'))
        {

            long converted = strtol(port.c_str(), &p, 10); //check if numbers or ports are valid
            if (*p)
            {
                cout << "Wrong format of udp port number";
                exit(-1);
            }

            this->pu.push_back(port);
            if (this->pt.size() > 2)
            {
                cout << "Wrong PU arugment";
                exit(-1);
            }
        }
    }
    else
    {
        while (getline(s, port, ','))
        {
            long converted = strtol(port.c_str(), &p, 10);
            if (*p)
            {
                cout << "Wrong format of udp port number";
                exit(-1);
            }
            this->pu.push_back(port);
        }
    }
}

//Parse and check if arguments are correct
void Arguments::checkarguments(int argc, char **argv)
{
    if (argc != 6 && argc != 8)
    {
        cout << "Wrong amount of arguments\n";
        exit(-1);
    }
    int c;
    char cc;
    string s;
    string rangepu;
    string rangept;
    int parsed_arg[7]; //
    int y = 0;
    while ((c = getopt(argc, argv, "ptipu")) != -1)
    { // parse arguments
        parsed_arg[y] = optind;
        y++;
        cc = c;
        switch (c)
        {
        case 'i':
            interface = argv[optind];
            break;
        case 'p':
            s = s + cc;
            break;
        case 't': //pt argument
            s = s + cc;
            if (s != "pt")
            {
                cout << "Wrong format of pt argument";
                exit(-1);
            }
            if (optind == argc)
            {
                cout << "Wrong amount of arguments";
                exit(-1);
            }
            rangept = argv[optind];
            seperateportsput(rangept, 1);
            s.clear();
            break;
        case 'u': //pu argument
            s = s + cc;
            if (s != "pu")
            {
                cout << "Wrong format of pu argument";
                exit(-1);
            }
            if (optind == argc)
            {
                cerr << "Wrong amount of arguments";
                exit(-1);
            }
            rangepu = argv[optind];
            seperateportspu(rangepu);
            s.clear();
            break;
        default:
            break;
        }
    }

    bool check;
    for (int x = 2; x < argc; x++)
    {
        for (int z = 0; z <= y; z++)
        {
            if (x == parsed_arg[z])
            {
                check = true;
                break;
            }
            else
            {
                check = false;
            }
        }
        if (!check)
        {
            domain = argv[x];
            break;
        }
    }
    if (domain == NULL)
    {
        cout << "Domain or ip address  missing"
             << "\n";
        exit(-1);
    }
}
