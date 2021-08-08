#include <vector>
#include <iostream>
#include <string>
#include <cstring>
#include <stdio.h>
#include <unistd.h>
#include <sstream>  


using namespace std;


class Arguments
{

private: 
    //function to seperate pt ports and insert them into vectors
    void seperateportsput(string pu_pt, int check);
    void seperateportspu ( string pus);
public:
    vector<string> pu;
    vector<string> pt;
    char *p;
    char *domain = NULL;
    char *interface = NULL;
    //Parse and check if arguments are correct
    void checkarguments(int argc, char **argv);
};