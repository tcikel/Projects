#include <iostream>
#include <filesystem>
#include <map>
#include <string>
#include "scanner.h"



int main(int argc, char* argv[]) { 

    if (argc != 2)
    { 
        std::cerr << "Include the path to directory" << std::endl;
        return -1;
    }

    std::string path = argv[1];
    if (!std::filesystem::is_directory(path))
    { 
        std::cerr << "Not a directory" << std::endl;
        return -1;
    }


    Scanner scanner;
    scanner.scandirectory(path);
    scanner.displayfiles();
    scanner.checkforduplicate();
    return 0;
}