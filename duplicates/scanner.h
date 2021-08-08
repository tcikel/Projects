
#include <iostream>
#include <string>
#include <map>
#include <list>
#include <filesystem>
#include <openssl/md5.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <utility>

typedef std::multimap<int,std::string> str_int_map;

class Scanner {

    private:
        std::multimap <std::string, std::string> file_hash;
        std::multimap <int,std::string> possible_duplicates;
    public:  
        std::multimap <int,std::string> files;
        Scanner();
        void scandirectory(std::string directoryname);
        void displayfiles();
        void checkforduplicate();
    
};
