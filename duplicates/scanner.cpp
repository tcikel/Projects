
#include "scanner.h"


Scanner::Scanner()
{ 
        std::cout << "Scanner created" << std::endl;
}

void Scanner::scandirectory(std::string directoryname) 
{ 
    for (const auto & entry : std::filesystem::recursive_directory_iterator(directoryname))
    {  
        if(!std::filesystem::is_directory(entry))
        {
            this->files.insert(std::make_pair(entry.file_size(),std::filesystem::absolute(entry)));
        }
    }
    return;
}


void Scanner::displayfiles(){ 

    for (auto i : this->files)
    { 
        std::cout << "File :" << i.first << " Size :" << i.second << std::endl;
    }
    return;
}


void Scanner::checkforduplicate(){ 
    
    for(auto i : this->files)
    { 
       if(this->files.count(i.first) != 1){ 
           this->possible_duplicates.insert(std::make_pair(i.first,i.second));
       }
    }

    if(this->possible_duplicates.empty())
    { 
        std::cout  << "There are no duplicate files" << std::endl;
        return;
    } 

    for( auto i : this-> possible_duplicates) 
    { 
        unsigned char result[MD5_DIGEST_LENGTH];

        int file_descript = open(i.second.c_str(), O_RDONLY);
        if (file_descript < 0 ) {
            std::cerr << "Unable to open file for hash scan" << std::endl;
        }

        char* file_buffer;
        file_buffer = (char *) mmap(0, i.first, PROT_READ, MAP_SHARED, file_descript,0);
        MD5((unsigned char*)file_buffer, i.first , result);
        munmap(file_buffer, i.first);
        this->file_hash.insert(std::make_pair((char *) result,i.second));
        std::cout << std::endl;
    }

    bool stratedlooping = false;
    std::string tmp; 
    for( auto i : this->file_hash)
    { 
        if (i.first == tmp) { 
            continue;
        }

        if (stratedlooping){ 
            this->file_hash.erase(tmp);
        }
        std::cout << "These files are same :" << std::endl;
        std::cout << i.second << std::endl; 
        for ( auto y : this->file_hash ) 
        { 
            if (i.first == y.first  && i.second !=y.second) 
            { 
                std::cout << y.second  << std::endl;
            }
        }
        tmp = i.first;
        stratedlooping = true;
        std::cout << std::endl;
    }
}