#pragma once
#include <iostream>
#include <vector>
#include <fstream>
class util
{
    public:
    size_t Split(std::string &src,std::string sep,std::vector<std::string> *array)
    {
        //情况1: abc
        //情况2: abc,,cba
        //情况3: ab,cdd,dd
        //情况4: ,abc
        //情况5: abc,

        size_t offset = 0;
        while(offset < src.size())
        {
            size_t pos = src.find(sep,offset);
            if(pos == src.size())
                break;
            if(pos == std::string::npos)
            {
                array->push_back(src.substr(offset));
                return array->size();
            }
            if(offset == pos)
            {
                offset = pos + sep.size();
                continue;
            }
            array->push_back(src.substr(offset,pos-offset));
            offset = pos + sep.size();
        }
        return array->size();
    }

    static bool ReadFile(const std::string &file_name,std::string *buf)
    {
        std::ifstream ifs(file_name,std::ios::binary);
        if(ifs.is_open()==false)
        {
            printf("Open %s File Failed\n",file_name.c_str());
            return false;
        }
        size_t fsize = 0;
        ifs.seekg(0,ifs.end);
        fsize = ifs.tellg();
        ifs.seekg(0,ifs.beg);
        ifs.read(&(*buf)[0],fsize);
        if(ifs.good()==false)
        {
            printf("Read %s File Failed\n",file_name.c_str());
            ifs.close();
            return false;
        }
        ifs.close();
        return true;
        

    }
};