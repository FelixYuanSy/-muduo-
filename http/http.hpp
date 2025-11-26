#pragma once
#include <iostream>
#include <vector>
#include <fstream>
#include "../server.hpp"
class util
{
public:
    size_t Split(std::string &src, std::string sep, std::vector<std::string> *array)
    {
        // 情况1: abc
        // 情况2: abc,,cba
        // 情况3: ab,cdd,dd
        // 情况4: ,abc
        // 情况5: abc,

        size_t offset = 0;
        while (offset < src.size())
        {
            size_t pos = src.find(sep, offset);
            if (pos == src.size())
                break;
            if (pos == std::string::npos)
            {
                array->push_back(src.substr(offset));
                return array->size();
            }
            if (offset == pos)
            {
                offset = pos + sep.size();
                continue;
            }
            array->push_back(src.substr(offset, pos - offset));
            offset = pos + sep.size();
        }
        return array->size();
    }

    static bool ReadFile(const std::string &file_name, std::string *buf)
    {
        std::ifstream ifs(file_name, std::ios::binary);
        if (ifs.is_open() == false)
        {
            printf("Open %s File Failed\n", file_name.c_str());
            return false;
        }
        size_t fsize = 0;
        ifs.seekg(0, ifs.end);
        fsize = ifs.tellg();
        ifs.seekg(0, ifs.beg);
        ifs.read(&(*buf)[0], fsize);
        if (ifs.good() == false)
        {
            printf("Read %s File Failed\n", file_name.c_str());
            ifs.close();
            return false;
        }
        ifs.close();
        return true;
    }

    static bool WriteFile(const std::string &file_name, const std::string &buf)
    {
        std::ofstream ofs(file_name, std::ios::binary | std::ios::trunc);
        if (ofs.is_open() == false)
        {
            printf("Open %s File Failed\n", file_name);
            ofs.close();
            return false;
        }
        ofs.write(buf.c_str(), buf.size());
        if (ofs.good() == false)
        {
            ERR_LOG("Write %s File Error\n", file_name);
            ofs.close();
            return false;
        }
        ofs.close();
        return true;
    }
    // url资源路径会和查询字符串中的特殊字符还有Http中的特殊字符产生歧义
    // 编码格式:将特殊字符ascii转化为16进制
    // bool convert_space_to_plus: 用来区分是否是用来查询字符串
    // RFC3986规定: . - _ ~,属于不编码字符
    // W3C规定:空格在查询字符串中需要编码为+,解码为空格->+
    static std::string UrlEncode(const std::string url, bool convert_space_to_plus)
    {
        std::string str;
        for (auto &c : url)
        {
            if (c == '.' || c == '_' || c == '-' || c == '~' || isalnum(c))
            {
                str += c;
                continue;
            }
            if (c == ' ' && convert_space_to_plus == true)
            {
                str += '+';
                continue;
            }
            // 其余转化为%HH
            char tmp[4];
            snprintf(tmp, 4, "%%%02X", c); //%%用来转译为'%',第三个%用来表示后面为数字,0为未满两位数用0补齐第一位,2表示宽度为两位,X表示转换为16进制
            str += tmp;
        }
        return str;
    }
    // 算出字母和数字ASKII码
    static char HEXTOI(char c)
    {
        if (c >= '0' && c <= '9')
        {
            return c - '0';
        }
        if (c >= 'a' && c <= 'z')
        {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'Z')
        {
            return c - 'A' + 10;
        }
        return -1;
    }
    static std::string UrlDecode(const std::string url, bool convert_space_to_plus)
    {
        std::string str;
        for (int i = 0; i < url.size(); i++)
        {
            if (url[i] == '%' && (i + 2) < url.size())
            {
                char v1 = HEXTOI(url[i + 1]);
                char v2 = HEXTOI(url[i + 2]);
                char v = (v1 * 16) + v2;
                str += v;
                i += 2;
                continue;
            }
            if (url[i] == ' ' && convert_space_to_plus == true)
            {
                str += '+';
                i += 2;
                continue;
            }
            str += url[i];
        }
        return str;
    }
    static std::string StatuDesc(int statu)
    {
        std::unordered_map<int, std::string> _statu_msg =
            {
                {100, "Continue"},
                {101, "Switching Protocol"},
                {102, "Processing"},
                {103, "Early Hints"},
                {200, "OK"},
                {201, "Created"},
                {202, "Accepted"},
                {203, "Non-Authoritative Information"},
                {204, "No Content"},
                {205, "Reset Content"},
                {206, "Partial Content"},
                {207, "Multi-Status"},
                {208, "Already Reported"},
                {226, "IM Used"},
                {300, "Multiple Choice"},
                {301, "Moved Permanently"},
                {302, "Found"},
                {303, "See Other"},
                {304, "Not Modified"},
                {305, "Use Proxy"},
                {306, "unused"},
                {307, "Temporary Redirect"},
                {308, "Permanent Redirect"},
                {400, "Bad Request"},
                {401, "Unauthorized"},
                {402, "Payment Required"},
                {403, "Forbidden"},
                {404, "Not Found"},
                {405, "Method Not Allowed"},
                {406, "Not Acceptable"},
                {407, "Proxy Authentication Required"},
                {408, "Request Timeout"},
                {409, "Conflict"},
                {410, "Gone"},
                {411, "Length Required"},
                {412, "Precondition Failed"},
                {413, "Payload Too Large"},
                {414, "URI Too Long"},
                {415, "Unsupported Media Type"},
                {416, "Range Not Satisfiable"},
                {417, "Expectation Failed"},
                {418, "I'm a teapot"},
                {421, "Misdirected Request"},
                {422, "Unprocessable Entity"},
                {423, "Locked"},
                {424, "Failed Dependency"},
                {425, "Too Early"},
                {426, "Upgrade Required"},
                {428, "Precondition Required"},
                {429, "Too Many Requests"},
                {431, "Request Header Fields Too Large"},
                {451, "Unavailable For Legal Reasons"},
                {501, "Not Implemented"},
                {502, "Bad Gateway"},
                {503, "Service Unavailable"},
                {504, "Gateway Timeout"},
                {505, "HTTP Version Not Supported"},
                {506, "Variant Also Negotiates"},
                {507, "Insufficient Storage"},
                {508, "Loop Detected"},
                {510, "Not Extended"},
                {511, "Network Authentication Required"}};
        auto it = _statu_msg.find(statu);
        if (it == _statu_msg.end())
        {
            return "Unknow the Status Code\n";
        }
        return it->second;
    }

    
};