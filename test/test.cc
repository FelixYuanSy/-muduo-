#include <iostream>
#include <vector>

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
            char v = (v1 *16) + v2;
            str += v;
            i+=2;
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

int main()
{
    // std::string str = "abc,,cba,dfd,vbn,";
    // std::vector<std::string> array;
    // Split(str, ",", &array);
    // for (auto &s : array)
    // {
    //     std::cout << "[" << s << "]\n";
    // }
    std::string str = "c++";
    std::string eco = UrlEncode(str,false);
    std::string res = UrlDecode(eco, false);
    std::cout << eco << std::endl;
    std::cout << res << std::endl;
}