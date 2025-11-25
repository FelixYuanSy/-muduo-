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

int main()
{
    std::string str = "abc,,cba,dfd,vbn,";
    std::vector<std::string> array;
    Split(str, ",", &array);
    for (auto &s : array)
    {
        std::cout << "[" << s << "]\n";
    }
}