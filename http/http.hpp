#pragma once
#include <iostream>
#include <vector>
#include <fstream>
#include <sys/stat.h>
#include <regex>
#include "../server.hpp"
class Util
{
public:
    static size_t Split(const std::string &src, std::string sep, std::vector<std::string> *array)
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

    static std::string ExtMime(std::string &file_name)
    {
        std::unordered_map<std::string, std::string> _mime_msg =
            {
                {".aac", "audio/aac"},
                {".abw", "application/x-abiword"},
                {".arc", "application/x-freearc"},
                {".avi", "video/x-msvideo"},
                {".azw", "application/vnd.amazon.ebook"},
                {".bin", "application/octet-stream"},
                {".bmp", "image/bmp"},
                {".bz", "application/x-bzip"},
                {".bz2", "application/x-bzip2"},
                {".csh", "application/x-csh"},
                {".css", "text/css"},
                {".csv", "text/csv"},
                {".doc", "application/msword"},
                {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
                {".eot", "application/vnd.ms-fontobject"},
                {".epub", "application/epub+zip"},
                {".gif", "image/gif"},
                {".htm", "text/html"},
                {".html", "text/html"},
                {".ico", "image/vnd.microsoft.icon"},
                {".ics", "text/calendar"},
                {".jar", "application/java-archive"},
                {".jpeg", "image/jpeg"},
                {".jpg", "image/jpeg"},
                {".js", "text/javascript"},
                {".json", "application/json"},
                {".jsonld", "application/ld+json"},
                {".mid", "audio/midi"},
                {".midi", "audio/x-midi"},
                {".mjs", "text/javascript"},
                {".mp3", "audio/mpeg"},
                {".mpeg", "video/mpeg"},
                {".mpkg", "application/vnd.apple.installer+xml"},
                {".odp", "application/vnd.oasis.opendocument.presentation"},
                {".ods", "application/vnd.oasis.opendocument.spreadsheet"},
                {".odt", "application/vnd.oasis.opendocument.text"},
                {".oga", "audio/ogg"},
                {".ogv", "video/ogg"},
                {".ogx", "application/ogg"},
                {".otf", "font/otf"},
                {".png", "image/png"},
                {".pdf", "application/pdf"},
                {".ppt", "application/vnd.ms-powerpoint"},
                {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
                {".rar", "application/x-rar-compressed"},
                {".rtf", "application/rtf"},
                {".sh", "application/x-sh"},
                {".svg", "image/svg+xml"},
                {".swf", "application/x-shockwave-flash"},
                {".tar", "application/x-tar"},
                {".tif", "image/tiff"},
                {".tiff", "image/tiff"},
                {".ttf", "font/ttf"},
                {".txt", "text/plain"},
                {".vsd", "application/vnd.visio"},
                {".wav", "audio/wav"},
                {".weba", "audio/webm"},
                {".webm", "video/webm"},
                {".webp", "image/webp"},
                {".woff", "font/woff"},
                {".woff2", "font/woff2"},
                {".xhtml", "application/xhtml+xml"},
                {".xls", "application/vnd.ms-excel"},
                {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
                {".xml", "application/xml"},
                {".xul", "application/vnd.mozilla.xul+xml"},
                {".zip", "application/zip"},
                {".3gp", "video/3gpp"},
                {".3g2", "video/3gpp2"},
                {".7z", "application/x-7z-compressed"}};
        size_t pos = file_name.find_last_of(".");
        if (pos == std::string::npos)
        {
            return "application/octet-stream";
        }
        std::string ext = file_name.substr(pos);
        auto it = _mime_msg.find(ext);
        if (it == _mime_msg.end())
        {
            return "application/octet-stream";
        }
        return it->second;
    }
    static bool IsRegularFile(std::string file_name)
    {
        struct stat st;
        int ret = stat(file_name.c_str(), &st);
        if (ret < 0)
            return false;
        return S_ISREG(st.st_mode);
    }

    static bool IsDirectory(std::string file_name)
    {
        struct stat st;
        int ret = stat(file_name.c_str(), &st);
        if (ret < 0)
            return false;
        return S_ISDIR(st.st_mode);
    }
    static bool IsValidPath(const std::string &path)
    {
        std::vector<std::string> subdir;
        Split(path, "/", &subdir);
        int level = 0;
        for (auto &dir : subdir)
        {
            if (dir == "..")
            {
                level--;
                if (level < 0)
                    return false;
                continue;
            }
            level++;
        }
        return true;
    }
};

class HttpRequest
{
    // 请求方法,URL,查询字符串,协议版本,头部字段,路径正则提取数据,请求正文
    /*
        GET /index.html HTTP/1.1
        Host: 127.0.0.1:8080
        User-Agent: Mozilla/5.0
        Accept: /
        Connection: keep-alive
        Content-Length: 0

    */
public:
    std::string _method;                                   // 请求方法
    std::string _version;                                  // 协议版本
    std::string _path;                                     // 资源路径
    std::smatch _mathces;                                  // 正则匹配资源路径
    std::string _body;                                     // 正文
    std::unordered_map<std::string, std::string> _headers; // 查询头部字段
    std::unordered_map<std::string, std::string> _params;  // 查询字符串

public:
    void SetHeader(std::string &key, std::string &val)
    {
        _headers.insert(std::make_pair(key, val));
    }
    // 查看指定的Header是否存在
    bool HasHeader(const std::string &key)
    {
        auto it = _headers.find(key);
        if (it == _headers.end())
        {
            return false;
        }
        return true;
    }
    // 获取指定的头部字段值
    std::string GetHeader(const std::string &key)
    {
        bool ret = HasHeader(key);
        if (ret == false)
        {
            return "未找到当前头部值\n";
        }
        auto it = _headers.find(key);
        if (it == _headers.end())
        {
            return "";
        }
        return it->second;
    }
    // Params用来设置,获取查询字符串
    void SetParams(std::string &key, std::string &val)
    {
        _params.insert(std::make_pair(key, val));
    }

    bool HasParam(const std::string &key)
    {
        auto it = _params.find(key);
        if (it == _params.end())
        {
            return false;
        }
        return true;
    }

    std::string GetParams(const std::string &key)
    {
        bool ret = HasParam(key);
        if (ret == false)
        {
            return "未找到当前字符值\n";
        }
        auto it = _params.find(key);
        if (it == _params.end())
        {
            return "";
        }
        return it->second;
    }

    size_t GetBodyLength()
    {
        // 需要有Conten_Length 这个Key 才有正文
        bool ret = HasHeader("Content-Length");
        if (ret < 0)
            return 0;
        std::string clen = GetHeader("Content-Length");
        return std::stol(clen);
    }

    // 判断是否是短链接
    bool IsShortConnection()
    {
        // 没有Connection字段，或者有Connection但是值是close，则都是短链接，否则就是长连接
        if (HasHeader("Connection") == true && GetHeader("Connection") == "keep-alive")
        {
            return false;
        }
        return true;
    }

    void Reset()
    {
        _method.clear();
        _path.clear();
        _version.clear();
        _body.clear();
        _headers.clear();
        _params.clear();
        std::smatch sm;
        _mathces.swap(sm);
    }
};

class HttpResponse
{
private:
    int _statu_code;                                       // 返回的状态码
    std::string _redirect_url;                             // 重定向url
    std::string _body;                                     // 返回的body
    bool _redirect_flag = false;                           // 是否设置了重定向
    std::unordered_map<std::string, std::string> _headers; // 返回的头部

public:
    void SetHeader(const std::string &key, const std::string &val)
    {
        _headers.insert(std::make_pair(key, val));
    }
    // 查看指定的Header是否存在
    bool HasHeader(const std::string &key)
    {
        auto it = _headers.find(key);
        if (it == _headers.end())
        {
            return false;
        }
        return true;
    }
    // 获取指定的头部字段值
    std::string GetHeader(const std::string &key)
    {
        bool ret = HasHeader(key);
        if (ret == false)
        {
            return "未找到当前头部值\n";
        }
        auto it = _headers.find(key);
        if (it == _headers.end())
        {
            return "";
        }
        return it->second;
    }
    void SetRedirectUrl(const std::string &url, int statu = 302)
    {
        _statu_code = statu;
        _redirect_url = url;
        _redirect_flag = true;
    }
    void SetContent(const std::string &data, const std::string &type = "text/html")
    {
        _body = data;
        SetHeader("Content-Type", type);
    }
    bool IsShortConnection()
    {
        // 没有Connection字段，或者有Connection但是值是close，则都是短链接，否则就是长连接
        if (HasHeader("Connection") == true && GetHeader("Connection") == "keep-alive")
        {
            return false;
        }
        return true;
    }
};

// HttpContext类用来防止传来的request是不完整的,需要先传入buffer里面进行处理再传入Request
// 需要定义一个处理状态enum类来查看处理到什么状态,下一步进行哪种处理
typedef enum
{
    RECV_HTTP_ERROR,
    RECV_HTTP_LINE,
    RECV_HTTP_HEAD,
    RECV_HTTP_BODY,
    RECV_HTTP_OVER
} HttpRecvStatu;
#define MAX_LINE 8192
class HttpContext
{
private:
    HttpRecvStatu _recv_statu; // 当前处于处理的哪个状态
    HttpRequest _request;       // 已经处理的字段
    int _resp_status_code;      // 应该返回的状态码

public:
    bool ParseHttpLine(const std::string &line)
    {
        std::smatch matches;
        std::regex e("(GET|HEAD|POST|PUT|DELETE) ([^?]*)(?:\\?(.*))? (HTTP/1\\.[01])(?:\n|\r\n)?", std::regex::icase);
        bool ret = std::regex_match(line, matches, e);
        if (ret == false)
        {
            _recv_statu = RECV_HTTP_ERROR;
            return false;
        }
        // 0 : GET /EA/login?user=xiaoming&pass=123123 HTTP/1.1
        // 1 : GET
        // 2 : /bitejiuyeke/login
        // 3 : user=xiaoming&pass=123123
        // 4 : HTTP/1.1
        _request._method = matches[1];
        _request._path = Util::UrlDecode(matches[2], false);
        _request._version = matches[4];
        std::vector<std::string> array;
        std::string source_array = matches[3];
        Util::Split(source_array, "&", &array);
        for (auto &it : array)
        {
            size_t pos = it.find("=");
            if (pos == std::string::npos)
            {
                _recv_statu = RECV_HTTP_ERROR;
                _resp_status_code = 400; // BAD REQUEST
                return false;
            }
            std::string key = Util::UrlDecode(it.substr(0, pos), true);
            std::string val = Util::UrlDecode(it.substr(pos + 1), true);
            _request.SetParams(key, val);
        }
        return true;
    }

    bool RecvHttpLine(Buffer *buf)
    {
        if (_recv_statu != RECV_HTTP_LINE)
            return false;

        std::string line = buf->GetLineAndPop(); // 从InBuffer传进来->InBuffer怎么输入?
        // 缓冲区不足一行, 判断缓冲区里的数组是否超出了设定大小,超过了就是false
        if (line.size() == 0)
        {
            if (buf->ReadableSize() > MAX_LINE)
            {
                _recv_statu = RECV_HTTP_ERROR;
                _resp_status_code = 414; // URL TOO LONG
                return false;
            }
        }
        if (line.size() > MAX_LINE)
        {
            _recv_statu = RECV_HTTP_ERROR;
            _resp_status_code = 414; // URL TOO LONG
            return false;
        }
        bool ret = ParseHttpLine(line);
        if(ret == false)
        {
            return false;
        }
        _recv_statu = RECV_HTTP_HEAD;
        return true;
    }

     bool RecvHttpHead(Buffer *buf) {
            if (_recv_statu != RECV_HTTP_HEAD) return false;
            //一行一行取出数据，直到遇到空行为止， 头部的格式 key: val\r\nkey: val\r\n....
            while(1){
                std::string line = buf->GetLineAndPop();
                //2. 需要考虑的一些要素：缓冲区中的数据不足一行， 获取的一行数据超大
                if (line.size() == 0) {
                    //缓冲区中的数据不足一行，则需要判断缓冲区的可读数据长度，如果很长了都不足一行，这是有问题的
                    if (buf->ReadableSize() > MAX_LINE) {
                        _recv_statu = RECV_HTTP_ERROR;
                        _resp_status_code = 414;//URI TOO LONG
                        return false;
                    }
                    //缓冲区中数据不足一行，但是也不多，就等等新数据的到来
                    return true;
                }
                if (line.size() > MAX_LINE) {
                    _recv_statu = RECV_HTTP_ERROR;
                    _resp_status_code = 414;//URI TOO LONG
                    return false;
                }
                if (line == "\n" || line == "\r\n") {
                    break;
                }
                bool ret = ParseHttpHead(line);
                if (ret == false) {
                    return false;
                }
            }
            //头部处理完毕，进入正文获取阶段
            _recv_statu = RECV_HTTP_BODY;
            return true;
        }
         bool ParseHttpHead(std::string &line) {
            //key: val\r\nkey: val\r\n....
            if (line.back() == '\n') line.pop_back();//末尾是换行则去掉换行字符
            if (line.back() == '\r') line.pop_back();//末尾是回车则去掉回车字符
            size_t pos = line.find(": ");
            if (pos == std::string::npos) {
                _recv_statu= RECV_HTTP_ERROR;
                _resp_status_code = 400;//
                return false;
            }
            std::string key = line.substr(0, pos);  
            std::string val = line.substr(pos + 2);
            _request.SetHeader(key, val);
            return true;
        }
         bool RecvHttpBody(Buffer *buf) {
            if (_recv_statu != RECV_HTTP_BODY) return false;
            //1. 获取正文长度
            size_t content_length = _request.GetBodyLength();
            if (content_length == 0) {
                //没有正文，则请求接收解析完毕
                _recv_statu = RECV_HTTP_OVER;
                return true;
            }
            //2. 当前已经接收了多少正文,其实就是往  _request._body 中放了多少数据了
            size_t real_len = content_length - _request._body.size();//实际还需要接收的正文长度
            //3. 接收正文放到body中，但是也要考虑当前缓冲区中的数据，是否是全部的正文
            //  3.1 缓冲区中数据，包含了当前请求的所有正文，则取出所需的数据
            if (buf->ReadableSize() >= real_len) {
                _request._body.append(buf->ReadPosition(), real_len);
                buf->MoveReaderOffset(real_len);
                _recv_statu = RECV_HTTP_OVER;
                return true;
            }
            //  3.2 缓冲区中数据，无法满足当前正文的需要，数据不足，取出数据，然后等待新数据到来
            _request._body.append(buf->ReadPosition(), buf->ReadableSize());
            buf->MoveReaderOffset(buf->ReadableSize());
            return true;
        }
    public:
        HttpContext():_resp_status_code(200), _recv_statu(RECV_HTTP_LINE) {}
        void ReSet() {
            _resp_status_code = 200;
            _recv_statu = RECV_HTTP_LINE;
            _request.Reset();
        }
        int GetRespStatu() { return _resp_status_code; }
        HttpRecvStatu RecvStatu() { return _recv_statu; }
        HttpRequest &Request() { return _request; }
        //接收并解析HTTP请求
        void RecvHttpRequest(Buffer *buf) {
            //不同的状态，做不同的事情，但是这里不要break， 因为处理完请求行后，应该立即处理头部，而不是退出等新数据
            switch(_recv_statu) {
                case RECV_HTTP_LINE: RecvHttpLine(buf);
                case RECV_HTTP_HEAD: RecvHttpHead(buf);
                case RECV_HTTP_BODY: RecvHttpBody(buf);
            }
            return;
        }
};

class HttpServer
{
    private:

    TcpServer _server;
    std::string base_dir;//静态资源根目录
    using Handler = std::function<void(const HttpRequest&,HttpResponse*)>;
    Handler _get_route;
    Handler _post_route;
    Handler _put_route;
    Handler _delete_route;

    private:

    void Dispatcher();    //分发任务给功能性处理逻辑
    void Route(const HttpRequest &req, HttpResponse *resp);       //分辨是功能性请求还是静态资源获取
    void FileHandler(); //静态资源请求处理逻辑
    void WriteResponse();   //对返回资源进行组织
    void OnMessage(const PtrConnection &conn,Buffer *buf)        //对缓冲区数据进行解析
    {
        HttpContext *context = conn->GetContext()->get<HttpContext>(); 
        context->RecvHttpRequest(buf);
        HttpRequest &request = context->Request();
        HttpResponse response;
        Route(request,&response);
        WriteResponse();
        conn->Shutdown();

    }

   
};