#pragma once
#include <iostream>
#include <sys/timerfd.h>
#include <stdio.h>
#include <ctime>
#include <pthread.h>
#include <vector>
#include <cstdint>
#include <assert.h>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
 #include <fcntl.h>
/*
    打印日志功能
*/
#define INFO 0
#define DBG 1
#define ERR 2
#define LOG_LEVEL DBG
#define LOG(level, format, ...)                                                                                       \
    do                                                                                                                \
    {                                                                                                                 \
        if (level < LOG_LEVEL)                                                                                        \
            break;                                                                                                    \
        time_t t = time(NULL);                                                                                        \
        struct tm *ltm = localtime(&t);                                                                               \
        char tmp[32] = {0};                                                                                           \
        strftime(tmp, 31, "%H:%M:%S", ltm);                                                                           \
        fprintf(stdout, "[%p %s %s:%d]" format "\n", (void *)pthread_self(), tmp, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define INFO_LOG(format, ...) LOG(INFO, format, ##__VA_ARGS__)
#define DBG_LOG(format, ...) LOG(DBG, format, ##__VA_ARGS__)
#define ERR_LOG(format, ...) LOG(ERR, format, ##__VA_ARGS__)

/*
        buffer使用vector来储存
        读和写需要偏移量,因为采用空间地址来管理数据位置
        需要位置功能:
        1.获取可读空间大小/
        2.获取读取位置: 写入偏移-读取偏移/
        3.获取写入位置/
        4.获取缓冲末尾空闲空间大小/
        5.获取缓冲区起始空闲空间大小/
        6.查看是否可写: 写入长度 >= 起始 + 末尾缓冲空间大小/
        7.移动读位置/
        8.移动写位置/

        写入功能:
        1. 写入数据(要输入数据,长度)/写入并移动/
        2. 读取数据((输出参数),读取长度)/读取并移动/
        3. 读取为string/+移动/
        4. 查找\n标识符
        5.获取行内容
        6.清空缓冲区
    */
#define BUFFER_DEFAULT_SIZE 1024
class Buffer
{
private:
    std::vector<char> _buffer;
    uint64_t _reader_idx;
    uint64_t _writer_idx;

public:
    Buffer() : _reader_idx(0), _writer_idx(0), _buffer(BUFFER_DEFAULT_SIZE) {}
    Buffer(Buffer &other)
    {
        Write(other.ReadPosition(), other.ReadableSize());
        MoveReaderOffset(other.ReadableSize());
    }
    char *Begin()
    {
        return &*_buffer.begin(); // 返回空间地址
    }
    char *ReadPosition()
    {
        return Begin() + _reader_idx;
    }
    char *WritePosition()
    {
        return Begin() + _writer_idx;
    }
    uint64_t TailIdleSize()
    {
        return _buffer.size() - _writer_idx;
    }
    uint64_t FrontIdleSize()
    {
        return _reader_idx;
    }
    uint64_t ReadableSize()
    {
        return _writer_idx - _reader_idx;
    }
    void EnsureWriteSpace(uint64_t len)
    {
        if (len <= TailIdleSize())
        {
            return;
        }
        if (len <= TailIdleSize() + FrontIdleSize())
        {
            uint64_t rsz = ReadableSize();
            std::copy(ReadPosition(), ReadPosition() + rsz, Begin());
            _reader_idx = 0;
            _writer_idx = rsz;
        }
        else
        {
            _buffer.resize(_writer_idx + len);
        }
    }
    void MoveReaderOffset(uint64_t len)
    {
        assert(len <= ReadableSize());
        _reader_idx += len;
    }
    void MoveWriterOffset(uint64_t len)
    {
        assert(len <= TailIdleSize());
        _writer_idx += len;
    }
    void Write(const void *data, uint64_t len)
    {
        if (len = 0)
            return;
        EnsureWriteSpace(len);
        char *d = (char *)data;
        std::copy(d, d + len, WritePosition());
    }
    void WriteAndMove(const void *data, uint64_t len)
    {
        Write(data, len);
        MoveWriterOffset(len);
    }
    void WriteString(const std::string &data)
    {
        Write(data.c_str(), data.size());
    }
    void WriteStringAndMove(const std::string &data)
    {
        WriteString(data);
        MoveWriterOffset(data.size());
    }

    void Read(void *buf, uint64_t len)
    {
        assert(len <= ReadableSize());
        std::copy(ReadPosition(), ReadPosition() + len, (char *)buf);
    }
    void ReadAndMove(void *buf, uint64_t len)
    {
        Read(buf, len);
        MoveReaderOffset(len);
    }
    std::string ReadAsString(uint64_t len)
    {
        assert(len <= ReadableSize());
        std::string str;
        str.resize(len);
        Read(&str[0], len);
        return str;
    }
    std::string ReadAsStringAndMove(uint64_t len)
    {
        assert(len <= ReadableSize());
        std::string str = ReadAsString(len);
        MoveReaderOffset(len);
        return str;
    }
    char *FindCRLF()
    {
        char *res = (char *)memchr(ReadPosition(), '\n', ReadableSize());
        return res;
    }
    std::string GetLine()
    {
        char *pos = FindCRLF();
        if (pos == NULL)
            return "";
        return ReadAsString(pos - ReadPosition() + 1); //+1读取\n
    }
    std::string GetLineAndPop()
    {
        std::string str = GetLine();
        MoveReaderOffset(str.size());
        return str;
    }
    void Clear()
    {
        _reader_idx = 0;
        _writer_idx = 0;
    }
};
#define MAX_LENGTH 1024
class Socket
{
private:
    int _sockfd;

public:
    Socket() : _sockfd(-1) {}
    Socket(int fd) : _sockfd(fd) {}
    ~Socket() {}
    // 创建套接字
    bool CreateSocket()
    {
        _sockfd = socket(AF_INET, SOCK_STREAM, 0); // 直接用0默认,面去写IPPROTO_TCP
        if (_sockfd < 0)
        {
            ERR_LOG("CREATE SOCKET FAILED");
            return false;
        }
        return true;
    }
    // 绑定地址信息(port是8字节)
    bool Bind(const std::string &ip, uint64_t &port)
    {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        socklen_t len = sizeof(struct sockaddr_in);
        int ret = bind(_sockfd, (struct sockaddr *)&addr, len);
        if (ret < 0)
        {
            ERR_LOG("Bind Address Failed");
            return false;
        }
        return true;
    }
    // 开始监听
    bool Listen(int backlog = MAX_LENGTH)
    {
        int ret = listen(_sockfd, backlog);
        if (ret < 0)
        {
            ERR_LOG("Create Listen Failed");
            return false;
        }
        return true;
    }
    // 向服务器发起连接
    bool Connect(const std::string &ip, uint64_t &port)
    {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        socklen_t len = sizeof(struct sockaddr_in);
        int ret = connect(_sockfd, (struct sockaddr *)&addr, len);
        if (ret < 0)
        {
            ERR_LOG("Connect Server Failed");
            return false;
        }
        return true;
    }
    // 获取新连接
    int Accept()
    {
        int new_sock = accept(_sockfd, NULL, NULL);
        if (new_sock < 0)
        {
            ERR_LOG("Accept new connetion Failed");
            return -1;
        }
        return new_sock;
    }
    // 接收数据
    ssize_t Rcev(void *buf, size_t len, int flag = 0)
    {
        ssize_t ret = recv(_sockfd, buf, len, flag);
        if (ret < 0)
        {
            ERR_LOG("Recev data Failed");
            return -1;
        }
        return ret; // 接收到数据长度
    }
    // 非阻塞接收
    ssize_t NonBlockRecv(void *buf, size_t len)
    {
        ssize_t ret = recv(_sockfd, buf, len, MSG_DONTWAIT);
    }
    // 发送数据
    ssize_t Send(void *buf, size_t len, int flag = 0)
    {
        ssize_t ret = send(_sockfd, buf, len, flag);
        if (ret < 0)
        {
            if (errno == EAGAIN || errno == EINTR)
                return 0;
            ERR_LOG("Send data Failed");
            return -1;
        }
        return ret; // 发送的数据长度
    }
    ssize_t NonBlockSend(void *buf, size_t len)
    {
        if (len == 0)
            return 0;
        return Send(buf, len, MSG_DONTWAIT); // MSG_DONTWAIT 表示当前发送为非阻塞。
    }
    // 关闭套接字
    void Close()
    {
        if (_sockfd != -1)
        {
            close(_sockfd);
            _sockfd = -1;
        }
    }

    // 创建一个服务器端
    bool CreateServer(uint64_t port, const std::string &ip = "0.0.0.0", bool block_flag = false)
    {
        if (CreateSocket() == false)
            return false;
        if (Bind(ip, port) == false)
            return false;
        // if(block_flag) NonBlock();
        if (Listen() == false)
            return false;
        // 地址重用
        ReuseAddress();
        return true;
    }
    // 创建一个客户端
    bool CreateClient(uint64_t port, const std::string &ip)
    {
        if (CreateSocket() == false)
            return false;
        if (Connect(ip, port) == false)
            return false;
        return true;
    }
    // 设置套接字开始地址端口重用
    void ReuseAddress()
    {
        int val = 1;
        setsockopt(_sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&val, sizeof(int));
        val = 1;
        setsockopt(_sockfd, SOL_SOCKET, SO_REUSEPORT, (void *)&val, sizeof(int));
    }
    // 设置套接字为非阻塞
    void NonBlock()
    {
        int flag;
        flag = fcntl(_sockfd,F_GETFL,0);
        flag |= O_NONBLOCK;
        fcntl(_sockfd,F_SETFL,flag);
    }
};