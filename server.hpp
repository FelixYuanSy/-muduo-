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
#include <functional>
#include <sys/epoll.h>
#include <unordered_map>
#include <memory>
#include <thread>
#include <sys/eventfd.h>
#include <mutex>
#include <condition_variable>
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
    void WriteBuffer(Buffer &data)
    {
        return Write(data.ReadPosition(), data.ReadableSize());
    }
    void WriteBufferAndPush(Buffer &data)
    {
        WriteBuffer(data);
        MoveWriterOffset(data.ReadableSize());
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
        return ret;
    }
    // 发送数据
    ssize_t Send(const void *buf, size_t len, int flag = 0)
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
        flag = fcntl(_sockfd, F_GETFL, 0);
        flag |= O_NONBLOCK;
        fcntl(_sockfd, F_SETFL, flag);
    }
    int GetFd()
    {
        return _sockfd;
    }
};
class EventLoop;
class Channel
{
private:
    int _fd;
    uint32_t _event;  // 当前需要监控的事件
    uint32_t _revent; // 当前触发的事件
    EventLoop *_loop;
    using EventCallBack = std::function<void()>;
    EventCallBack _read_callback;
    EventCallBack _write_callback;
    EventCallBack _error_callback;
    EventCallBack _close_callback;
    EventCallBack _event_callback;

public:
    Channel(EventLoop *loop, int fd) : _fd(fd), _event(0), _revent(0), _loop(loop)
    {
    }
    int Getfd()
    {
        return _fd;
    }
    // 获取当前触发的事件
    uint32_t GetEvents()
    {
        return _event;
    }
    void SetREvent(uint32_t event)
    {
        _revent = event;
    }
    EventCallBack SetReadCallBack(const EventCallBack &cb) { return _read_callback = cb; }
    EventCallBack SetWriteCallBack(const EventCallBack &cb) { return _write_callback = cb; }
    EventCallBack SetErrorCallBack(const EventCallBack &cb) { return _error_callback = cb; }
    EventCallBack SetCloseCallBack(const EventCallBack &cb) { return _close_callback = cb; }
    EventCallBack SetEventCallBack(const EventCallBack &cb) { return _event_callback = cb; }

    // 是否监控了可读
    bool ReadAble()
    {
        return (_event & EPOLLIN);
    }
    // 是否监控了可写
    bool WriteAble()
    {
        return (_event & EPOLLOUT);
    }
    // 启动读事件监控
    void EnableRead()
    {
        _event |= EPOLLIN;
        Update();
    }
    // 启动写事件监控
    void EnableWrite()
    {
        _event |= EPOLLOUT;
        Update();
    }
    // 关闭读事件监控
    void CloseRead()
    {
        _event &= ~EPOLLIN;
        Update();
    }
    // 关闭写事件监控
    void CloseWrite()
    {
        _event &= ~EPOLLOUT;
        Update();
    }
    // 关闭所有监控
    void CloseAll()
    {
        _event = 0;
        Update();
    }
    // 移除监控
    void Remove();
    // 事件处理
    void HandleEvent()
    {
        if ((_revent & EPOLLIN) || (_revent & EPOLLRDHUP) || (_revent & EPOLLPRI))
        {
            /*不管任何事件，都调用的回调函数*/
            if (_read_callback)
                _read_callback();
        }
        /*有可能会释放连接的操作事件，一次只处理一个*/
        if (_revent & EPOLLOUT)
        {
            if (_write_callback)
                _write_callback();
        }
        else if (_revent & EPOLLERR)
        {
            if (_error_callback)
                _error_callback(); // 一旦出错，就会释放连接，因此要放到前边调用任意回调
        }
        else if (_revent & EPOLLHUP)
        {
            if (_close_callback)
                _close_callback();
        }
        if (_event_callback)
            _event_callback();
    }
    void Update();
};
#define MAX_EPOLLEVENTS 1024
class Poller
{
private:
    int _epid;
    struct epoll_event _evs[MAX_EPOLLEVENTS];
    std::unordered_map<int, Channel *> _channels; // 进行已经监控的数据管理

private:
    void Update(Channel *channel, int op)
    {
        struct epoll_event ev;
        int fd = channel->Getfd();
        ev.data.fd = fd;
        ev.events = channel->GetEvents();
        int ret = epoll_ctl(_epid, op, fd, &ev);
        if (ret < 0)
        {
            ERR_LOG("EPOLLCTL Failed");
        }
        return;
    }
    bool HasChannel(Channel *channel)
    {
        auto it = _channels.find(channel->Getfd());
        if (it == _channels.end())
        {
            return false;
        }
        return true;
    }

public:
    Poller() // op传给epoll_ctl函数
    {
        _epid = epoll_create(MAX_EPOLLEVENTS);
        if (_epid < 0)
        {
            ERR_LOG("Create epoll_id Failed");
            abort();
        }
    }
    // 添加/修改监控事件
    void UpdateEvent(Channel *channel)
    {
        bool ret = HasChannel(channel);
        if (ret == false)
        {
            // 把当前channel传入_channels
            _channels.insert(std::make_pair(channel->Getfd(), channel));

            return Update(channel, EPOLL_CTL_ADD);
        }

        return Update(channel, EPOLL_CTL_MOD);
    }

    // 删除事件
    void RemoveEvent(Channel *channel)
    {
        auto it = _channels.find(channel->Getfd());
        if (it != _channels.end())
        {
            _channels.erase(it);
        }
        Update(channel, EPOLL_CTL_DEL);
    }

    // 开始监控
    void Poll(std::vector<Channel *> *actives)
    {
        int nfds = epoll_wait(_epid, _evs, MAX_EPOLLEVENTS, -1); //-1阻塞等待
        if (nfds < 0)
        {
            if (errno == EINTR)
            {
                return;
            }
            ERR_LOG("EPOLL WAIT ERROR:%s\n", strerror(errno));
            abort(); // 退出程序
        }
        for (int i = 0; i < nfds; i++)
        {
            auto it = _channels.find(_evs[i].data.fd);
            assert(it != _channels.end());
            it->second->SetREvent(_evs[i].events); // 设置实际就绪的事件
            actives->push_back(it->second);
        }
        return;
    }
};

using TaskFunc = std::function<void()>;    // 用来传入定时任务
using ReleaseFunc = std::function<void()>; // 用来删除定时器对象信息
class TimerTask
{
private:
    uint64_t _id;         // 任务id
    uint32_t _timeout;    // 定时任务超时时间
    TaskFunc _task_cb;    // 定时器要执行的任务
    ReleaseFunc _release; // 用来删除timerwheel里定时器对象
    bool cancel;          // 用来解除定时任务

public:
    TimerTask(uint64_t id, uint32_t timeout, const TaskFunc &task_cb) : _id(id), _timeout(timeout), _task_cb(task_cb)
    {
    }
    ~TimerTask()
    {
        if (cancel == false)
            _task_cb();
        _release();
    }
    void SetRelease(const ReleaseFunc &cb)
    {
        _release = cb;
    }
    uint32_t GetDelayTime()
    {
        return _timeout;
    }
    void Cancel()
    {
        cancel = true;
    }
};

class TimerWheel
{
private:
    using PtrTask = std::shared_ptr<TimerTask>;
    using WeakTask = std::weak_ptr<TimerTask>;
    int _tick;                                      // 轮子当前时间指针
    int _capacity;                                  // 最大延迟时间
    std::vector<std::vector<PtrTask>> _wheel;       // 二维数组,用来存时间轮中的任务
    std::unordered_map<uint64_t, WeakTask> _timers; // 用弱指针来移除timer,弱指针不占用计数

    int _timer_fd;    // timer_fd来充当信号唤醒EvenLoop阻塞,每秒钟唤醒一次;可读事件回调是读取计数器
    EventLoop *_loop; // 与EventLoop进行链接,TimerWheel属于EventLoop类
    std::unique_ptr<Channel> _timer_channel;

private:
    void RemoveTimer(uint64_t id)
    {
        auto it = _timers.find(id);
        if (it != _timers.end())
        {
            _timers.erase(it);
        }
    }
    static int CreateTimerFd()
    {
        int timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (timer_fd < 0)
        {
            ERR_LOG("Create TimerFd Failed");
            abort();
        }
        struct itimerspec itime;
        itime.it_value.tv_sec = 1;
        itime.it_value.tv_nsec = 0; // 第一次超时时间为1s后
        itime.it_interval.tv_sec = 1;
        itime.it_interval.tv_nsec = 0; // 第一次超时后，每次超时的间隔时
        timerfd_settime(timer_fd, 0, &itime, NULL);
        return timer_fd;
    }

    int ReadTimerFd()
    {
        uint64_t times;
        int ret = read(_timer_fd, &times, 8); // 读取超时的次数
        if (ret < 0)
        {
            ERR_LOG("Read TimerFd Failed");
            abort();
        }
        return times;
    }
    void RunTimerTask() // 每秒执行一次
    {
        _tick = (_tick + 1) % _capacity; // 每次走一个时间点
        _wheel[_tick].clear();           // 调用clear清除当前时间点上的任务,任务的析构函数会让任务自己运行
    }

    // 封装每秒执行到期任务
    void OnTime()
    {
        int times = ReadTimerFd();
        for (int i = 0; i < times; i++)
        {
            RunTimerTask();
        }
    }

    void TimerAddInLoop(uint64_t id, uint32_t timeout, const TaskFunc &cb)
    {
        PtrTask pt(new TimerTask(id, timeout, cb));
        pt->SetRelease(std::bind(&TimerWheel::RemoveTimer, this, id));
        int pos = (_tick + timeout) % _capacity;
        _wheel[pos].push_back(pt);
        _timers[id] = WeakTask(pt);
    }

    void TimerRefreshInLoop(uint64_t id)
    {
        auto it = _timers.find(id);
        if (it == _timers.end())
        {
            return; // 没找到任务,代表无法刷新
        }
        PtrTask pt = it->second.lock();
        int delaytime = pt->GetDelayTime();
        int pos = (_tick + delaytime) % _capacity;
        _wheel[pos].push_back(pt);
    }

    void TimerCancelInLoop(uint64_t id)
    {
        auto it = _timers.find(id);
        if (it == _timers.end())
        {
            return;
        }
        PtrTask pt = it->second.lock();
        pt->Cancel();
    }

public:
    TimerWheel(EventLoop *loop) : _tick(0), _capacity(60), _wheel(_capacity), _loop(loop),
                                  _timer_fd(CreateTimerFd()), _timer_channel(new Channel(_loop, _timer_fd))
    {
        _timer_channel->SetReadCallBack(std::bind(&TimerWheel::OnTime, this));
    }

    void TimerAdd(uint64_t id, uint32_t timeout, const TaskFunc &cb)
    {
    }

    void TimerRefresh(uint64_t id)
    {
    }

    void TimerCancel(uint64_t id)
    {
        TimerCancelInLoop(id);
    }

    bool HasTimer(int id)
    {
        auto it = _timers.find(id);
        if (it == _timers.end())
        {
            return false;
        }
        return true;
    }
};

class EventLoop
{
private:
    using Func = std::function<void()>;
    std::thread::id _thread_id; // 判断是否在同一线程内
    int _event_fd;              // 用来唤醒IO导致的阻塞
    Poller _poller;             // 监控模块
    std::vector<Func> _task;    // 任务队列
    std::mutex _mutex;
    std::unique_ptr<Channel> _event_channel;
    TimerWheel _timerwheel;

public:
    static int CreateEventFd()
    {
        int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (fd < 0)
        {
            ERR_LOG("Create EventFd Failed");
            abort();
        }
        return fd;
    }
    void ReadEventfd()
    {
        uint64_t val = 0;
        int ret = read(_event_fd, &val, sizeof(val));
        if (ret < 0)
        {
            if (errno == EAGAIN | errno == EINTR)
            {
                return;
            }
            ERR_LOG("Read EventFd Failed");
            abort();
        }
        return;
    }
    void WakeUpEventFd()
    {
        uint64_t val = 1;
        int ret = write(_event_fd, &val, sizeof(val));
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                return;
            }
            ERR_LOG("READ EVENTFD FAILED!");
            abort();
        }
        return;
    }

public:
    EventLoop() : _thread_id(std::this_thread::get_id()),
                  _event_fd(CreateEventFd()),
                  _event_channel(new Channel(this, _event_fd)),
                  _timerwheel(this)
    {
        // 需要跨线程唤醒机制,防止epoll_wait进行阻塞中
        _event_channel->SetReadCallBack(std::bind(&EventLoop::ReadEventfd, this));
        _event_channel->EnableRead();
    }
    // 判断实行的任务是否在同一线程中
    void RunInLoop(const Func &cb)
    {
        if (IsInLoop())
        {
            return cb();
        }
        return QueueInLoop(cb);
    }
    // 判断当前线程是否是EventLoop对应线程
    bool IsInLoop()
    {
        return _thread_id == std::this_thread::get_id();
    }
    // 把不是同一线程的任务放入任务队列
    void QueueInLoop(const Func &cb)
    {
        {
            std::unique_lock<std::mutex> _lock(_mutex);
            _task.push_back(cb);
        }
        WakeUpEventFd();
    }
    void UpdateEvent(Channel *channel) // 添加,修改描述符监控
    {
        return _poller.UpdateEvent(channel);
    }

    void RemoveEvent(Channel *channel) // 移除事件监控
    {
        return _poller.RemoveEvent(channel);
    }
    void RunAllTask() // 执行任务队列全部任务
    {
        std::vector<Func> Func;
        {
            std::unique_lock<std::mutex> _lock(_mutex);
            Func.swap(_task);
        }
        for (auto &f : Func)
        {
            f();
        }
        return;
    }
    void Start() // 封转流程添加监控->就绪事件处理->执行任务队列任务
    {
        while (1)
        {
            std::vector<Channel *> actives;
            _poller.Poll(&actives);
            for (auto &it : actives)
            {
                it->HandleEvent();
            }
            RunAllTask();
        }
    }

    void TimerAdd(uint64_t id, uint32_t delay, const TaskFunc &cb) { return _timerwheel.TimerAdd(id, delay, cb); }
    void TimerRefresh(uint64_t id) { return _timerwheel.TimerRefresh(id); }
    void TimerCancel(uint64_t id) { return _timerwheel.TimerCancel(id); }
    bool HasTimer(uint64_t id) { return _timerwheel.HasTimer(id); }
};
// void TimerWheel::TimerAdd(uint64_t id, uint32_t timeout, const TaskFunc &cb)
// {
//     _loop->RunInLoop(std::bind(&TimerWheel::TimerAddInLoop, this, id, timeout, cb));
// }
// void TimerWheel::TimerCancel(uint64_t id)
// {
//     _loop->RunInLoop(std::bind(&TimerWheel::TimerCancelInLoop, this, id));
// }
// void TimerWheel::TimerRefresh(uint64_t id)
// {
//     _loop->RunInLoop(std::bind(&TimerWheel::TimerRefreshInLoop, this, id));
// }

class Any
{
private:
    class placeholder
    {
    public:
        virtual ~placeholder() {}
        virtual std::type_info &type() = 0;
        virtual placeholder *clone() = 0;
    };
    template <class T>
    class holder : placeholder
    {
    public:
        T _val;

    public:
        holder(const T &val) : _val(val)
        {
        }
        ~holder() {}
        const std::type_info &type() override { return typeid(T); }
        placeholder *clone() override { return new holder(_val); } // 克隆时候直接new一个新的基类返回
    };

    placeholder *_content;

public:
    Any() : _content(NULL)
    {
    }
    template <typename T>
    Any(const T &val) : _content(new holder<T>(val)) {}
    Any(const Any &other) : _content(other._content ? other._content->clone() : NULL)
    {
    }
    ~Any()
    {
        if (_content)
            delete _content;
    }
    const std::type_info &type()
    {
        return _content ? _content->type() : typeid(void);
    }
    template <class T>
    T *get()
    {
        assert(typeid(T) == _content->type());
        return &((holder<T> *)_content)->_val;
    }
    Any &swap(Any &other)
    {
        std::swap(_content, other._content);
        return *this;
    }
    template <typename T>
    Any &operator=(const T val)
    {
        Any(val).swap(*this);
        return *this;
    }

    Any &operator=(Any other)
    {
        other.swap(*this);
        return *this;
    }
};
typedef enum
{
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    DISCONNECTING
} ConnStatu;                                       // 连接状态
class Connection;                                  // forward declaration so shared_ptr can be declared before full type
using PtrConnection = std::shared_ptr<Connection>; // 给外界使用的用智能指针
class Connection : public std::enable_shared_from_this<Connection>
{

private:
    uint64_t _conn_id; // 唯一连接ID
    int _sock_fd;
    bool _enable_inactive_release; // 是否启动非活跃销毁释放
    EventLoop *_loop;              // 连接关联的EP
    Channel _channel;              // 管理Channel
    ConnStatu _statu;              // 管理连接状态
    Socket _socket;                // 管理套接字
    Buffer _in_buffer;
    Buffer _out_buffer;
    Any _context; // 请求的接受处理上下文

    using ConnectedCallBack = std::function<void(const PtrConnection &)>;
    using MessageCallBack = std::function<void(const PtrConnection &, Buffer *)>; // 对缓冲区进行业务处理
    using ClosedCallBack = std::function<void(const PtrConnection &)>;
    using AnyEventCallBack = std::function<void(const PtrConnection &)>;
    using ServeClosedCallBack = std::function<void(const PtrConnection &)>;
    ConnectedCallBack _connected_callback;
    MessageCallBack _message_callback;
    ClosedCallBack _closed_callback;
    AnyEventCallBack _anyevent_callback;
    ClosedCallBack _server_closed_callback;

private:
    void HandleRead()
    {
        char buf[65536];
        int ret = _socket.NonBlockRecv(buf, 65535);
        if (ret < 0)
        {
            return ShutDownInLoop();
        }
        _in_buffer.WriteAndMove(buf, ret);
        if (_in_buffer.ReadableSize() > 0)
        {
            return _message_callback(shared_from_this(), &_in_buffer);
        }
    }
    void HandleWrite()
    {
        uint64_t ret = _socket.NonBlockSend(_out_buffer.ReadPosition(), _out_buffer.ReadableSize());
        if (ret < 0)
        {
            // 如果错误了应该关闭连接,需要查看输入缓冲区是否有内容,清空之后再关闭->输入输出缓冲区不能单独管理吗?
            if (_in_buffer.ReadableSize() > 0)
            {
                _message_callback(shared_from_this(), &_in_buffer);
            }
            return ReleaseInLoop();
        }
        _out_buffer.MoveReaderOffset(ret);
        if (_out_buffer.ReadableSize() == 0)
        {
            _channel.CloseWrite();
            if (_statu == DISCONNECTING)
                return ReleaseInLoop();
        }
        return;
    }
    void HandleClose()
    {
        if (_in_buffer.ReadableSize() > 0)
        {
            _message_callback(shared_from_this(), &_in_buffer);
        }
        return ReleaseInLoop();
    }
    void HandleError()
    {
        HandleClose();
    }
    void HandleEvent()
    {
        if (_enable_inactive_release == true)
        {
            _loop->TimerRefresh(_conn_id);
        }
        if (_anyevent_callback)
        {
            _anyevent_callback(shared_from_this());
        }
    }
    void EstablishedInLoop()
    {
        assert(_statu == CONNECTING); // 当前状态必须是半连接状态
        _statu = CONNECTED;
        _channel.EnableRead(); // 启动读监控
        if (_connected_callback)
        {
            _connected_callback(shared_from_this());
        }
    }
    void ReleaseInLoop()
    {
        // 修改连接状态
        _statu = DISCONNECTED;
        // 移除监控
        _channel.Remove();
        // 关闭描述符
        _socket.Close();
        // 如果有超时任务,取消超时任务
        if (_loop->HasTimer(_conn_id))
        {
            CancelInactiveReleaseInLoop();
        }
        // 调用关闭回调函数
        _closed_callback(shared_from_this());
        // 调用服务器关闭回调函数移除信息
        _server_closed_callback(shared_from_this());
    }
    void SendInLoop(Buffer buf)
    {
        if (_statu == DISCONNECTED)
        {
            return;
        }
        _out_buffer.WriteBufferAndPush(buf);
        if (_channel.WriteAble() == false)
        {
            _channel.EnableWrite();
        }
    }
    void ShutDownInLoop()
    {
        _statu = DISCONNECTING;
        if (_in_buffer.ReadableSize() > 0)
        {
            if (_message_callback)
                _message_callback(shared_from_this(), &_in_buffer);
        }
        if (_out_buffer.ReadableSize() > 0)
        {
            if (_channel.WriteAble() == false)
            {
                _channel.EnableWrite();
            }
            if (_out_buffer.ReadableSize() == 0)
            {
                ReleaseInLoop();
            }
        }
    }
    void EnableInactiveReleaseInLoop(int sec)
    {
        _enable_inactive_release = true;
        if (_loop->HasTimer(_conn_id))
            _loop->TimerRefresh(_conn_id);
    }
    void CancelInactiveReleaseInLoop()
    {
        _enable_inactive_release = false;
        if (_loop->HasTimer(_conn_id))
            _loop->TimerCancel(_conn_id);
    }
    void SwitchProtocolInLoop(const Any &context, const ConnectedCallBack &conn, const MessageCallBack &message, const ClosedCallBack &closed, AnyEventCallBack &anyevent)
    {
        _context = context;
        _connected_callback = conn;
        _message_callback = message;
        _closed_callback = closed;
        _anyevent_callback = anyevent;
    }

public:
    Connection(EventLoop *loop, uint64_t conn_id, int sock_fd) : _conn_id(conn_id), _sock_fd(sock_fd),
                                                                 _enable_inactive_release(false), _loop(loop), _statu(CONNECTING), _socket(_sock_fd),
                                                                 _channel(loop, _sock_fd)
    {
        _channel.SetCloseCallBack(std::bind(&Connection::HandleClose, this));
        _channel.SetEventCallBack(std::bind(&Connection::HandleEvent, this));
        _channel.SetReadCallBack(std::bind(&Connection::HandleRead, this));
        _channel.SetWriteCallBack(std::bind(&Connection::HandleWrite, this));
        _channel.SetErrorCallBack(std::bind(&Connection::HandleError, this));
    }
    ~Connection() {};
    int GetId() { return _conn_id; }
    bool Connnected() { return _statu == CONNECTED; }
    Any *GetContext() { return &_context; }
    void SetConnectedCallBack(const ConnectedCallBack &cb) { _connected_callback = cb; }
    void SetMessageCallBack(const MessageCallBack &cb) { _message_callback = cb; }
    void SetCloseCallBack(const ClosedCallBack &cb) { _closed_callback = cb; }
    void SetAnyEventCallBack(const AnyEventCallBack &cb) { _anyevent_callback = cb; }
    void SetServeClosedCallBack(const ServeClosedCallBack &cb) { _server_closed_callback = cb; }
    void Established()
    {
        _loop->RunInLoop(std::bind(&Connection::EstablishedInLoop, this));
    }
    void Send(const char *data, size_t len)
    {
        Buffer buf;
        buf.WriteAndMove(data, len);
        _loop->RunInLoop(std::bind(&Connection::SendInLoop, this, std::move(buf))); // 采用move函数直接将buffer类底层vector所有权转移,减少了两次BUffer拷贝.减少开销
    }
    void Shutdown(); // 关闭连接(检查缓冲区是否还有数据)
    void EnableInactiveRelease(int timeout)
    {
        _loop->RunInLoop(std::bind(&Connection::EnableInactiveReleaseInLoop, this, timeout));
    }
    void CancelInactiveRelease();
    void SwitchProtocol(const Any &context, const ConnectedCallBack &conn, const MessageCallBack &message, const ClosedCallBack &closed, AnyEventCallBack &anyevent);
};

void Channel::Remove() { return _loop->RemoveEvent(this); }
void Channel::Update() { return _loop->UpdateEvent(this); }

class LoopThread
{
private:
    EventLoop *_loop;
    std::thread _thread;

    std::mutex _mutex;
    std::condition_variable _cond;

private:
    void ThreadEntry()
    {
        EventLoop loop;
        {
            std::unique_lock<std::mutex> lock(_mutex);
            _loop = &loop;
            _cond.notify_all();
        }
        loop.Start();
    }

public:
    LoopThread() : _loop(NULL), _thread(std::thread(&LoopThread::ThreadEntry, this))
    {
    }
    EventLoop *GetLoop()
    {
        EventLoop *loop = NULL;
        {
            std::unique_lock<std::mutex> lock(_mutex);
            // 需要考虑EventLoop还没有构建好的状态:
            _cond.wait(lock, [&]()
                       { return _loop != NULL; });
            loop = _loop;
        }
        return loop;
    }
};

class LoopThreadPool
{
private:
    int _thread_account;
    int _next_idx; // 索引
    EventLoop *_base_loop;
    std::vector<LoopThread *> _threads;
    std::vector<EventLoop *> _loop;

public:
    LoopThreadPool(EventLoop *baseloop) : _thread_account(0), _next_idx(0), _base_loop(baseloop)
    {
    }
    void SetThreadAccount(int account)
    {
        _thread_account = account;
    }
    void Create()
    {
        if (_thread_account > 0)
        {
            _threads.resize(_thread_account);
            _loop.resize(_thread_account);
            for (int i = 0; i < _thread_account; i++)
            {
                _threads[i] = new LoopThread();
                _loop[i] = _threads[i]->GetLoop();
            }
        }
        return;
    }
    EventLoop *NextLoop()
    {
        if (_thread_account == 0)
        {
            return _base_loop;
        }
        else
        {
            _next_idx = (_next_idx + 1) % _thread_account;
            return _loop[_next_idx];
        }
    }
};

class Acceptor
{
private:
    Socket _socket;   // 创建套接字
    EventLoop *_loop; // 对套接字进行监控(留意为什么是指针)
    Channel _channel; // 对监控进行管理

    using AcceptCallBack = std::function<void(int)>;
    AcceptCallBack _accept_callback;

private:
    int CreateServer(int port)
    {
        bool ret = _socket.CreateServer(port);
        assert(ret == true);
        return _socket.GetFd();
    }
    void HandleRead()
    {
        int newfd = _socket.Accept();
        if (newfd < 0)
        {
            return;
        }
        if (_accept_callback)
        {
            _accept_callback(newfd);
        }
    }

public:
    Acceptor(EventLoop *loop, int port) : _loop(loop), _socket(CreateServer(port)), _channel(loop, _socket.GetFd())
    {
        _channel.SetReadCallBack(std::bind(&Acceptor::HandleRead, this));
    }
    void SetAcceptCallBack(const AcceptCallBack &cb) { _accept_callback = cb; }

    void Listen()
    {
        _channel.EnableRead();
    }
};

class TcpServer
{
private:
    uint64_t _conn_id;                                  // 自增长id
    EventLoop _baseloop;                                // 对监听事件管理,baseloop
    Acceptor _acceptor;                                 // 创建监听套接字
    int _port;                                          // 监听端口
    LoopThreadPool _pool;                               // 对新建连接进行事件监控以及管理
    std::unordered_map<uint64_t, PtrConnection> _conns; // 对所有的shared_ptr进行管理
    bool _enable_task_release;                          // 释放非活跃人物
    int _timeout;                                       // 统计超时时间

    using ConnectedCallBack = std::function<void(const PtrConnection &)>;
    using MessageCallBack = std::function<void(const PtrConnection &, Buffer *)>; // 对缓冲区进行业务处理
    using ClosedCallBack = std::function<void(const PtrConnection &)>;
    using AnyEventCallBack = std::function<void(const PtrConnection &)>;
    using ServeClosedCallBack = std::function<void(const PtrConnection &)>;
    ConnectedCallBack _connected_callback;
    MessageCallBack _message_callback;
    ClosedCallBack _closed_callback;
    AnyEventCallBack _anyevent_callback;
    ClosedCallBack _server_closed_callback;

private:
    void NewConnection(int fd)
    {
        _conn_id++;
        PtrConnection conn(new Connection(_pool.NextLoop(), _conn_id, fd));
        conn->SetMessageCallBack(_message_callback);
        conn->SetCloseCallBack(_closed_callback);
        conn->SetConnectedCallBack(_connected_callback);
        conn->SetAnyEventCallBack(_anyevent_callback);
        conn->SetServeClosedCallBack(std::bind(&TcpServer::RemoveConnection, this, std::placeholders::_1));
        if (_enable_task_release)
            conn->EnableInactiveRelease(_timeout); // 启动非活跃超时销毁
        conn->Established();                       // 就绪初始化
        _conns.insert(std::make_pair(_conn_id, conn));
    }
    void RemoveConnectionInLoop(const PtrConnection &conn)
    {
        int id = conn->GetId();
        auto it = _conns.find(id);
        if(it != _conns.end())
        {
            _conns.erase(id);
        }
        
    }
    void RemoveConnection(const PtrConnection &conn) 
    {
        _baseloop.RunInLoop(std::bind(&TcpServer::RemoveConnectionInLoop,this,conn));
    }
    void AddTimeInLoop(const TaskFunc &cb, int delay)
    {
        _conn_id++;
        _baseloop.TimerAdd(_conn_id, delay, cb);
    }

public:
    TcpServer(int port) : _conn_id(0), _port(port), _acceptor(&_baseloop, port), _pool(&_baseloop), _enable_task_release(false)
    {
        _acceptor.SetAcceptCallBack(std::bind(&TcpServer::NewConnection,this,std::placeholders::_1));
        _acceptor.Listen();
    }
    // 设置从属线程数量
    void SetThreadCount(int count)
    {
        _pool.SetThreadAccount(count);
    }
    void Start()
    {
        _pool.Create();
        _baseloop.Start();
    }
    void SetConnectedCallBack(const ConnectedCallBack &cb) { _connected_callback = cb; }
    void SetMessageCallBack(const MessageCallBack &cb) { _message_callback = cb; }
    void SetCloseCallBack(const ClosedCallBack &cb) { _closed_callback = cb; }
    void SetAnyEventCallBack(const AnyEventCallBack &cb) { _anyevent_callback = cb; }
    void SetServeClosedCallBack(const ServeClosedCallBack &cb) { _server_closed_callback = cb; }
    void EnableInactiveRelease(int count)
    {
        _timeout = count;
        _enable_task_release = true;
    }
    void AddTimeTask(const TaskFunc &task, int timeout)
    {
        _baseloop.RunInLoop(std::bind(&TcpServer::AddTimeInLoop, this, task, timeout));
    }
};