#include "server.hpp"

void HandleRead(Channel channel)
{
    int fd = channel.Getfd();
    char buf[1024] = {0};
    int ret = recv(fd, buf, 1023, 0);
    if (ret < 0)
    {
    }
}

std::unordered_map<uint64_t, PtrConnection> _conns;
uint64_t conn_id = 0;
void ConnectionDestroy(const PtrConnection &conn)
{
    _conns.erase(conn->GetId());
}

void OnConnected(const PtrConnection &conn)
{
    DBG_LOG("NEW CONNECTION:%p", conn.get());
}

void OnMessage(const PtrConnection &conn, Buffer *buf)
{
    DBG_LOG("%s", buf->ReadPosition());
    buf->MoveReaderOffset(buf->ReadableSize());
    std::string str = "Hello World";
    conn->Send(str.c_str(), str.size());
}

void Acceptor(EventLoop *loop, Channel *lst_channel)
{
    int fd = lst_channel->Getfd();
    int newfd = accept(fd, NULL, NULL);
    if (newfd < 0)
        return;
    conn_id++;
    PtrConnection conn(new Connection(loop, conn_id, newfd));
    conn->SetMessageCallBack(std::bind(OnMessage, std::placeholders::_1, std::placeholders::_2));
    conn->SetServeClosedCallBack(std::bind(ConnectionDestroy, std::placeholders::_1));
    conn->SetConnectedCallBack(std::bind(OnConnected, std::placeholders::_1));
    conn->EnableInactiveRelease(10);
    conn->Established();
    _conns.insert(std::make_pair(conn_id,conn));
}

int main()
{
    srand(time(NULL));
    EventLoop loop;
    Socket socket;
    socket.CreateServer(8087);
    Channel channel(&loop,socket.GetFd());
    channel.SetReadCallBack(std::bind(Acceptor,&loop,&channel));
    channel.EnableRead();
    while(1)
    {
        loop.Start();
    }
    socket.Close();
    return 0;
}