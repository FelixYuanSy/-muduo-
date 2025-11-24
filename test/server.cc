#include "server.hpp"
#include <iostream>

void OnConnected(const PtrConnection &conn)
{
    DBG_LOG("NEW CONNECTION:%p", conn.get());
}
void OnClosed(const PtrConnection &conn)
{
    DBG_LOG("CLOSE CONNECTION:%p", conn.get());
}
void OnMessage(const PtrConnection &conn, Buffer *buf)
{
    DBG_LOG("%s", buf->ReadPosition());
    buf->MoveReaderOffset(buf->ReadableSize());
    std::string str = "Hello World";
    conn->Send(str.c_str(), str.size());
}
int main()
{
    TcpServer server(8087);
    server.SetThreadCount(2);
    // server.EnableInactiveRelease(10);
    server.SetCloseCallBack(OnClosed);
    server.SetConnectedCallBack(OnConnected);
    std::cout<<"turn to message\n";
    server.SetMessageCallBack(OnMessage);
    server.Start();
    return 0;
}