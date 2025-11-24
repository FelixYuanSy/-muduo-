#pragma once
#include "../server.hpp"
class EchoServer
{
private:
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
        conn->Send(buf->ReadPosition(), buf->ReadableSize());
        buf->MoveReaderOffset(buf->ReadableSize());
        conn->Shutdown();
    }

private:
    TcpServer _server;

public:
    EchoServer(int port) : _server(port)
    {

        _server.SetThreadCount(2);
        // _server.EnableInactiveRelease(10);
        _server.SetCloseCallBack(std::bind(&EchoServer::OnClosed,this,std::placeholders::_1));
        _server.SetConnectedCallBack(std::bind(&EchoServer::OnConnected,this,std::placeholders::_1));
        _server.SetMessageCallBack(std::bind(&EchoServer::OnMessage,this,std::placeholders::_1,std::placeholders::_2));
    }

    void Start(){_server.Start();}

};