#include "EchoServer.hpp"

int main()
{
    EchoServer server(8087);
    server.Start();
    return 0;
}