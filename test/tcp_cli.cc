#include "../server.hpp"

int main()
{
    Socket cli_sock;
    cli_sock.CreateClient(8087, "127.0.0.1");
    std::cout << "create succ"<<std::endl;
    for (int i = 0; i < 5; i++)
    {
        std::string str = "hello bitejiuyeke!";
        std::cout<<str<<std::endl;
        cli_sock.Send(str.c_str(), str.size());
        std::cout<<"Runing finish send"<<std::endl;
        char buf[1024] = {0};
        cli_sock.Rcev(buf, 1023);
        DBG_LOG("%s", buf);
        sleep(1);
    }
    while (1)
        sleep(1);
    return 0;
}