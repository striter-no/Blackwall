#include <cmath>
#include <iostream>
#include <Amulet/Main/servers/DetachedServer.hpp>

using namespace amulet::main;

int main(){
    servers::DetachedServer server(
        {"192.168.31.100", 8080},
        std::pow(2, 13),
        true
    );

    server.callbackOnClientConnected(
        [&](servers::ClientData &client){
            std::cout << "Client with address \"" << (std::string)client.socket.address() << "\" connected" << std::endl;
        }
    );
    
    server.callbackOnClientDisconnected(
        [&](servers::ClientData &client){
            std::cout << "Client with address \"" << (std::string)client.socket.address() << "\" diconnected" << std::endl;
        }
    );
    
    server.callbackOnClientForcefullyDisconnected(
        [&](servers::ClientData &client){
            std::cout << "Client with address \"" << (std::string)client.socket.address() << "\" forcefully disconnected" << std::endl;
        }
    );

    server.callbackOnClientMessage(
        [&](servers::ClientData &client, const std::string &message, std::string &response){
            response = "Echo: " + message;

            std::cout << "Client with address \"" << (std::string)client.socket.address() << "\" sent \"" << message << '"' << std::endl;
            std::cout << "...and server replied: " << response << std::endl;
        }
    );
    
    server.startup(30);
    
    while(true){
        ; // Listening
    }
    
    server.stop();
}