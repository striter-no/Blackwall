#include <cmath>
#include <iostream>
#include <Amulet/Main/servers/DetachedServer.hpp>
#include <blackwall/nmap/nmap.hpp>
#include <utils/files.hpp>

using namespace amulet::main;

int main(){
    servers::DetachedServer server(
        {"192.168.31.100", 8080},
        std::pow(2, 13),
        true
    );

    bw::nmap::Nmap scaner;

    scaner.option( bw::nmap::NORMAL );
    scaner.option( bw::nmap::PROBE );
    scaner.option( bw::nmap::AGGRESIVE );
    scaner.option( bw::nmap::SPEED_4 );

    scaner.option( bw::nmap::OS_DETECTION::ENABLED );

    scaner.option( bw::nmap::ALL_PORTS );


    server.callbackOnClientConnected(
        [&](servers::ClientData &client){
            std::cout << "Client with address \"" << (std::string)client.socket.address() << "\" connected" << std::endl;
            std::string ip = client.socket.address().only_ip();
            auto tmp = scaner.scan(
                ip,
                std::string("./dev/results/basic_vuln_norm_result_") + ip
            );
            std::cout << "Scan result: " << tmp << std::endl;
            
            scaner.option( bw::nmap::CUSTOM_WHOIS_IP, true);
            scaner.option( bw::nmap::CUSTOM_GEOLOC, true);
            scaner.option( bw::nmap::CUSTOM_TOR_CHECK, true);
            
            auto tmp = scaner.scan(
                ip,
                std::string("./dev/results/ex_vuln_norm_result_") + ip
            );

            scaner.option( bw::nmap::CUSTOM_VULNERS, true );
            
            auto tmp = scaner.scan(
                ip,
                std::string("./dev/results/vuln_vuln_norm_result_") + ip
            );
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
            // response = "Echo: " + message;

            utils::fls::writeFile("./dev/messages/message_" + client.socket.address().only_ip() + ".msg", message);
            std::cout << "Client with address \"" << (std::string)client.socket.address() << "\" sent \"" << message << '"' << std::endl;
            // std::cout << "...and server replied: " << response << std::endl;
        }
    );
    
    server.startup(30);
    
    while(true){
        ; // Listening
    }
    
    server.stop();
}