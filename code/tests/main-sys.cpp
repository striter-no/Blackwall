#include <iostream>
#include <blackwall/system/execute.hpp>

int main(){

    std::vector<std::string> buffer;

    bw::sys::execute(
        "nmap -oA 192.168.31.100",
        buffer
    );

    for (const auto& line : buffer){
        std::cout << line << std::endl;
    }
}