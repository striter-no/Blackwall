#include <blackwall/nmap/nmap.hpp>

int main(){
    bw::nmap::Nmap scaner;

    scaner.option( bw::nmap::CUSTOM_VULNERS );

    scaner.scan(
        "192.168.31.100",
        "./dev/results/local_result"
    );
}