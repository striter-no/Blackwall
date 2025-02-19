#include <blackwall/nmap/nmap.hpp>

int main(){
    bw::nmap::Nmap scaner;

    scaner.option( bw::nmap::NORMAL );
    scaner.option( bw::nmap::SERVICE_DETECT::PROBE );
    
    scaner.option( bw::nmap::CUSTOM_VULNERS );
    scaner.option( bw::nmap::CUSTOM_GEOLOC  );

    std::string out = scaner.scan(
        "83.222.191.202",
        "./dev/results/vuln_norm_result"
    );

    
}