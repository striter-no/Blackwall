#include <blackwall/nmap/nmap.hpp>
#include <blackwall/nmap/parse_result.hpp>

int main(){
    bw::nmap::Nmap scaner;

    scaner.option( bw::nmap::NORMAL );
    scaner.option( bw::nmap::PROBE );
    scaner.option( bw::nmap::AGGRESIVE );
    scaner.option( bw::nmap::SPEED_4 );
    
    scaner.option( bw::nmap::OS_DETECTION::ENABLED );

    // scaner.option( bw::nmap::CUSTOM_VULNERS );
    scaner.option( bw::nmap::CUSTOM_GEOLOC, true);
    scaner.option( bw::nmap::CUSTOM_WHOIS_IP, true);

    std::string ip = "192.168.31.100";

    std::string out = scaner.scan(
        ip,
        "./dev/results/vuln_norm_result_" + ip
    );

    // std::cout << out << std::endl;

    out = scaner.scan(
        ip,
        "./dev/results/vuln_norm_result_" + ip
    );

    // std::cout << out << std::endl;

    bw::nmap::NmapParser parser;
    parser.nmap_output = out;
    parser.nmap = &scaner;

    parser.parse();

    std::cout << parser.stringify() << std::endl;
}