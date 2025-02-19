#pragma once

#include <Amulet/Raw/types.hpp>
#include <blackwall/system/execute.hpp>

namespace bw::nmap {
    using namespace amulet::raw;

    struct CPE{};
    struct CVE{};

    enum SCAN_TECHNIQUES{
        TCP_SYN,
        TCP_CONN,
        TCP_ACK,
        WIN,
        MAIMON,
        UDP,
        TCP_NULL,
        FIN,
        XMAS,
        SCTP_INIT,
        SCTP_COOKIE_ECHO,
        IP_PROT,
        FTP_BOUNCE
    };

    enum HOST_DISCOVERY{
        PING_SCAN,
        ALL_HOSTS_ONLINE,
        TCP_SYN_PORT,
        TCP_ACK_PORT,
        UDP_PORT,
        SCTP_PORT,
        ICMP_ECHO,
        ICMP_TIMESTAMP,
        ICMP_ADDRESS_MASK,
        IP_PROT_PING,
        NO_DNS_RESOLVE,
        ALW_DNS_RESOLVE,
        TRACEROUTE
    };

    enum PORT_SPEC{
        PORT_RANGE,
        FEWER,
        NO_RANDOM
    };

    enum SERVICE_DETECT{
        PROBE,
        TRY_ALL_PROBES,
        VER_TRACE
    };

    enum SCRIPT_SCAN{
        DEFAULT,
        TRACE_SCRIPT,
        CUSTOM
    };

    enum OS_DETECTION{
        ENABLED,
        DISABLED,
        AGGRESIVE
    };

    enum PERFORMANCE{
        SPEED_0,
        SPEED_1,
        SPEED_2,
        SPEED_3,
        SPEED_4,
        SPEED_5
    };

    enum FIREWALL_SPOOFING{
        FRAGMENT_PACKETS,
        DECOYS,
        SPOOF_SOURCE,
        SPOOF_MAC,
        BAD_SUM
    };

    enum OUTPUT{
        NORMAL,
        VERBOSE,
        VERY_VERBOSE
    };

    class Nmap{

            std::string resolveScanTech(SCAN_TECHNIQUES val){
                switch(val){
                    case SCAN_TECHNIQUES::TCP_SYN:    return "sS";
                    case SCAN_TECHNIQUES::TCP_ACK:    return "sA";
                    case SCAN_TECHNIQUES::TCP_CONN:   return "sT";
                    case SCAN_TECHNIQUES::WIN:        return "sW";
                    case SCAN_TECHNIQUES::MAIMON:     return "sM";
                    case SCAN_TECHNIQUES::UDP:        return "sU";
                    case SCAN_TECHNIQUES::TCP_NULL:   return "sN";
                    case SCAN_TECHNIQUES::FIN:        return "sF";
                    case SCAN_TECHNIQUES::XMAS:       return "sX";
                    case SCAN_TECHNIQUES::IP_PROT:    return "sO";
                    case SCAN_TECHNIQUES::FTP_BOUNCE: return "b";
                    
                    case SCAN_TECHNIQUES::SCTP_COOKIE_ECHO: return "sY";
                    case SCAN_TECHNIQUES::SCTP_INIT:        return "sZ";
                }
                return "";
            }

            std::string resolveHostDisc(HOST_DISCOVERY val){
                switch(val){
                    case HOST_DISCOVERY::PING_SCAN:         return "sn";
                    case HOST_DISCOVERY::ALL_HOSTS_ONLINE:  return "Pn";
                    case HOST_DISCOVERY::TCP_SYN_PORT:      return "PS";
                    case HOST_DISCOVERY::TCP_ACK_PORT:      return "PA";
                    case HOST_DISCOVERY::UDP_PORT:          return "PU";
                    case HOST_DISCOVERY::SCTP_PORT:         return "PY";
                    case HOST_DISCOVERY::ICMP_ECHO:         return "PE";
                    case HOST_DISCOVERY::ICMP_TIMESTAMP:    return "PP";
                    case HOST_DISCOVERY::ICMP_ADDRESS_MASK: return "";
                    case HOST_DISCOVERY::IP_PROT_PING:      return "";
                    case HOST_DISCOVERY::NO_DNS_RESOLVE:    return "";
                    case HOST_DISCOVERY::ALW_DNS_RESOLVE:   return "";
                    case HOST_DISCOVERY::TRACEROUTE:        return "";
                }
                return "";
            }

            std::string resolvePortSpec(PORT_SPEC val){
                switch(val){
                    case PORT_SPEC::FEWER: return "F";
                    case PORT_SPEC::NO_RANDOM: return "r";
                }
                return "";
            }

        public:
            Address address;
            std::vector<short> ports;

            std::vector<SCAN_TECHNIQUES>   scanTechniques;
            std::vector<HOST_DISCOVERY>    hostDiscovery;
            std::vector<PORT_SPEC>         portSpecs;
            std::vector<SERVICE_DETECT>    serviceDetection;
            std::vector<SCRIPT_SCAN>       scriptsSpecs;
            std::vector<FIREWALL_SPOOFING> firewallSpoofing;

            OS_DETECTION osDetection;
            PERFORMANCE  performance;
            OUTPUT       output;
            
            void scan(
                Address address,
                std::string output_file = "",
                std::vector<int> specified_ports = {}
            ){
                
                std::string nmap_command = "nmap";

                for (auto & technique : scanTechniques)
                    nmap_command += " -" + technique;
                


                sys::execute("mkdir -p ./tmp/nmap");
                sys::execute(nmap_command);
            }

            Nmap(){}
            ~Nmap(){}
    };
}