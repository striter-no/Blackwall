#pragma once

#include <blackwall/system/execute.hpp>

namespace bw::nmap {

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
        // IP_PROT_PING,
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
        NO_SCRIPT, // None
        DEFAULT, // sC
        TRACE_SCRIPT, // script-trace
        // EXPOIT, // TODO: implement
        CUSTOM_VULNERS, // vulners
        CUSTOM_GEOLOC, // ip-geolocation-geoplugin
        // CUSTOM_SSH_AUTH_INFO, // ssh-auth-methods TODO --script-args="ssh.user=<username>"
        CUSTOM_AUTH_SPOOF, // auth-spoof
        CUSTOM_TOR_CHECK, // tor-consensus-checker
        CUSTOM_WHOIS_IP, // whois-ip
        CUSTOM_WHOIS_DOMEN // whois-domen
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
        // DECOYS, TODO
        // SPOOF_SOURCE,
        // SPOOF_MAC,
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
                    case HOST_DISCOVERY::ICMP_ADDRESS_MASK: return "PM";
                    // case HOST_DISCOVERY::IP_PROT_PING:      return "";
                    case HOST_DISCOVERY::NO_DNS_RESOLVE:    return "n";
                    case HOST_DISCOVERY::ALW_DNS_RESOLVE:   return "R";
                    case HOST_DISCOVERY::TRACEROUTE:        return "traceroute";
                }
                return "";
            }

            std::string resolveServiceDet(SERVICE_DETECT val){
                switch(val){
                    case SERVICE_DETECT::PROBE: return "sV";
                    case SERVICE_DETECT::TRY_ALL_PROBES: return "version-all";
                    case SERVICE_DETECT::VER_TRACE: return "version-trace";
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

            std::string resolveScripts(SCRIPT_SCAN val){
                switch(val){
                    case SCRIPT_SCAN::NO_SCRIPT: return "";
                    case SCRIPT_SCAN::DEFAULT: return "sC";
                    case SCRIPT_SCAN::TRACE_SCRIPT: return "script-trace";
                    case SCRIPT_SCAN::CUSTOM_VULNERS: return "vulners";
                    case SCRIPT_SCAN::CUSTOM_GEOLOC: return "ip-geolocation-geoplugin";
                    case SCRIPT_SCAN::CUSTOM_AUTH_SPOOF: return "auth-spoof";
                    case SCRIPT_SCAN::CUSTOM_TOR_CHECK: return "tor-consensus-checker";
                    case SCRIPT_SCAN::CUSTOM_WHOIS_IP: return "whois-ip";
                    case SCRIPT_SCAN::CUSTOM_WHOIS_DOMEN: return "whois-domen";
                }

                return "";
            }

            std::string resolveOsDet(OS_DETECTION val){
                switch(val){
                    case OS_DETECTION::DISABLED: return "";
                    case OS_DETECTION::ENABLED: return "O";
                    case OS_DETECTION::AGGRESIVE: return "osscan-guess";
                }

                return "";
            }

            std::string resolvePerf(PERFORMANCE val){
                switch(val){
                    case PERFORMANCE::SPEED_0: return "T0";
                    case PERFORMANCE::SPEED_1: return "T1";
                    case PERFORMANCE::SPEED_2: return "T2";
                    case PERFORMANCE::SPEED_3: return "T3";
                    case PERFORMANCE::SPEED_4: return "T4";
                    case PERFORMANCE::SPEED_5: return "T5";
                }

                return "";
            }

            std::string resolveFirewallSpoof(FIREWALL_SPOOFING val){
                switch(val){
                    case FIREWALL_SPOOFING::FRAGMENT_PACKETS: return "f";
                    case FIREWALL_SPOOFING::BAD_SUM: return "badsum";
                }

                return "";
            }

            std::string resolveOutput(OUTPUT val){
                switch(val){
                    case OUTPUT::NORMAL: return "oN";
                    case OUTPUT::VERBOSE: return "v";
                    case OUTPUT::VERY_VERBOSE: return "vv";
                }

                return "";
            }

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

        public:
            
            void option(SCAN_TECHNIQUES val){ scanTechniques.push_back(val);}
            void option(HOST_DISCOVERY val){ hostDiscovery.push_back(val);}
            void option(SERVICE_DETECT val){ serviceDetection.push_back(val);}
            void option(SCRIPT_SCAN val){ scriptsSpecs.push_back(val);}
            void option(FIREWALL_SPOOFING val){ firewallSpoofing.push_back(val);}
            void option(OS_DETECTION val){ osDetection = val;}
            void option(PERFORMANCE val){ performance = val;}
            void option(OUTPUT val){ output = val;}

            void scan(
                std::string address,
                std::string output_file = "",
                std::vector<int> specified_ports = {}
            ){
                
                std::string nmap_command = "nmap";

                for (auto &val : scanTechniques){
                    std::string str_val = resolveScanTech(val);
                    if (str_val.empty()) continue;
                    nmap_command += " -" + str_val;
                }
                
                for (auto &val: hostDiscovery){
                    std::string str_val = resolveHostDisc(val);
                    if (str_val.empty()) continue;
                    nmap_command += " -" + str_val;
                }
                
                for (auto &val: portSpecs){
                    std::string str_val = resolvePortSpec(val);
                    if (str_val.empty()) continue;
                    nmap_command += " -" + str_val;
                }
                
                for (auto &val: serviceDetection){
                    std::string str_val = resolveServiceDet(val);
                    if (str_val.empty()) continue;
                    nmap_command += " -" + str_val;
                }
                
                for (auto &val: firewallSpoofing){
                    std::string str_val = resolveFirewallSpoof(val);
                    if (str_val.empty()) continue;
                    nmap_command += " -" + str_val;
                }
                
                for (auto &val: scriptsSpecs){
                    if (val == SCRIPT_SCAN::DEFAULT){
                        nmap_command += resolveScripts(val);
                        continue;
                    }

                    if (val == SCRIPT_SCAN::TRACE_SCRIPT){
                        nmap_command += "--" + resolveScripts(val);
                        continue;
                    }

                    std::string str_val = resolveScripts(val);
                    nmap_command += " --script=" + str_val;
                }

                std::string str_val = resolveOsDet(osDetection);
                if (!str_val.empty()) nmap_command += " -O " + str_val;

                str_val = resolvePerf(performance);
                if (!str_val.empty()) nmap_command += " -O " + str_val;

                str_val = resolveOutput(output);
                if (!str_val.empty()) nmap_command += " -O " + str_val;

                nmap_command += " -oX " + output_file;
                nmap_command += " " + address;

                sys::execute("mkdir -p ./tmp/nmap");

                std::cout << nmap_command << std::endl;
                sys::execute(nmap_command);
            }

            Nmap(){}
            ~Nmap(){}
    };
}