#include <blackwall/nmap/nmap.hpp>
#include <utils/files.hpp>
#include <utils/vector.hpp>

int main(){
    auto lines = utils::vec::stripsplit(
        utils::fls::getFile("./dev/results/random_10000_scan"),
        '\n'
    );

    for (auto &line: lines){
        if (utils::str::count(line, '(') != 0 && utils::str::count(line, "report") != 0){
            auto start = line.find('(');
            auto end = line.find(')');
            auto target_ip = line.substr(start + 1, end - start - 1);
            
            // std::cout << target_ip << std::endl;
            int status = 0;
            std::string out = bw::sys::execute("sshpass -p root ssh -o ConnectTimeout=10 root@" + target_ip, &status);
            // if (status == 0){
            std::cout << target_ip << " >>---------\n";
            std::cout << out << std::endl;
            // }
        }
    }
}