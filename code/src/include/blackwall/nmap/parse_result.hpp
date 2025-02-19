#pragma once

#include "nmap.hpp"
#include <rapidxml/rapidxml.hpp>

namespace bw::nmap {
    class NmapParser {
        
        public:

            std::string nmap_output;
            std::string  xml_output;

            void parse(const Nmap &nmap){
                ;
            }

            NmapParser(){}
            ~NmapParser(){}
    };
}