#pragma once

#include <utils/string.hpp>

namespace bw::sys{
    void execute(
        std::string command,
        std::vector<std::string> &lines_buffer
    ){
        char * line = NULL;
        size_t len = 0;
        ssize_t read;

        FILE *pin = popen(command.c_str(), "r");
        if (pin == NULL)
            return;

        while ((read = getline(&line, &len, pin)) != -1) {
            lines_buffer.push_back(line);
        }

        fclose(pin);
        if (line)
            free(line);
    }

    std::string execute(
        std::string command
    ){
        char * line = NULL;
        size_t len = 0;
        ssize_t read;

        FILE *pin = popen(command.c_str(), "r");
        if (pin == NULL)
            return "";

        std::string output;
        while ((read = getline(&line, &len, pin)) != -1) {
            output += line;
        }

        fclose(pin);
        if (line)
            free(line);
        
        return output;
    }
}