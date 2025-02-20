#pragma once

#include <utils/string.hpp>

namespace bw::sys{
    void execute(
        std::string command,
        std::vector<std::string> &lines_buffer,
        int *status
    ){
        char * line = NULL;
        size_t len = 0;
        ssize_t read;

        // Redirect stderr to stdout
        command += " 2>&1";
        
        FILE *pin = popen(command.c_str(), "r");
        if (pin == NULL){
            *status = -993;
            return;
        }

        std::string output;
        while ((read = getline(&line, &len, pin)) != -1) {
            output += line;
        }

        int exit_code = pclose(pin);
        if (line)
            free(line);
        
        // return {output, WEXITSTATUS(exit_code)};
    }

    std::string execute(
        std::string command,
        int *status
    ){
        char * line = NULL;
        size_t len = 0;
        ssize_t read;

        // Redirect stderr to stdout
        command += " 2>&1";
        
        FILE *pin = popen(command.c_str(), "r");
        if (pin == NULL){
            *status = -993;
            return "";
        }

        std::string output;
        while ((read = getline(&line, &len, pin)) != -1) {
            output += line;
        }

        int exit_code = pclose(pin);
        if (line)
            free(line);
        
        *status = WEXITSTATUS(exit_code);

        return output;
    }
}
