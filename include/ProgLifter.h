#pragma once

#include <string>

// contains the main logic to lift each program bytecode to IR
class ProgLifter
{
private:
    std::string out_file;

public:

    ProgLifter(std::string& out_file);
    void getIR(); //TODO: Determine return type
    void dumpIR();

private:

    ProgLifter();
};