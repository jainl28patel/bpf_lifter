#pragma once

// llvm

// bpf
#include <bpf_extern.h>

// std lib includes
#include <iostream>
#include <string>
#include <assert.h>
#include <sys/stat.h>
#include <filesystem>

// lifting
#include <ProgLifter.h>


class Lifter
{
private:
    bpf_object* objcode;

public:

    // constructor
    Lifter(std::string& objfile_path);

    // apis
    void generateIR(std::string& out_dir);

    // destructor
    ~Lifter();

private:

    // default is private
    Lifter();

};