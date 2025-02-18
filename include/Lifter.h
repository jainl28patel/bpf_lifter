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
#include <Decompiler.h>
#include <elf_utils.h>
#include <elfio/elfio.hpp>

using namespace ELFIO;

class Lifter
{
private:
    std::string object_file;
    elfio elf;

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