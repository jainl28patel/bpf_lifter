#pragma once

#include <string>
#include <vector>

// from source code
#include <bpf_extern.h>
#include <elfio/elfio.hpp>
#include <elf_utils.h>
#include <bpf_utils.h>

// llvm
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/DerivedTypes.h>

using namespace ELFIO;
using namespace llvm;

// contains the main logic to lift each program bytecode to IR
class Decompiler
{
private:
    std::string out_file;
    std::unordered_map<std::string, FunctionData> funcs; // name -> data

public:

    Decompiler(std::string& out_file);
    void getIR(bpf_program* prog); //TODO: Determine return type
    void dumpIR(bpf_program* prog);

    // Elf functions
    bool process_elf(elfio& elf, std::string& object_file);

private:

    Decompiler();
    void lift_program(bpf_program* prog);
};