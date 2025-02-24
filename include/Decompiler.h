#pragma once

#include <string>
#include <vector>
#include <cassert>

// from source code
#include <bpf_extern.h>
#include <elfio/elfio.hpp>
#include <elf_utils.h>
#include <instr_utils.h>

// llvm
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Verifier.h>

using namespace ELFIO;
using namespace llvm;

const int EBPF_STACK_SIZE = 512;
const int STACK_SIZE = (EBPF_STACK_SIZE + 7) / 8;
const int CALL_STACK_SIZE = 64;
const size_t MAX_LOCAL_FUNC_DEPTH = 32;


// contains the main logic to lift each program bytecode to IR
class Decompiler
{
private:
    std::string out_file;
    std::unordered_map<std::string, FunctionData> funcs; // name -> data
    std::unordered_map<int, helper_func_def> helper_func_metadata; // ptr -> data

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