#include <Decompiler.h>

Decompiler::Decompiler(std::string& out_file)
    : out_file(out_file)
{

}

void Decompiler::getIR(bpf_program* prog)
{
    // main logic to get the IR of a bpf program
    
}

void Decompiler::dumpIR(bpf_program* prog)
{
}

bool Decompiler::process_elf(elfio &elf, std::string& object_file)
{

    /*  Approach
        1. Iterate over all sections and preprocess and store all required information
        2. Iterate over all bpf program present and convert to IR using llvm IR builder
        3. Generate required IR information using other information obtained from elf file
        4. Handle definition of maps, helper structs, programs, used bpf_helper_functions, section of each program etc
        5. Compile everything into llvm::Module and get the whole IR
    */

    // iterate over all section and store information
    for(auto&sec : elf.sections)
    {
        ELFSection sec_type = StringToELFSection(sec->get_name());

        switch (sec_type)
        {
        case ELFSection::XDP:
        {
            // For now iterate over functions present and get llvm IR

            // break into different function.
            // In ebpf function ends at syscall 'exit'. Also code after that won't be useful
            // as ebpf doesn't allow backwards jump in the bytecode
            
        }
        break;
        
        default:
            // std::cout << "Section Not supported" << std::endl;
            break;
        }

    }


    // iterate over all programs and process them
    bpf_object* obj = bpf_object__open(object_file.c_str());
    bpf_program* prog;
    bpf_object__for_each_program(prog, obj)
    {
        auto ins = bpf_program__insns(prog);
        auto cnt = bpf_program__insn_cnt(prog);
        auto sec_name = bpf_program__section_name(prog);

        // we can access all required data
        // now need to implement lifting for each function
    }

    return true;
}
