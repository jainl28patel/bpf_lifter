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

bool Decompiler::process_elf(elfio &elf)
{
    // iterate over all section and store information
    size_t num_sec = elf.sections.size();
    for(auto i = 0; i < num_sec; i++)
    {
        section* sec = elf.sections[i];
        std::cout << sec->get_name() << std::endl;
    }

    return true;
}
