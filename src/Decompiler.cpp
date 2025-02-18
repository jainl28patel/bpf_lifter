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
    for(auto&sec : elf.sections)
    {
        ELFSection sec_type = StringToELFSection(sec->get_name());

        switch (sec_type)
        {
        case ELFSection::XDP:
        {
            // For now iterate over functions present and get llvm IR
            // symbol_section_accessor sym_accessor(elf, sec.get());
            // int sym_cnt = sym_accessor.get_symbols_num();
            // std::cout << "cnt : " << sym_cnt << std::endl;
            // std::cout << "class : " << elf.get_class() << std::endl;
            // for(int sym_idx = 0; sym_idx < sym_cnt; sym_idx++)
            // {
            //     SymbolDetails sym_details;
            //     sym_details.index = sym_idx;
            //     sym_accessor.get_symbol(sym_details.index, sym_details.name, sym_details.size, sym_details.bind, sym_details.type, sym_details.section_index, sym_details.other);
            //     std::cout << "Symbol Name : " << sym_details.name << std::endl;
            // }
        }
        break;
        
        default:
            // std::cout << "Section Not supported" << std::endl;
            break;
        }

    }

    return true;
}
