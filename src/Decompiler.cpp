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
        // auto ins = bpf_program__insns(prog);
        // auto cnt = bpf_program__insn_cnt(prog);
        // auto sec_name = bpf_program__section_name(prog);

        // we can access all required data
        // now need to implement lifting for each function

        // lift each program
        this->lift_program(prog);
    }

    return true;
}

void Decompiler::lift_program(bpf_program *prog)
{
    // Initialization
    auto context = std::make_unique<LLVMContext>();
	auto jitModule = std::make_unique<Module>("bpf-jit", *context);
    auto prog_name = bpf_program__name(prog);
    std::vector<bpf_insn> instructions;
    {
        // store instr in vector
        auto instr = bpf_program__insns(prog);
        auto cnt = bpf_program__insn_cnt(prog);
        while(cnt--) {
            instructions.push_back(*instr);
        }

        if(instructions.empty()) { 
            return;
        }
    }

    // Function initialization and creation
    /*
        TODO: Decide the function type, for now going with llvmbpf implementation
        BPF Function type := (I64, I64)
        Two arguments of type I64
    */
    Function *bpf_func = Function::Create(
        FunctionType::get(Type::getInt64Ty(*context),
                { llvm::PointerType::getUnqual(
                        llvm::Type::getInt8Ty(*context)),
                    Type::getInt64Ty(*context) },
                false),
        Function::ExternalLinkage, std::string(prog_name), jitModule.get());

    Argument *mem = bpf_func->getArg(0);
    Argument *mem_len = bpf_func->getArg(1);

    // Now split the instructions into basic blocks
    /*
        Basic block boundary are
        1. start of program
        2. End of program
        3. Transfer of control flow
    */
    std::vector<uint32_t> basicBlockStart(instructions.size(),0); // value will represent the no of basic block
    std::vector<uint32_t> basicBlockEnd(instructions.size(), 0); 

    // identify entry and exit
    int curr_bb = 1;
    basicBlockStart[0] = curr_bb;
    for(uint64_t idx = 0; idx < instructions.size(); idx++)
    {
        // check if control flow changes on prev instruction
        // than this is the starting of new basic block
        if(idx > 0 && is_control_flow_split(instructions[idx-1])) {
            basicBlockStart[idx] = curr_bb;
        }

        // check if control flow split on this instruction
        // then this is the end of current basic block
        // (this is always encountered before begin of new basic block)
        if(is_control_flow_split(instructions[idx])) {
            basicBlockEnd[idx] = curr_bb;
            curr_bb++;
        }
    }

    // link different basic blocks
    std::vector<BasicBlock*> progBasicBlock;
    std::map<uint16_t, BlockAddress*> localFuncRetBlock; // TODO
    std::map<uint16_t, BasicBlock*> instBlocks;

    {
        IRBuilder<> builder(*context);

        for(uint16_t i = 0; i < instructions.size(); i++) {
            if(basicBlockStart[i]) {
                // create new block
                auto curr_block = BasicBlock::Create(*context, "bb" + std::to_string(basicBlockStart[i]), bpf_func);
                instBlocks[i] = curr_block;
                progBasicBlock.push_back(curr_block);

                // if this block is instruction of local function call
                // TODO
            }
        }
    }

    // Last block / exit block
    // TODO

    // Handling of return from local function call
    // TODO

    // Iterate over all instructions and convert
    BasicBlock* currBlock = instBlocks[0];
    IRBuilder<> builder(currBlock);

    for(uint16_t pc = 0; pc < instructions.size(); pc++) {
        auto& curr_inst = instructions[pc];

        // if new basic block start
        if(basicBlockStart[pc]) {
            if(instBlocks.find(pc) != instBlocks.end()) {
                currBlock = instBlocks[pc];
            } else {
                throw "can't find basic block for instruction";
            }
        }

        // set new block in the builder
        builder.SetInsertPoint(currBlock);

        // instruction validation checks
        // TODO: Add more checks
        if(!isValidBPFInstruction(curr_inst)) {
            throw "INVALID bpf instruction";
        }

        // TODO: Lift instructions
        // switch (curr_inst.code)
        // {
        // case 0:
        //     /* code */
        //     break;
        
        // default:
        //     break;
        // }
    }

    // Handle branching for blocks

    // Verify generated module

    // emit / store

}
