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


    std::vector<Value *> regs;
	std::vector<BasicBlock*> progBasicBlock;;
	// Stack used to save return address and saved registers
	// Value *callStack, *callItemCnt;
	{
		BasicBlock *setupBlock =
			BasicBlock::Create(*context, "setupBlock", bpf_func);
        progBasicBlock.push_back(setupBlock);
		IRBuilder<> builder(setupBlock);
		// Create registers

		for (int i = 0; i <= 10; i++) {
			regs.push_back(builder.CreateAlloca(
				builder.getInt64Ty(), nullptr,
				"r" + std::to_string(i)));
		}
		// // Create stack
		// auto stackBegin = builder.CreateAlloca(
		// 	builder.getInt64Ty(),
		// 	builder.getInt32(STACK_SIZE * MAX_LOCAL_FUNC_DEPTH +
		// 			 10),
		// 	"stackBegin");
		// auto stackEnd = builder.CreateGEP(
		// 	builder.getInt64Ty(), stackBegin,
		// 	{ builder.getInt32(STACK_SIZE * MAX_LOCAL_FUNC_DEPTH) },
		// 	"stackEnd");
		// // Write stack pointer into r10
		// builder.CreateStore(stackEnd, regs[10]);
		// // Write memory address into r1
		// builder.CreateStore(mem, regs[1]);
		// // Write memory len into r1
		// builder.CreateStore(mem_len, regs[2]);

		// callStack = builder.CreateAlloca(
		// 	builder.getPtrTy(),
		// 	builder.getInt32(CALL_STACK_SIZE * 5), "callStack");
		// callItemCnt = builder.CreateAlloca(builder.getInt64Ty(),
		// 				   nullptr, "callItemCnt");
		// builder.CreateStore(builder.getInt64(0), callItemCnt);
	}

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
        auto& inst = instructions[pc];

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
        if(!isValidBPFInstruction(inst)) {
            throw "INVALID bpf instruction";
        }

        // TODO: Lift instructions
		switch (inst.code) {
			// ALU
		case EBPF_OP_ADD64_IMM:
		case EBPF_OP_ADD_IMM:
		case EBPF_OP_ADD64_REG:
		case EBPF_OP_ADD_REG: {
			emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateAdd(dst_val,
								 src_val);
				});
			break;
		}
		case EBPF_OP_SUB64_IMM:
		case EBPF_OP_SUB_IMM:
		case EBPF_OP_SUB64_REG:
		case EBPF_OP_SUB_REG: {

			break;
		}
		case EBPF_OP_MUL64_IMM:
		case EBPF_OP_MUL_IMM:
		case EBPF_OP_MUL64_REG:
		case EBPF_OP_MUL_REG: {

			break;
		}
		case EBPF_OP_DIV64_IMM:
		case EBPF_OP_DIV_IMM:
		case EBPF_OP_DIV64_REG:
		case EBPF_OP_DIV_REG: {
			// Set dst to zero if trying to being divided by
			// zero

			break;
		}
		case EBPF_OP_OR64_IMM:
		case EBPF_OP_OR_IMM:
		case EBPF_OP_OR64_REG:
		case EBPF_OP_OR_REG: {

			break;
		}
		case EBPF_OP_AND64_IMM:
		case EBPF_OP_AND_IMM:
		case EBPF_OP_AND64_REG:
		case EBPF_OP_AND_REG: {

			break;
		}
		case EBPF_OP_LSH64_IMM:
		case EBPF_OP_LSH_IMM:
		case EBPF_OP_LSH64_REG:
		case EBPF_OP_LSH_REG: {

			break;
		}
		case EBPF_OP_RSH64_IMM:
		case EBPF_OP_RSH_IMM:
		case EBPF_OP_RSH64_REG:
		case EBPF_OP_RSH_REG: {

			break;
		}
		case EBPF_OP_NEG:
		case EBPF_OP_NEG64: {

			break;
		}
		case EBPF_OP_MOD64_IMM:
		case EBPF_OP_MOD_IMM:
		case EBPF_OP_MOD64_REG:
		case EBPF_OP_MOD_REG: {

			break;
		}
		case EBPF_OP_XOR64_IMM:
		case EBPF_OP_XOR_IMM:
		case EBPF_OP_XOR64_REG:
		case EBPF_OP_XOR_REG: {

			break;
		}
		case EBPF_OP_MOV64_IMM:
		case EBPF_OP_MOV_IMM:
		case EBPF_OP_MOV64_REG:
		case EBPF_OP_MOV_REG: {

			break;
		}
		case EBPF_OP_ARSH64_IMM:
		case EBPF_OP_ARSH_IMM:
		case EBPF_OP_ARSH64_REG:
		case EBPF_OP_ARSH_REG: {

			break;
		}
		case EBPF_OP_LE:
		case EBPF_OP_BE: {

			break;
		}

			// ST and STX
			//  Only supports mode = 0x60
		case EBPF_OP_STB:
		case EBPF_OP_STXB: {
			break;
		}
		case EBPF_OP_STH:
		case EBPF_OP_STXH: {

			break;
		}
		case EBPF_OP_STW:
		case EBPF_OP_STXW: {

			break;
		}
		case EBPF_OP_STDW:
		case EBPF_OP_STXDW: {

			break;
		}
			// LDX
			// Only supports mode=0x60
		case EBPF_OP_LDXB: {
			break;
		}
		case EBPF_OP_LDXH: {

			break;
		}
		case EBPF_OP_LDXW: {

			break;
		}
		case EBPF_OP_LDXDW: {

			break;
		}
		// LD
		// Keep compatiblity to ubpf
		case EBPF_OP_LDDW: {
			// ubpf only supports EBPF_OP_LDDW in instruction class
			// EBPF_CLS_LD, so do us
			break;
		}
			// JMP
		case EBPF_OP_JA: {

			break;
		}
			// Call helper or local function
		case EBPF_OP_CALL:
			// Work around for clang producing instructions
			// that we don't support
		case EBPF_OP_CALL | 0x8: {
			// Call local function


			break;
		}
		case EBPF_OP_EXIT: {

			break;
		}

		case EBPF_OP_JEQ32_IMM:
		case EBPF_OP_JEQ_IMM:
		case EBPF_OP_JEQ32_REG:
		case EBPF_OP_JEQ_REG: {

			break;
		}

		case EBPF_OP_JGT32_IMM:
		case EBPF_OP_JGT_IMM:
		case EBPF_OP_JGT32_REG:
		case EBPF_OP_JGT_REG: {

			break;
		}
		case EBPF_OP_JGE32_IMM:
		case EBPF_OP_JGE_IMM:
		case EBPF_OP_JGE32_REG:
		case EBPF_OP_JGE_REG: {

			break;
		}
		case EBPF_OP_JSET32_IMM:
		case EBPF_OP_JSET_IMM:
		case EBPF_OP_JSET32_REG:
		case EBPF_OP_JSET_REG: {

			break;
		}
		case EBPF_OP_JNE32_IMM:
		case EBPF_OP_JNE_IMM:
		case EBPF_OP_JNE32_REG:
		case EBPF_OP_JNE_REG: {

			break;
		}
		case EBPF_OP_JSGT32_IMM:
		case EBPF_OP_JSGT_IMM:
		case EBPF_OP_JSGT32_REG:
		case EBPF_OP_JSGT_REG: {

			break;
		}
		case EBPF_OP_JSGE32_IMM:
		case EBPF_OP_JSGE_IMM:
		case EBPF_OP_JSGE32_REG:
		case EBPF_OP_JSGE_REG: {

			break;
		}
		case EBPF_OP_JLT32_IMM:
		case EBPF_OP_JLT_IMM:
		case EBPF_OP_JLT32_REG:
		case EBPF_OP_JLT_REG: {

			break;
		}
		case EBPF_OP_JLE32_IMM:
		case EBPF_OP_JLE_IMM:
		case EBPF_OP_JLE32_REG:
		case EBPF_OP_JLE_REG: {

			break;
		}
		case EBPF_OP_JSLT32_IMM:
		case EBPF_OP_JSLT_IMM:
		case EBPF_OP_JSLT32_REG:
		case EBPF_OP_JSLT_REG: {

			break;
		}
		case EBPF_OP_JSLE32_IMM:
		case EBPF_OP_JSLE_IMM:
		case EBPF_OP_JSLE32_REG:
		case EBPF_OP_JSLE_REG: {

			break;
		}
		case EBPF_ATOMIC_OPCODE_32:
		case EBPF_ATOMIC_OPCODE_64: {
			switch (inst.imm) {
			case EBPF_ATOMIC_ADD:
			case EBPF_ATOMIC_ADD | EBPF_ATOMIC_OP_FETCH: {
				break;
			}

			case EBPF_ATOMIC_AND:
			case EBPF_ATOMIC_AND | EBPF_ATOMIC_OP_FETCH: {

				break;
			}

			case EBPF_ATOMIC_OR:
			case EBPF_ATOMIC_OR | EBPF_ATOMIC_OP_FETCH: {

				break;
			}
			case EBPF_ATOMIC_XOR:
			case EBPF_ATOMIC_XOR | EBPF_ATOMIC_OP_FETCH: {

				break;
			}
			case EBPF_ATOMIC_OP_XCHG: {

				break;
			}
			case EBPF_ATOMIC_OP_CMPXCHG: {

				break;
			}
			default: {
				// return llvm::make_error<llvm::StringError>(
				// 	"Unsupported atomic operation: " +
				// 		std::to_string(inst.imm),
				// 	llvm::inconvertibleErrorCode());
			}
			}
			break;
		}
		default: {}
			// return llvm::make_error<llvm::StringError>(
			// 	"Unsupported or illegal opcode: " +
			// 		std::to_string(inst.code) +
			// 		" at pc " + std::to_string(pc),
			// 	llvm::inconvertibleErrorCode());
		}
    }

    // Handle branching for blocks

    // Verify generated module

    // emit / store

}
