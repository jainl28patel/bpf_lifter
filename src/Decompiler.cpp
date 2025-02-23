#include <Decompiler.h>

Decompiler::Decompiler(std::string& out_file)
    : out_file(out_file)
{
	// load helper function definitions
	std::ifstream csv("/home/jainil/Draco/bpf_lifter/scripts/bpf_function_data.csv");
	std::string line;
	while(std::getline(csv, line)) {
		helper_func_def data;
		int l = 0,r;
		r = line.find(',',l);
		data.func_ptr = std::stoi(line.substr(l,r));

		l=r;
		r = line.find(',',l);
		data.ret_type = line.substr(l,r);

		l=r;
		r = line.find(',',l);
		data.func_name = line.substr(l,r);

		l=r;
		r = line.find(',',l);
		data.num_args = std::stoi(line.substr(l,r));

		this->helper_func_metadata[data.func_ptr] = data;
	}

	csv.close();
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
    // TODO: Handle for Maps and helper funct etc
    // .relxdp contains info for file desc patching of maps
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
            std::cout << static_cast<int>(instr->code) << std::endl;
            instr++;
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
	Value *callStack, *callItemCnt;
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
		// Create stack
		auto stackBegin = builder.CreateAlloca(
			builder.getInt64Ty(),
			builder.getInt32(STACK_SIZE * MAX_LOCAL_FUNC_DEPTH +
					 10),
			"stackBegin");
		auto stackEnd = builder.CreateGEP(
			builder.getInt64Ty(), stackBegin,
			{ builder.getInt32(STACK_SIZE * MAX_LOCAL_FUNC_DEPTH) },
			"stackEnd");
		// Write stack pointer into r10
		builder.CreateStore(stackEnd, regs[10]);
		// Write memory address into r1
		builder.CreateStore(mem, regs[1]);
		// Write memory len into r1
		builder.CreateStore(mem_len, regs[2]);

		callStack = builder.CreateAlloca(
			llvm::PointerType::get(builder.getContext(), 0),
			builder.getInt32(CALL_STACK_SIZE * 5), "callStack");
		callItemCnt = builder.CreateAlloca(builder.getInt64Ty(),
						   nullptr, "callItemCnt");
		builder.CreateStore(builder.getInt64(0), callItemCnt);
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
    // Basic block used to exit the eBPF program
	// will read r0 and return it
	BasicBlock *exitBlk = BasicBlock::Create(*context, "exitBlock", bpf_func);
	{
		IRBuilder<> builder(exitBlk);
		builder.CreateRet(
			builder.CreateLoad(builder.getInt64Ty(), regs[0]));
	}


	// Defining different helper function types
	FunctionType *helper_func_0 = FunctionType::get(
		Type::getInt64Ty(*context),
		{},
		false
	);
	
	FunctionType *helper_func_1 = FunctionType::get(
		Type::getInt64Ty(*context),
		{Type::getInt64Ty(*context)},
		false
	);

	FunctionType *helper_func_2 = FunctionType::get(
		Type::getInt64Ty(*context),
		{Type::getInt64Ty(*context),Type::getInt64Ty(*context)},
		false
	);

	FunctionType *helper_func_3 = FunctionType::get(
		Type::getInt64Ty(*context),
		{Type::getInt64Ty(*context),Type::getInt64Ty(*context),
		 	Type::getInt64Ty(*context)},
		false
	);

	FunctionType *helper_func_4 = FunctionType::get(
		Type::getInt64Ty(*context),
		{Type::getInt64Ty(*context),Type::getInt64Ty(*context),
			Type::getInt64Ty(*context),Type::getInt64Ty(*context)},
		false
	);

	FunctionType *helper_func_5 = FunctionType::get(
		Type::getInt64Ty(*context),
		{Type::getInt64Ty(*context),Type::getInt64Ty(*context),
			Type::getInt64Ty(*context),Type::getInt64Ty(*context),
			Type::getInt64Ty(*context)},
		false
	);

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
            emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateSub(dst_val,
								 src_val);
				});
			break;
		}
		case EBPF_OP_MUL64_IMM:
		case EBPF_OP_MUL_IMM:
		case EBPF_OP_MUL64_REG:
		case EBPF_OP_MUL_REG: {
            emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateBinOp(
						Instruction::BinaryOps::Mul,
						dst_val, src_val);
				});
			break;
		}
		case EBPF_OP_DIV64_IMM:
		case EBPF_OP_DIV_IMM:
		case EBPF_OP_DIV64_REG:
		case EBPF_OP_DIV_REG: {
			// Set dst to zero if trying to being divided by
			// zero

            emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					bool is64 = (inst.code & 0x07) ==
						    EBPF_CLS_ALU64;
					auto result = builder.CreateSelect(
						builder.CreateICmpEQ(
							src_val,
							is64 ? builder.getInt64(
								       0) :
							       builder.getInt32(
								       0)),
						is_alu64(inst) ?
							builder.getInt64(0) :
							builder.getInt32(0),
						builder.CreateUDiv(dst_val,
								   src_val));
					return result;
				});

			;
			break;
		}
		case EBPF_OP_OR64_IMM:
		case EBPF_OP_OR_IMM:
		case EBPF_OP_OR64_REG:
		case EBPF_OP_OR_REG: {
            emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateOr(dst_val,
								src_val);
				});
			break;
		}
		case EBPF_OP_AND64_IMM:
		case EBPF_OP_AND_IMM:
		case EBPF_OP_AND64_REG:
		case EBPF_OP_AND_REG: {
            emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateAnd(dst_val,
								 src_val);
				});
			break;
		}
		case EBPF_OP_LSH64_IMM:
		case EBPF_OP_LSH_IMM:
		case EBPF_OP_LSH64_REG:
		case EBPF_OP_LSH_REG: {
            emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateShl(
						dst_val,
						is_alu64(inst) ?
							builder.CreateURem(
								src_val,
								builder.getInt64(
									64)) :
							builder.CreateURem(
								src_val,
								builder.getInt32(
									32)));
				});
			break;
		}
		case EBPF_OP_RSH64_IMM:
		case EBPF_OP_RSH_IMM:
		case EBPF_OP_RSH64_REG:
		case EBPF_OP_RSH_REG: {
            emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateLShr(
						dst_val,
						is_alu64(inst) ?
							builder.CreateURem(
								src_val,
								builder.getInt64(
									64)) :
							builder.CreateURem(
								src_val,
								builder.getInt32(
									32)));
				});
			break;
		}
		case EBPF_OP_NEG:
		case EBPF_OP_NEG64: {
            Value *dst_val =
				emitLoadALUDest(inst, &regs[0], builder, false);
			Value *result = builder.CreateNeg(dst_val);
			emitStoreALUResult(inst, &regs[0], builder, result);
			break;
		}
		case EBPF_OP_MOD64_IMM:
		case EBPF_OP_MOD_IMM:
		case EBPF_OP_MOD64_REG:
		case EBPF_OP_MOD_REG: {
            emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					// Keep dst untouched is src is
					// zero
					return builder.CreateSelect(
						builder.CreateICmpEQ(
							src_val,
							is_alu64(inst) ?
								builder.getInt64(
									0) :
								builder.getInt32(
									0)),
						dst_val,
						builder.CreateURem(dst_val,
								   src_val));
				});
			break;
		}
		case EBPF_OP_XOR64_IMM:
		case EBPF_OP_XOR_IMM:
		case EBPF_OP_XOR64_REG:
		case EBPF_OP_XOR_REG: {
            emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateXor(dst_val,
								 src_val);
				});
			break;
		}
		case EBPF_OP_MOV64_IMM:
		case EBPF_OP_MOV_IMM:
		case EBPF_OP_MOV64_REG:
		case EBPF_OP_MOV_REG: {
            Value *src_val =
				emitLoadALUSource(inst, &regs[0], builder);
			Value *result = src_val;
			emitStoreALUResult(inst, &regs[0], builder, result);
			break;
		}
		case EBPF_OP_ARSH64_IMM:
		case EBPF_OP_ARSH_IMM:
		case EBPF_OP_ARSH64_REG:
		case EBPF_OP_ARSH_REG: {
            emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateAShr(
						dst_val,
						is_alu64(inst) ?
							builder.CreateURem(
								src_val,
								builder.getInt64(
									64)) :
							builder.CreateURem(
								src_val,
								builder.getInt32(
									32)));
				});
			break;
		}
		case EBPF_OP_LE:
		case EBPF_OP_BE: {
            Value *dst_val =
				emitLoadALUDest(inst, &regs[0], builder, true);
			Value *result;
			if (auto exp = emitALUEndianConversion(inst, builder,
							       dst_val);
			    exp) {
				result = exp.get();
			} else {
                // TODO: Handle error
				// return exp.takeError();
			}
			emitStoreALUResult(inst, &regs[0], builder, result);
			break;
		}

			// ST and STX
			//  Only supports mode = 0x60
		case EBPF_OP_STB:
		case EBPF_OP_STXB: {
            emitStore(inst, builder, &regs[0], builder.getInt8Ty());
			break;
		}
		case EBPF_OP_STH:
		case EBPF_OP_STXH: {
            emitStore(inst, builder, &regs[0], builder.getInt16Ty());
			break;
		}
		case EBPF_OP_STW:
		case EBPF_OP_STXW: {
            emitStore(inst, builder, &regs[0], builder.getInt32Ty());
			break;
		}
		case EBPF_OP_STDW:
		case EBPF_OP_STXDW: {
            emitStore(inst, builder, &regs[0], builder.getInt64Ty());
			break;
		}
			// LDX
			// Only supports mode=0x60
		case EBPF_OP_LDXB: {
            emitLoadX(builder, &regs[0], inst, builder.getInt8Ty());
			break;
		}
		case EBPF_OP_LDXH: {
            emitLoadX(builder, &regs[0], inst, builder.getInt16Ty());
			break;
		}
		case EBPF_OP_LDXW: {
            emitLoadX(builder, &regs[0], inst, builder.getInt32Ty());
			break;
		}
		case EBPF_OP_LDXDW: {
            emitLoadX(builder, &regs[0], inst, builder.getInt64Ty());
			break;
		}
		// LD
		// Keep compatiblity to ubpf
		case EBPF_OP_LDDW: {
			// ubpf only supports EBPF_OP_LDDW in instruction class
			// EBPF_CLS_LD, so do us
            // TODO: Implement this part
            auto size = inst.code & 0x18;
            auto mode = inst.code & 0xe0;
            if (size != 0x18 || mode != 0x00) {
				throw llvm::make_error<llvm::StringError>(
					"Unsupported size (" +
						std::to_string(size) +
						") or mode (" +
						std::to_string(mode) +
						") for non-standard load operations" +
						" at pc " + std::to_string(pc),
					llvm::inconvertibleErrorCode());
			}
            if (pc + 1 >= instructions.size()) {
				throw llvm::make_error<llvm::StringError>(
					"Loaded LDDW at pc=" +
						std::to_string(pc) +
						" which requires an extra pseudo instruction, but it's the last instruction",
					llvm::inconvertibleErrorCode());
			}
            const auto &nextinst = instructions[pc + 1];
			if (nextinst.code || nextinst.dst_reg || nextinst.src_reg ||
			    nextinst.off) {
				throw llvm::make_error<llvm::StringError>(
					"Loaded LDDW at pc=" +
						std::to_string(pc) +
						" which requires an extra pseudo instruction, but the next instruction is not a legal one",
					llvm::inconvertibleErrorCode());
			}
            uint64_t val =
				(uint64_t)((uint32_t)inst.imm) |
				(((uint64_t)((uint32_t)nextinst.imm)) << 32);
			pc++;

			// For now only implement for test program which has immediate value to load (xdp_reader)
            if (inst.src_reg== 0) {
				builder.CreateStore(builder.getInt64(val),
						    regs[inst.dst_reg]);
			} 
			// else if (inst.src_reg= 1) {
			// 	if (vm.map_by_fd) {
			// 		builder.CreateStore(
			// 			builder.getInt64(
			// 				vm.map_by_fd(inst.imm)),
			// 			regs[inst.dst_reg]);
			// 	} else {
			// 		// Default: input value
			// 		builder.CreateStore(
			// 			builder.getInt64(
			// 				(int64_t)inst.imm),
			// 			regs[inst.dst_reg]);
			// 	}

			// } else if (inst.src_reg == 2) {
			// 	uint64_t mapPtr;
			// 	if (vm.map_by_fd) {
			// 		mapPtr = vm.map_by_fd(inst.imm);
			// 	} else {
			// 		// Default: returns the input value
			// 		mapPtr = (uint64_t)inst.imm;
			// 	}
			// 	if (patch_map_val_at_compile_time) {
			// 		if (!vm.map_val) {
			// 			throw llvm::make_error<
			// 				llvm::StringError>(
			// 				"map_val is not provided, unable to compile at pc " +
			// 					std::to_string(
			// 						pc),
			// 				llvm::inconvertibleErrorCode());
			// 		}
			// 		builder.CreateStore(
			// 			builder.getInt64(
			// 				vm.map_val(mapPtr) +
			// 				nextinst.imm),
			// 			regs[inst.dst_reg]);
			// 	} else {
			// 		SPDLOG_DEBUG(
			// 			"map_val is required to be evaluated at runtime, emitting calling instructions");
			// 		if (auto itrMapVal = lddwHelper.find(
			// 			    LDDW_HELPER_MAP_VAL);
			// 		    itrMapVal != lddwHelper.end()) {
			// 			auto retMapVal = builder.CreateCall(
			// 				lddwHelperWithUint64,
			// 				itrMapVal->second,
			// 				{ builder.getInt64(
			// 					mapPtr) });
			// 			auto finalRet = builder.CreateAdd(
			// 				retMapVal,
			// 				builder.getInt64(
			// 					nextinst.imm));
			// 			builder.CreateStore(
			// 				finalRet,
			// 				regs[inst.dst_reg]);

			// 		} else {
			// 			throw llvm::make_error<
			// 				llvm::StringError>(
			// 				"Using lddw helper 2, which requires map_val to be defined at pc " +
			// 					std::to_string(
			// 						pc),
			// 				llvm::inconvertibleErrorCode());
			// 		}
			// 	}

			// } else if (inst.src_reg== 3) {
			// 	if (!vm.var_addr) {
			// 		throw llvm::make_error<
			// 			llvm::StringError>(
			// 			"var_addr is not provided, unable to compile at pc " +
			// 				std::to_string(pc),
			// 			llvm::inconvertibleErrorCode());
			// 	}
			// 	builder.CreateStore(
			// 		builder.getInt64(vm.var_addr(inst.imm)),
			// 		regs[inst.dst_reg]);
			// } else if (inst.src_reg == 4) {
			// 	if (!vm.code_addr) {
			// 		throw llvm::make_error<
			// 			llvm::StringError>(
			// 			"code_addr is not provided, unable to compile at pc " +
			// 				std::to_string(pc),
			// 			llvm::inconvertibleErrorCode());
			// 	}
			// 	builder.CreateStore(
			// 		builder.getInt64(
			// 			vm.code_addr(inst.imm)),
			// 		regs[inst.dst_reg]);
			// } else if (inst.src_reg == 5) {
			// 	if (vm.map_by_idx) {
			// 		builder.CreateStore(
			// 			builder.getInt64(vm.map_by_idx(
			// 				inst.imm)),
			// 			regs[inst.dst_reg]);
			// 	} else {
			// 		// Default: returns the input value
			// 		builder.CreateStore(
			// 			builder.getInt64(
			// 				(int64_t)inst.imm),
			// 			regs[inst.dst_reg]);
			// 	}

			// } else if (inst.src_reg == 6) {
			// 	uint64_t mapPtr;
			// 	if (vm.map_by_idx) {
			// 		mapPtr = vm.map_by_idx(inst.imm);
			// 	} else {
			// 		// Default: returns the input value
			// 		mapPtr = (int64_t)inst.imm;
			// 	}
			// 	if (patch_map_val_at_compile_time) {
			// 		if (vm.map_val) {
			// 			builder.CreateStore(
			// 				builder.getInt64(
			// 					vm.map_val(
			// 						mapPtr) +
			// 					nextinst.imm),
			// 				regs[inst.dst_reg]);
			// 		} else {
			// 			throw llvm::make_error<
			// 				llvm::StringError>(
			// 				"map_val is not provided, unable to compile at pc " +
			// 					std::to_string(
			// 						pc),
			// 				llvm::inconvertibleErrorCode());
			// 		}

			// 	} else {
			// 		if (auto itrMapVal = lddwHelper.find(
			// 			    LDDW_HELPER_MAP_VAL);
			// 		    itrMapVal != lddwHelper.end()) {
			// 			auto retMapVal = builder.CreateCall(
			// 				lddwHelperWithUint64,
			// 				itrMapVal->second,
			// 				{ builder.getInt64(
			// 					mapPtr) });
			// 			auto finalRet = builder.CreateAdd(
			// 				retMapVal,
			// 				builder.getInt64(
			// 					nextinst.imm));
			// 			builder.CreateStore(
			// 				finalRet,
			// 				regs[inst.dst_reg]);

			// 		} else {
			// 			throw llvm::make_error<
			// 				llvm::StringError>(
			// 				"Using lddw helper 6 at pc " +
			// 					std::to_string(
			// 						pc),
			// 				llvm::inconvertibleErrorCode());
			// 		}
			// 	}
			// }

			break;
		}
			// JMP
		case EBPF_OP_JA: {
            if (auto dst = loadJmpDstBlock(pc, inst, instBlocks);
			    dst) {
				builder.CreateBr(dst.get());
			} else {
                // TODO: Handler error
				throw dst.takeError();
			}
			break;
		}
			// Call helper or local function
		case EBPF_OP_CALL:
			// Work around for clang producing instructions
			// that we don't support
		case EBPF_OP_CALL | 0x8: {
			// Call local function
            // TODO: Implement
			if (inst.src_reg == 0x1) {
				Value *nextPos = builder.CreateAdd(
					builder.CreateLoad(builder.getInt64Ty(),
								callItemCnt),
					builder.getInt64(5));

				builder.CreateStore(nextPos, callItemCnt);
				// assert(localFuncRetBlock.contains(pc + 1));
				// Store returning address
				builder.CreateStore(
					localFuncRetBlock[pc + 1],
					builder.CreateGEP(
						llvm::PointerType::get(builder.getContext(), 0), callStack,
						{ builder.CreateSub(
							nextPos,
							builder.getInt64(1)) }));
				// Store callee-saved registers
				for (int i = 6; i <= 9; i++) {
					builder.CreateStore(
						builder.CreateLoad(
							builder.getInt64Ty(),
							regs[i]),
						builder.CreateGEP(
							builder.getInt64Ty(),
							callStack,
							{ builder.CreateSub(
								nextPos,
								builder.getInt64(
									i -
									4)) }));
				}

				// Move data stack
				// r10 -= stackSize
				builder.CreateStore(
					builder.CreateSub(
						builder.CreateLoad(
							builder.getInt64Ty(),
							regs[10]),
						builder.getInt64(STACK_SIZE)),
					regs[10]);
				if (auto dstBlk = loadCallDstBlock(pc, inst,
									instBlocks);
					dstBlk) {
					builder.CreateBr(dstBlk.get());
				} else {
					throw dstBlk.takeError();
				}
			} else {
				// TODO: Implement external function call [Important]
				if(this->helper_func_metadata.find(inst.imm) == this->helper_func_metadata.end()) {
					throw "No such helper function found for external call";
				}
				switch (this->helper_func_metadata[inst.imm].func_ptr)
				{
				case 0: {
					auto currFunc = Function::Create(helper_func_0,
						Function::ExternalLinkage,
						this->helper_func_metadata[inst.imm].func_name, jitModule.get());
					emitExtFuncCall( builder, inst, &regs[0], pc, exitBlk, helper_func_0, currFunc,{});
					break;
				}
				case 1: {
					auto currFunc = Function::Create(helper_func_1,
						Function::ExternalLinkage,
						this->helper_func_metadata[inst.imm].func_name, jitModule.get());
					emitExtFuncCall( builder, inst, &regs[0], pc, exitBlk, helper_func_1, currFunc,{
						builder.CreateLoad(builder.getInt64Ty(), regs[1])
					});
					break;
				}
				case 2: {
					auto currFunc = Function::Create(helper_func_2,
						Function::ExternalLinkage,
						this->helper_func_metadata[inst.imm].func_name, jitModule.get());
					emitExtFuncCall( builder, inst, &regs[0], pc, exitBlk, helper_func_2, currFunc,{
						builder.CreateLoad(builder.getInt64Ty(), regs[1]),
						builder.CreateLoad(builder.getInt64Ty(), regs[2])
					});
					break;
				}
				case 3: {
					auto currFunc = Function::Create(helper_func_3,
						Function::ExternalLinkage,
						this->helper_func_metadata[inst.imm].func_name, jitModule.get());
					emitExtFuncCall( builder, inst, &regs[0], pc, exitBlk, helper_func_3, currFunc,{
						builder.CreateLoad(builder.getInt64Ty(), regs[1]),
						builder.CreateLoad(builder.getInt64Ty(), regs[2]),
						builder.CreateLoad(builder.getInt64Ty(), regs[3])
					});
					break;
				}
				case 4: {
					auto currFunc = Function::Create(helper_func_4,
						Function::ExternalLinkage,
						this->helper_func_metadata[inst.imm].func_name, jitModule.get());
					emitExtFuncCall( builder, inst, &regs[0], pc, exitBlk, helper_func_4, currFunc,{
						builder.CreateLoad(builder.getInt64Ty(), regs[1]),
						builder.CreateLoad(builder.getInt64Ty(), regs[2]),
						builder.CreateLoad(builder.getInt64Ty(), regs[3]),
						builder.CreateLoad(builder.getInt64Ty(), regs[4])
					});
					break;
				}
				case 5: {
					auto currFunc = Function::Create(helper_func_5,
						Function::ExternalLinkage,
						this->helper_func_metadata[inst.imm].func_name, jitModule.get());
					emitExtFuncCall( builder, inst, &regs[0], pc, exitBlk, helper_func_5, currFunc,{
						builder.CreateLoad(builder.getInt64Ty(), regs[1]),
						builder.CreateLoad(builder.getInt64Ty(), regs[2]),
						builder.CreateLoad(builder.getInt64Ty(), regs[3]),
						builder.CreateLoad(builder.getInt64Ty(), regs[4]),
						builder.CreateLoad(builder.getInt64Ty(), regs[5])
					});
					break;
				}
				
				default:
					throw "Argument count is not valid for helper function";
					break;
				}
			}

			break;
		}
		case EBPF_OP_EXIT: {
            // TODO: Implement (based on our logic)
			break;
		}

        // TODO: Implement error handler
#define HANDLE_ERR(ret)                                                        \
    {                                                                      \
        if (!ret);                                                      \                               
    }
    

		case EBPF_OP_JEQ32_IMM:
		case EBPF_OP_JEQ_IMM:
		case EBPF_OP_JEQ32_REG:
		case EBPF_OP_JEQ_REG: {
            HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpEQ(dst, src);
				}));
			break;
		}

		case EBPF_OP_JGT32_IMM:
		case EBPF_OP_JGT_IMM:
		case EBPF_OP_JGT32_REG:
		case EBPF_OP_JGT_REG: {
            HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpUGT(dst, src);
				}));
			break;
		}
		case EBPF_OP_JGE32_IMM:
		case EBPF_OP_JGE_IMM:
		case EBPF_OP_JGE32_REG:
		case EBPF_OP_JGE_REG: {
            HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpUGE(dst, src);
				}));
			break;
		}
		case EBPF_OP_JSET32_IMM:
		case EBPF_OP_JSET_IMM:
		case EBPF_OP_JSET32_REG:
		case EBPF_OP_JSET_REG: {
            if (auto ret =
                    localJmpDstAndNextBlk(pc, inst, instBlocks);
                ret) {
                auto [dstBlk, nextBlk] = ret.get();
                auto [src, dst, zero] =
                    emitJmpLoadSrcAndDstAndZero(
                        inst, &regs[0], builder);
                builder.CreateCondBr(
                    builder.CreateICmpNE(
                        builder.CreateAnd(dst, src),
                        zero),
                    dstBlk, nextBlk);
            } else {
                // TODO
                // return ret.takeError();
            }
			break;
		}
		case EBPF_OP_JNE32_IMM:
		case EBPF_OP_JNE_IMM:
		case EBPF_OP_JNE32_REG:
		case EBPF_OP_JNE_REG: {
            HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpNE(dst, src);
				}));
			break;
		}
		case EBPF_OP_JSGT32_IMM:
		case EBPF_OP_JSGT_IMM:
		case EBPF_OP_JSGT32_REG:
		case EBPF_OP_JSGT_REG: {
            HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpSGT(dst, src);
				}));
			break;
		}
		case EBPF_OP_JSGE32_IMM:
		case EBPF_OP_JSGE_IMM:
		case EBPF_OP_JSGE32_REG:
		case EBPF_OP_JSGE_REG: {
            HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpSGE(dst, src);
				}));
			break;
		}
		case EBPF_OP_JLT32_IMM:
		case EBPF_OP_JLT_IMM:
		case EBPF_OP_JLT32_REG:
		case EBPF_OP_JLT_REG: {
            HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpULT(dst, src);
				}));
			break;
		}
		case EBPF_OP_JLE32_IMM:
		case EBPF_OP_JLE_IMM:
		case EBPF_OP_JLE32_REG:
		case EBPF_OP_JLE_REG: {
            HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpULE(dst, src);
				}));
			break;
		}
		case EBPF_OP_JSLT32_IMM:
		case EBPF_OP_JSLT_IMM:
		case EBPF_OP_JSLT32_REG:
		case EBPF_OP_JSLT_REG: {
            HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpSLT(dst, src);
				}));
			break;
		}
		case EBPF_OP_JSLE32_IMM:
		case EBPF_OP_JSLE_IMM:
		case EBPF_OP_JSLE32_REG:
		case EBPF_OP_JSLE_REG: {
            HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpSLE(dst, src);
				}));
			break;
		}
		case EBPF_ATOMIC_OPCODE_32:
		case EBPF_ATOMIC_OPCODE_64: {
			switch (inst.imm) {
			case EBPF_ATOMIC_ADD:
			case EBPF_ATOMIC_ADD | EBPF_ATOMIC_OP_FETCH: {
                emitAtomicBinOp(
					builder, &regs[0],
					llvm::AtomicRMWInst::BinOp::Add, inst,
					inst.code == EBPF_ATOMIC_OPCODE_64,
					(inst.imm & EBPF_ATOMIC_OP_FETCH) ==
						EBPF_ATOMIC_OP_FETCH);
				break;
			}

			case EBPF_ATOMIC_AND:
			case EBPF_ATOMIC_AND | EBPF_ATOMIC_OP_FETCH: {
                emitAtomicBinOp(
					builder, &regs[0],
					llvm::AtomicRMWInst::BinOp::And, inst,
					inst.code == EBPF_ATOMIC_OPCODE_64,
					(inst.imm & EBPF_ATOMIC_OP_FETCH) ==
						EBPF_ATOMIC_OP_FETCH);
				break;
			}

			case EBPF_ATOMIC_OR:
			case EBPF_ATOMIC_OR | EBPF_ATOMIC_OP_FETCH: {
                emitAtomicBinOp(
					builder, &regs[0],
					llvm::AtomicRMWInst::BinOp::Or, inst,
					inst.code == EBPF_ATOMIC_OPCODE_64,
					(inst.imm & EBPF_ATOMIC_OP_FETCH) ==
						EBPF_ATOMIC_OP_FETCH);
				break;
			}
			case EBPF_ATOMIC_XOR:
			case EBPF_ATOMIC_XOR | EBPF_ATOMIC_OP_FETCH: {
                emitAtomicBinOp(
					builder, &regs[0],
					llvm::AtomicRMWInst::BinOp::Xor, inst,
					inst.code == EBPF_ATOMIC_OPCODE_64,
					(inst.imm & EBPF_ATOMIC_OP_FETCH) ==
						EBPF_ATOMIC_OP_FETCH);
				break;
			}
			case EBPF_ATOMIC_OP_XCHG: {
                emitAtomicBinOp(
					builder, &regs[0],
					llvm::AtomicRMWInst::BinOp::Xchg, inst,
					inst.code == EBPF_ATOMIC_OPCODE_64,
					false);
				break;
			}
			case EBPF_ATOMIC_OP_CMPXCHG: {
                bool is64 =
					inst.code= EBPF_ATOMIC_OPCODE_64;
				auto vPtr = builder.CreateGEP(
					builder.getInt8Ty(),
					builder.CreateLoad(llvm::PointerType::get(builder.getContext(), 0),
							   regs[inst.dst_reg]),
					{ builder.getInt64(inst.off) });
				auto beforeVal = builder.CreateLoad(
					is64 ? builder.getInt64Ty() :
					       builder.getInt32Ty(),
					vPtr);
				builder.CreateAtomicCmpXchg(
					vPtr,
					builder.CreateLoad(
						is64 ? builder.getInt64Ty() :
						       builder.getInt32Ty(),
						regs[0]),
					builder.CreateLoad(
						is64 ? builder.getInt64Ty() :
						       builder.getInt32Ty(),
						regs[inst.src_reg]),
					MaybeAlign(0),
					AtomicOrdering::Monotonic,
					AtomicOrdering::Monotonic);
				builder.CreateStore(
					builder.CreateZExt(beforeVal,
							   builder.getInt64Ty()),
					regs[0]);
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
