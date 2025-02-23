#pragma once

#include <functional>
#include <llvm/IR/Constants.h>
#include <llvm/Support/Alignment.h>
#include <llvm/Support/AtomicOrdering.h>
#include <llvm/ADT/APInt.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/Error.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/IRBuilder.h>

#include <map>
#include <tuple>
#include <utility>
#include <unordered_map>

#include <bpf_extern.h>
#include <bpf_instr.h>

using namespace llvm;

struct helper_func_def {
  int func_ptr;
  std::string ret_type;
  std::string func_name;
  int num_args;
};

bool is_control_flow_split(bpf_insn& instruction);
bool isValidBPFInstruction(bpf_insn& instruction);
bool is_alu64(const bpf_insn &insn);

// IR builder for instructions

/// Get the source representation of certain ALU operands
llvm::Value *emitLoadALUSource(const bpf_insn &inst, llvm::Value **regs,
    llvm::IRBuilder<> &builder);
llvm::Value *emitLoadALUDest(const bpf_insn &inst, llvm::Value **regs,
  llvm::IRBuilder<> &builder, bool dstAlways64);
void emitStoreALUResult(const bpf_insn &inst, llvm::Value **regs,
llvm::IRBuilder<> &builder, llvm::Value *result);
llvm::Expected<llvm::Value *>
emitALUEndianConversion(const bpf_insn &inst, llvm::IRBuilder<> &builder,
llvm::Value *dst_val);

void emitALUWithDstAndSrc(
const bpf_insn &inst, llvm::IRBuilder<> &builder, llvm::Value **regs,
std::function<llvm::Value *(llvm::Value *, llvm::Value *)> func);

llvm::Value *emitStoreLoadingSrc(const bpf_insn &inst,
  llvm::IRBuilder<> &builder,
  llvm::Value **regs);
void emitStoreWritingResult(const bpf_insn &inst, llvm::IRBuilder<> &builder,
 llvm::Value **regs, llvm::Value *result);

void emitStore(const bpf_insn &inst, llvm::IRBuilder<> &builder,
llvm::Value **regs, llvm::IntegerType *destTy);

std::tuple<llvm::Value *, llvm::Value *, llvm::Value *>
emitJmpLoadSrcAndDstAndZero(const bpf_insn &inst, llvm::Value **regs,
 llvm::IRBuilder<> &builder);

llvm::Expected<llvm::BasicBlock *>
loadJmpDstBlock(uint16_t pc, const bpf_insn &inst,
const std::map<uint16_t, llvm::BasicBlock *> &instBlocks);
llvm::Expected<llvm::BasicBlock *>
loadCallDstBlock(uint16_t pc, const bpf_insn &inst,
const std::map<uint16_t, llvm::BasicBlock *> &instBlocks);
llvm::Expected<llvm::BasicBlock *>
loadJmpNextBlock(uint16_t pc, const bpf_insn &inst,
const std::map<uint16_t, llvm::BasicBlock *> &instBlocks);
llvm::Expected<std::pair<llvm::BasicBlock *, llvm::BasicBlock *> >
localJmpDstAndNextBlk(uint16_t pc, const bpf_insn &inst,
const std::map<uint16_t, llvm::BasicBlock *> &instBlocks);
llvm::Value *emitLDXLoadingAddr(llvm::IRBuilder<> &builder, llvm::Value **regs,
 const bpf_insn &inst);
void emitLDXStoringResult(llvm::IRBuilder<> &builder, llvm::Value **regs,
const bpf_insn &inst, llvm::Value *result);
void emitLoadX(llvm::IRBuilder<> &builder, llvm::Value **regs,
const bpf_insn &inst, llvm::IntegerType *srcTy);

llvm::Expected<int> emitCondJmpWithDstAndSrc(
llvm::IRBuilder<> &builder, uint16_t pc, const bpf_insn &inst,
const std::map<uint16_t, llvm::BasicBlock *> &instBlocks,
llvm::Value **regs,
std::function<llvm::Value *(llvm::Value *, llvm::Value *)> func);

void
emitExtFuncCall(llvm::IRBuilder<> &builder, const bpf_insn &inst,
  llvm::Value **regs, uint16_t pc, llvm::BasicBlock *exitBlk,
  llvm::FunctionType *helperFuncTy, llvm::Value* currFunc,
  llvm::ArrayRef<llvm::Value *> Args);
void emitAtomicBinOp(llvm::IRBuilder<> &builder, llvm::Value **regs,
llvm::AtomicRMWInst::BinOp op, const bpf_insn &inst,
bool is64, bool is_fetch);