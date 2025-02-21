#pragma once

#include <bpf_extern.h>
#include <bpf_instr.h>

bool is_control_flow_split(bpf_insn& instruction);
bool isValidBPFInstruction(bpf_insn& instruction);