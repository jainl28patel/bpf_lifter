#include <bpf_utils.h>
#include <linux/bpf.h>

bool is_control_flow_split(bpf_insn &instruction)
{
    // if any instruction of class jump
	return (instruction.code & 0x07) == EBPF_CLS_JMP ||
	       (instruction.code & 0x07) == EBPF_CLS_JMP32;
}

bool isValidBPFInstruction(bpf_insn &instruction)
{
    // check register range
	if(instruction.dst_reg > 10 || instruction.src_reg > 10) {
		return false;
	}

	return true;
}
