#pragma once

#include <string>
#include <unordered_map>
#include <elfio/elfio.hpp>

using namespace ELFIO;

struct SymbolDetails {
    Elf_Xword index;
    std::string name;
    Elf64_Addr value;
    Elf_Xword size;
    unsigned char bind;
    unsigned char type;
    Elf_Half section_index;
    unsigned char other;
};

enum class ELFSection {
    // eBPF-Specific Code Sections
    TEXT,
	MAPS,
	BSS,
	DATA,
	RODATA,
    KPROBE,
	KRETPROBE,
	UPROBE,
	URETPROBE,
    TRACEPOINT,
	RAW_TRACEPOINT,
	TP_BTF,
    FENTRY,
	FEXIT,
	STRUCT_OPS,
    SK_MSG,
	SK_REUSEPORT,
	SOCKOPS,
	XDP,
	TC,
    LWT_IN,
	LWT_OUT,
	LWT_XMIT,
	LWT_SEG6LOCAL,
    CGROUP_SKB,
	CGROUP_SOCK,
	CGROUP_DEV,
    CGROUP_BIND4,
	CGROUP_BIND6,
	LSM,

    // Relocation and Symbol Sections
    REL_TEXT,
	REL_RODATA,
	SYMTAB,
	STRTAB,
    BTF,
	BTF_EXT,

    // Debugging and Metadata Sections
    DEBUG_INFO,
	DEBUG_ABBREV,
	DEBUG_LINE,
    DEBUG_STR,
	LLVM_ADDRSIG,

    // Other Sections
    NOTE_GNU_BUILD_ID,
	EH_FRAME,
	COMMENT,

    UNKNOWN // Default case for unrecognized sections
};

// Map of section names to their corresponding enum values
const std::unordered_map<std::string, ELFSection> stringToEnumMap = {
    {".text", ELFSection::TEXT},
    {".maps", ELFSection::MAPS},
    {".bss", ELFSection::BSS},
    {".data", ELFSection::DATA},
    {".rodata", ELFSection::RODATA},
    {".kprobe", ELFSection::KPROBE},
    {".kretprobe", ELFSection::KRETPROBE},
    {".uprobe", ELFSection::UPROBE},
    {".uretprobe", ELFSection::URETPROBE},
    {".tracepoint", ELFSection::TRACEPOINT},
    {".raw_tracepoint", ELFSection::RAW_TRACEPOINT},
    {".tp_btf", ELFSection::TP_BTF},
    {".fentry", ELFSection::FENTRY},
    {".fexit", ELFSection::FEXIT},
    {".struct_ops", ELFSection::STRUCT_OPS},
    {".sk_msg", ELFSection::SK_MSG},
    {".sk_reuseport", ELFSection::SK_REUSEPORT},
    {".sockops", ELFSection::SOCKOPS},
    {"xdp", ELFSection::XDP},
    {"tc", ELFSection::TC},
    {".lwt_in", ELFSection::LWT_IN},
    {".lwt_out", ELFSection::LWT_OUT},
    {".lwt_xmit", ELFSection::LWT_XMIT},
    {".lwt_seg6local", ELFSection::LWT_SEG6LOCAL},
    {".cgroup/skb", ELFSection::CGROUP_SKB},
    {".cgroup/sock", ELFSection::CGROUP_SOCK},
    {".cgroup/dev", ELFSection::CGROUP_DEV},
    {".cgroup/bind4", ELFSection::CGROUP_BIND4},
    {".cgroup/bind6", ELFSection::CGROUP_BIND6},
    {".lsm", ELFSection::LSM},
    {".rel.text", ELFSection::REL_TEXT},
    {".rel.rodata", ELFSection::REL_RODATA},
    {".symtab", ELFSection::SYMTAB},
    {".strtab", ELFSection::STRTAB},
    {".BTF", ELFSection::BTF},
    {".BTF.ext", ELFSection::BTF_EXT},
    {".debug_info", ELFSection::DEBUG_INFO},
    {".debug_abbrev", ELFSection::DEBUG_ABBREV},
    {".debug_line", ELFSection::DEBUG_LINE},
    {".debug_str", ELFSection::DEBUG_STR},
    {".llvm_addrsig", ELFSection::LLVM_ADDRSIG},
    {".note.gnu.build-id", ELFSection::NOTE_GNU_BUILD_ID},
    {".eh_frame", ELFSection::EH_FRAME},
    {".comment", ELFSection::COMMENT}
};

// Function to convert string to ELFSection enum
ELFSection StringToELFSection(const std::string& sectionName);

// Function to convert ELFSection enum to string
std::string ELFSectionToString(ELFSection section);