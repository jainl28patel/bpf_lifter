#include <elf_utils.h>

// Function to convert string to ELFSection enum
ELFSection StringToELFSection(const std::string& sectionName) {
    auto it = stringToEnumMap.find(sectionName);
    if (it != stringToEnumMap.end()) {
        return it->second;
    }
    return ELFSection::UNKNOWN; // Return UNKNOWN if not found
}

// Function to convert ELFSection enum to string
std::string ELFSectionToString(ELFSection section) {
    switch (section) {
        // eBPF-Specific Code Sections
        case ELFSection::TEXT: return ".text";
        case ELFSection::MAPS: return ".maps";
        case ELFSection::BSS: return ".bss";
        case ELFSection::DATA: return ".data";
        case ELFSection::RODATA: return ".rodata";
        case ELFSection::KPROBE: return ".kprobe";
        case ELFSection::KRETPROBE: return ".kretprobe";
        case ELFSection::UPROBE: return ".uprobe";
        case ELFSection::URETPROBE: return ".uretprobe";
        case ELFSection::TRACEPOINT: return ".tracepoint";
        case ELFSection::RAW_TRACEPOINT: return ".raw_tracepoint";
        case ELFSection::TP_BTF: return ".tp_btf";
        case ELFSection::FENTRY: return ".fentry";
        case ELFSection::FEXIT: return ".fexit";
        case ELFSection::STRUCT_OPS: return ".struct_ops";
        case ELFSection::SK_MSG: return ".sk_msg";
        case ELFSection::SK_REUSEPORT: return ".sk_reuseport";
        case ELFSection::SOCKOPS: return ".sockops";
        case ELFSection::XDP: return "xdp";
        case ELFSection::TC: return "tc";
        case ELFSection::LWT_IN: return ".lwt_in";
        case ELFSection::LWT_OUT: return ".lwt_out";
        case ELFSection::LWT_XMIT: return ".lwt_xmit";
        case ELFSection::LWT_SEG6LOCAL: return ".lwt_seg6local";
        case ELFSection::CGROUP_SKB: return ".cgroup/skb";
        case ELFSection::CGROUP_SOCK: return ".cgroup/sock";
        case ELFSection::CGROUP_DEV: return ".cgroup/dev";
        case ELFSection::CGROUP_BIND4: return ".cgroup/bind4";
        case ELFSection::CGROUP_BIND6: return ".cgroup/bind6";
        case ELFSection::LSM: return ".lsm";

        // Relocation and Symbol Sections
        case ELFSection::REL_TEXT: return ".rel.text";
        case ELFSection::REL_RODATA: return ".rel.rodata";
        case ELFSection::SYMTAB: return ".symtab";
        case ELFSection::STRTAB: return ".strtab";
        case ELFSection::BTF: return ".BTF";
        case ELFSection::BTF_EXT: return ".BTF.ext";

        // Debugging and Metadata Sections
        case ELFSection::DEBUG_INFO: return ".debug_info";
        case ELFSection::DEBUG_ABBREV: return ".debug_abbrev";
        case ELFSection::DEBUG_LINE: return ".debug_line";
        case ELFSection::DEBUG_STR: return ".debug_str";
        case ELFSection::LLVM_ADDRSIG: return ".llvm_addrsig";

        // Other Sections
        case ELFSection::NOTE_GNU_BUILD_ID: return ".note.gnu.build-id";
        case ELFSection::EH_FRAME: return ".eh_frame";
        case ELFSection::COMMENT: return ".comment";

        default: return "UNKNOWN";
    }
}
