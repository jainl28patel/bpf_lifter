# bpf_lifter
eBPF bytecode to LLVM IR Lifter

* Some of lifting logic and approach is refered from https://github.com/eunomia-bpf/llvmbpf


## TODO

- [x] Add boilerplate structure
- [x] Add ELFIO for elf parsing
- [x] Add logic for basic blocks in program, start and end blocks
- [x] Add lifting for each type of bpf instruction
- [x] Add script to get required information as csv for helper functions
- [x] Dump the generated IR code
- [ ] Add preprocessing for helper function and add at the top of generated IR
- [ ] Add support for ebpf map details in IR
- [ ] Handle addition of section name with maps, function, symbols etc
- [ ] List other required things in the IR
- [ ] TODO: Think about llvm pass to support execution on [DRACO](https://github.com/jainl28patel/DRACO-verifier)
