#pragma once

#include <unistd.h>

extern "C" {
    struct bpf_object;
    struct bpf_program;
    struct bpf_insn;
    void bpf_object__close(bpf_object *obj);
    bpf_program *bpf_object__next_program(const bpf_object *obj, bpf_program *prog);
    const char *bpf_program__name(const bpf_program *prog);
    const char * bpf_program__section_name (const struct bpf_program *prog);
    bpf_object *bpf_object__open(const char *path);
    const bpf_insn *bpf_program__insns(const bpf_program *prog);
    size_t bpf_program__insn_cnt(const bpf_program *prog);


    #define bpf_object__for_each_program(pos, obj)			\
        for ((pos) = bpf_object__next_program((obj), NULL);	\
            (pos) != NULL;					\
            (pos) = bpf_object__next_program((obj), (pos)))
}