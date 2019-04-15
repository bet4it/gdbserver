#ifndef ARCH_H
#define ARCH_H

#include <stdint.h>
#include <sys/reg.h>

static uint8_t break_instr[] = {0xcc};

struct reg_struct
{
    int idx;
    int size;
};

// gdb/features/i386/64bit-core.c
struct reg_struct regs_map[] = {
    {RAX, 8},
    {RBX, 8},
    {RCX, 8},
    {RDX, 8},
    {RSI, 8},
    {RDI, 8},
    {RBP, 8},
    {RSP, 8},
    {R8, 8},
    {R9, 8},
    {R10, 8},
    {R11, 8},
    {R12, 8},
    {R13, 8},
    {R14, 8},
    {R15, 8},
    {RIP, 8},
    {EFLAGS, 4},
    {CS, 4},
    {SS, 4},
    {DS, 4},
    {ES, 4},
    {FS, 4},
    {GS, 4},
};

#define ARCH_REG_NUM (sizeof(regs_map) / sizeof(struct reg_struct))

#endif /* ARCH_H */
