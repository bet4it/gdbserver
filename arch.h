#ifndef ARCH_H
#define ARCH_H

#include <stdint.h>

struct reg_struct
{
    int idx;
    int size;
};

#define ARCH_REG_NUM (sizeof(regs_map) / sizeof(struct reg_struct))

#ifdef __i386__

#include <sys/reg.h>

#define SZ 4
#define FEATURE_STR "l<target version=\"1.0\"><architecture>i386</architecture></target>"
static uint8_t break_instr[] = {0xcc};

#define PC EIP
#define EXTRA_NUM 41
#define EXTRA_REG ORIG_EAX
#define EXTRA_SIZE 4

typedef struct user_regs_struct regs_struct;

// gdb/features/i386/32bit-core.c
struct reg_struct regs_map[] = {
    {EAX, 4},
    {ECX, 4},
    {EDX, 4},
    {EBX, 4},
    {UESP, 4},
    {EBP, 4},
    {ESI, 4},
    {EDI, 4},
    {EIP, 4},
    {EFL, 4},
    {CS, 4},
    {SS, 4},
    {DS, 4},
    {ES, 4},
    {FS, 4},
    {GS, 4},
};

#endif /* __i386__ */

#ifdef __x86_64__

#include <sys/reg.h>

#define SZ 8
#define FEATURE_STR "l<target version=\"1.0\"><architecture>i386:x86-64</architecture></target>"
static uint8_t break_instr[] = {0xcc};

#define PC RIP
#define EXTRA_NUM 57
#define EXTRA_REG ORIG_RAX
#define EXTRA_SIZE 8

typedef struct user_regs_struct regs_struct;

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

#endif /* __x86_64__ */

#ifdef __arm__

#define SZ 4
#define FEATURE_STR "l<target version=\"1.0\"><architecture>arm</architecture></target>"

static uint8_t break_instr[] = {0xf0, 0x01, 0xf0, 0xe7};

#define PC 15
#define EXTRA_NUM 25
#define EXTRA_REG 16
#define EXTRA_SIZE 4

typedef struct user_regs regs_struct;

struct reg_struct regs_map[] = {
    {0, 4},
    {1, 4},
    {2, 4},
    {3, 4},
    {4, 4},
    {5, 4},
    {6, 4},
    {7, 4},
    {8, 4},
    {9, 4},
    {10, 4},
    {11, 4},
    {12, 4},
    {13, 4},
    {14, 4},
    {15, 4},
};

#endif /* __arm__ */

#endif /* ARCH_H */
