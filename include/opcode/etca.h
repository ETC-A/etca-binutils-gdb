/* Definitions for decoding the ggx opcode table.
   Copyright 2023 Free Software Foundation, Inc.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
02110-1301, USA.  */
#ifndef _ETCA_H_
#define _ETCA_H_

#include "elf/etca.h"
#include <stdint.h>
#include <stdbool.h>

// The idea of these comes from i386.h and they are used in tc-i386.c.
// However, I'm not sold; they seem easy to forget about and therefore
// could easily lead to bugs due to improper maintanence in the future.
// We could instead make them global vars and initialize them in md_begin,
// in which case lookup_register_name_checked and any opcode-searching
// code would probably involve a variable-length array (hence can't be C89).
// Do we care about that?
// - 8/4/23 AbelianGrape

/* The length of the longest instruction name. */
#define MAX_MNEM_SIZE (sizeof("cache_invalidate_all") - 1)
/* The length of the longest register name. */
#define MAX_REG_NAME_SIZE (sizeof("cache_line_size") - 1)

enum etca_ext_index { /* This needs to match the order in the listing of instructions */
    ETCA_EXT_BASE, /* base isa */

    /* Start of CPUID1 */
    ETCA_EXT_FI,  /* Full immediate */
    ETCA_EXT_SAF, /* Stack And Functions */
    ETCA_EXT_INT, /* Interrupts */
    ETCA_EXT_BYTE, /* 8 Bit Operations + Registers */
    ETCA_EXT_COND, /* Conditional Execution */
    ETCA_EXT_REX, /* Expanded Registers */
    ETCA_EXT_CI, /* Cache Instructions */
    ETCA_EXT_ASP, /* Arbitrary Stack Pointer */

    ETCA_EXT_MO2, /* Memory Operands 2 */
    ETCA_EXT_DW, /* 32 Bit Operations + Registers */
    ETCA_EXT_QW, /* 64 Bit Operations + Registers */
    ETCA_EXT_DWAS, /* 32 Bit Address Space */
    ETCA_EXT_PG16, /* Virtual Memory + 16 Bit Paging (undefined) */
    ETCA_EXT_PG32, /* Virtual Memory + 32 Bit Paging (undefined) */
    ETCA_EXT_QWAS, /* 64 Bit Address Space */
    ETCA_EXT_PG48, /* Virtual Memory + 48 Bit Paging (undefined) */
    ETCA_EXT_PG57, /* Virtual Memory + 57 Bit Paging (undefined) */
    ETCA_EXT_PG64, /* Virtual Memory + 64 Bit Paging (undefined) */

    /* Start of CPUID2 */
    ETCA_EXT_EXOP, /* 	Expanded Opcodes */
    ETCA_EXT_MO1,  /* Memory Operands 1 */
    ETCA_EXT_PM,   /* Privileged Mode */
    ETCA_EXT_MD,   /* Multiply Divide */
    ETCA_EXT_BM1,  /* Bit Manipulation 1 */

    ETCA_FEAT_VON,  /* Von Neumann */
    ETCA_FEAT_UMA,  /* Unaligned Memory Access */
    ETCA_FEAT_CC,   /* Cache Coherency */
    ETCA_FEAT_MMAI, /* Multiple Memory Access Instructions */

    ETCA_EXTCOUNT
};

// For each extension, provide its CPUID1, CPUID2, and FEAT bits.
// The value should be 0 for the fields to which the extension does not belong.
// These are referred to generatively by other macros to make compound patterns.
#define ETCA_CP1_FI     (1ULL << 0)
#define ETCA_CP2_FI     0
#define ETCA_FT_FI      0
#define ETCA_CP1_SAF    (1ULL << 1)
#define ETCA_CP2_SAF    0
#define ETCA_FT_SAF     0
#define ETCA_CP1_INT    (1ULL << 2)
#define ETCA_CP2_INT    0
#define ETCA_FT_INT     0
#define ETCA_CP1_BYTE   (1ULL << 3)
#define ETCA_CP2_BYTE   0
#define ETCA_FT_BYTE    0
#define ETCA_CP1_COND   (1ULL << 4)
#define ETCA_CP2_COND   0
#define ETCA_FT_COND    0
#define ETCA_CP1_REX    (1ULL << 5)
#define ETCA_CP2_REX    0
#define ETCA_FT_REX     0
#define ETCA_CP1_CI     (1ULL << 6)
#define ETCA_CP2_CI     0
#define ETCA_FT_CI      0
#define ETCA_CP1_ASP    (1ULL << 7)
#define ETCA_CP2_ASP    0
#define ETCA_FT_ASP     0
#define ETCA_CP1_MO2    (1ULL << 13)
#define ETCA_CP2_MO2    0
#define ETCA_FT_MO2     0
#define ETCA_CP1_DW     (1ULL << 14)
#define ETCA_CP2_DW     0
#define ETCA_FT_DW      0
#define ETCA_CP1_QW     (1ULL << 15)
#define ETCA_CP2_QW     0
#define ETCA_FT_QW      0
#define ETCA_CP1_DWAS   (1ULL << 16)
#define ETCA_CP2_DWAS   0
#define ETCA_FT_DWAS    0
#define ETCA_CP1_PG16   (1ULL << 17)
#define ETCA_CP2_PG16   0
#define ETCA_FT_PG16    0
#define ETCA_CP1_PG32   (1ULL << 18)
#define ETCA_CP2_PG32   0
#define ETCA_FT_PG32    0
#define ETCA_CP1_QWAS   (1ULL << 32)
#define ETCA_CP2_QWAS   0
#define ETCA_FT_QWAS    0
#define ETCA_CP1_PG48   (1ULL << 33)
#define ETCA_CP2_PG48   0
#define ETCA_FT_PG48    0
#define ETCA_CP1_PG57   (1ULL << 34)
#define ETCA_CP2_PG57   0
#define ETCA_FT_PG57    0
#define ETCA_CP1_PG64   (1ULL << 35)
#define ETCA_CP2_PG64   0
#define ETCA_FT_PG64    0
#define ETCA_CP1_EXOP   0
#define ETCA_CP2_EXOP   (1ULL << 0)
#define ETCA_FT_EXOP    0
#define ETCA_CP1_MO1    0
#define ETCA_CP2_MO1    (1ULL << 1)
#define ETCA_FT_MO1     0
#define ETCA_CP1_PM     0
#define ETCA_CP2_PM     (1ULL << 2)
#define ETCA_FT_PM      0
#define ETCA_CP1_MD     0
#define ETCA_CP2_MD     (1ULL << 3)
#define ETCA_FT_MD      0
#define ETCA_CP1_BM1    0
#define ETCA_CP2_BM1    (1ULL << 4)
#define ETCA_FT_BM1     0
#define ETCA_CP1_VON    0
#define ETCA_CP2_VON    0
#define ETCA_FT_VON     (1ULL << 0)
#define ETCA_CP1_UMA    0
#define ETCA_CP2_UMA    0
#define ETCA_FT_UMA     (1ULL << 1)
#define ETCA_CP1_CC     0
#define ETCA_CP2_CC     0
#define ETCA_FT_CC      (1ULL << 2)
#define ETCA_CP1_MMAI   0
#define ETCA_CP2_MMAI   0
#define ETCA_FT_MMAI    (1ULL << 3)

struct etca_cpuid {
    uint64_t cpuid1;
    uint64_t cpuid2;
    uint64_t feat;
};

#define MK_ETCA_CPI(cp1, cp2, feat) {(cp1), (cp2), (feat)}
#define ETCA_CPI_OF_EXT(ext) MK_ETCA_CPI(ETCA_CP1_##ext, ETCA_CP2_##ext, ETCA_FT_##ext)

#define ETCA_CPI_BASE   MK_ETCA_CPI(0, 0, 0)

#define ETCA_CPI_FI     ETCA_CPI_OF_EXT(FI)
#define ETCA_CPI_SAF    ETCA_CPI_OF_EXT(SAF)
#define ETCA_CPI_INT    ETCA_CPI_OF_EXT(INT)
#define ETCA_CPI_BYTE   ETCA_CPI_OF_EXT(BYTE)
#define ETCA_CPI_COND   ETCA_CPI_OF_EXT(COND)
#define ETCA_CPI_REX    ETCA_CPI_OF_EXT(REX)
#define ETCA_CPI_CI     ETCA_CPI_OF_EXT(CI)
#define ETCA_CPI_ASP    ETCA_CPI_OF_EXT(ASP)

#define ETCA_CPI_MO2    ETCA_CPI_OF_EXT(MO2)
#define ETCA_CPI_DW     ETCA_CPI_OF_EXT(DW)
#define ETCA_CPI_QW     ETCA_CPI_OF_EXT(QW)
#define ETCA_CPI_DWAS   ETCA_CPI_OF_EXT(DWAS)
#define ETCA_CPI_PG16   ETCA_CPI_OF_EXT(PG16)
#define ETCA_CPI_PG32   ETCA_CPI_OF_EXT(PG32)

#define ETCA_CPI_QWAS   ETCA_CPI_OF_EXT(QWAS)
#define ETCA_CPI_PG48   ETCA_CPI_OF_EXT(PG48)
#define ETCA_CPI_PG57   ETCA_CPI_OF_EXT(PG57)
#define ETCA_CPI_PG64   ETCA_CPI_OF_EXT(PG64)

#define ETCA_CPI_EXOP   ETCA_CPI_OF_EXT(EXOP)
#define ETCA_CPI_MO1    ETCA_CPI_OF_EXT(MO1)
#define ETCA_CPI_PM     ETCA_CPI_OF_EXT(PM)
#define ETCA_CPI_MD     ETCA_CPI_OF_EXT(MD)
#define ETCA_CPI_BM1    ETCA_CPI_OF_EXT(BM1)

#define ETCA_CPI_VON    ETCA_CPI_OF_EXT(VON)
#define ETCA_CPI_UMA    ETCA_CPI_OF_EXT(UMA)
#define ETCA_CPI_CC     ETCA_CPI_OF_EXT(CC)
#define ETCA_CPI_MMAI   ETCA_CPI_OF_EXT(MMAI)

/* A CPUID pattern of extensions that are required for some purpose.
We can require either "all" or "any" of the extensions.
The pattern requiring all of no extensions always matches,
the pattern requiring any of no extensions always fails. */
struct etca_cpuid_pattern {
    /* 0 if we only need _any_ of the given extensions,
       nonzero if we need _all_ of them. */
    char match_all;
    /* An etca_cpuid bitpattern with possibly many bits set. */
    struct etca_cpuid pat;
};

#define ETCA_EXT_PAT2(ext1, ext2) MK_ETCA_CPI( \
    ETCA_CP1_##ext1 | ETCA_CP1_##ext2,        \
    ETCA_CP2_##ext1 | ETCA_CP2_##ext2,        \
    ETCA_FT_##ext1  | ETCA_FT_##ext2)

#define ETCA_EXT_PAT3(ext1, ext2, ext3) MK_ETCA_CPI( \
    ETCA_CP1_##ext1 | ETCA_CP1_##ext2 | ETCA_CP1_##ext3, \
    ETCA_CP2_##ext1 | ETCA_CP2_##ext2 | ETCA_CP2_##ext3, \
    ETCA_FT_##ext1  | ETCA_FT_##ext2  | ETCA_FT_##ext3)

#define ETCA_PAT(ext) ((struct etca_cpuid_pattern){1, ETCA_CPI_##ext})
#define ETCA_PAT_OR2(ext1, ext2) \
    ((struct etca_cpuid_pattern){0, ETCA_EXT_PAT2(ext1, ext2)})
#define ETCA_PAT_AND2(ext1, ext2) \
    ((struct etca_cpuid_pattern){1, ETCA_EXT_PAT2(ext1, ext2)})
#define ETCA_PAT_OR3(ext1, ext2, ext3) \
    ((struct etca_cpuid_pattern){0, ETCA_EXT_PAT3(ext1, ext2, ext3)})
#define ETCA_PAT_AND3(ext1, ext2, ext3) \
    ((struct etca_cpuid_pattern){1, ETCA_EXT_PAT3(ext1, ext2, ext3)})

/* Return 0 if the pattern does not match, 1 otherwise. */
extern unsigned
etca_match_cpuid_pattern(const struct etca_cpuid_pattern *pat, const struct etca_cpuid *cpuid);

struct etca_extension {
    const char *name;
    enum etca_ext_index index;
    /* The CPU ID bit for this extension. This is not a cpuid_pattern! */
    struct etca_cpuid cpi;
};

/* Any other operand-related #define configuration should go here as well. */
#define MAX_OPERANDS 2
#define CLASS_WIDTH 2

enum etca_register_class {
    /* Not a register. */
    RegClassNone,
    /* A general-purpose register. */
    GPR,
    /* A control register. */
    CTRL
// no enum case for things like the instruction pointer;
// references to the instruction pointer are handled in
// etca_mem_arg.
};

// This enum generates bit indices into the etca_arg_kind bitfield.
enum {
    Class = CLASS_WIDTH - 1,
    /* A 5-bit signed immediate. Note this is also a valid 8-bit etc. */
    Imm5S,
    /* A 5-bit unsigned immediate */
    Imm5Z,
    /* An 8-bit signed immediate */
    Imm8S,
    /* An 8-bit unsigned immediate */
    Imm8Z,
    /* An unqualified immediate. Used by FI/MO2 instruction formats.
    To validate the size of an immediate, you need to also retrieve
    the signedness, and obtain an operand size attribute. That size attribute
    might come from an instruction being assembled, or from an instruction
    being disassembled. */
    ImmAny,
    /* The value of this immediate is already known */
    ImmConcrete,
    /* An 8-bit displacement, used in MO1/MO2 formats. */
    Disp8,
    /* A 9-bit displacement in base jump formats. */
    Disp9,
    /* A 12-bit displacement in the saf call format. */
    Disp12,
    /* A pointer-width displacement. The actual width of this depends on the
    size of pointers on the target machine, hence, it can encode any
    displacement.
    TODO: Function that can be called to retrieve that value? */
    DispPtr,
    /* An unqualified displacement. Used by the exop jump format. For
    disassembly, you need the size attribute from the instruction.
    For assembly, any displacement is fine, but should be validated against
    the configured pointer width. */
    DispAny,
    /* A memory operand.
    If we have a memory operand with a displacement, then the appropriate
    displacement type bit will also be set. In the etca_arg, more information
    about the scale, base, index, and (potential) displacement will be present.
    */
    Memory
};

/* A bitfield used to represent arg kinds.

The kind of a register is just its class.
The kind of an immediate includes (at least one) size and a size.
The kind of a displacement includes (at least one) size.
The kind of a memory operand includes the 'memory' bit, and also 
the information about the displacement if there is one.

In the assembler, all sizes that are guaranteed to fit should be marked.
This means that a displacement of 300 should have `disp9,disp12,dispPtr,dispAny` all active.
Same goes for immediates.
*/
struct etca_arg_kind {
    unsigned int reg_class:CLASS_WIDTH;
    unsigned int imm5s:1;
    unsigned int imm5z:1;
    unsigned int imm8s:1;
    unsigned int imm8z:1;
    unsigned int immAny:1;
    unsigned int immConc:1;
    unsigned int disp8:1;
    unsigned int disp9:1;
    unsigned int disp12:1;
    unsigned int dispPtr:1;
    unsigned int dispAny:1;
    unsigned int memory:1;
    unsigned int nested_memory:1;
    unsigned int predec:1;
    unsigned int postinc:1;
};

/* Signed so that -1 can represent "no register." */
typedef signed char reg_num;

struct etca_reg_info {
    const char *name;
    reg_num reg_num;
    /* Split depending on 'class'.
     * For GPR, this is the size. Validity is handled by a custom REX check.
     * For CTRL, this is an indication of what extension makes it valid. */
    union {
        int8_t reg_size; /* standard: -1 none, 0 h, 1 x, 2 d, 3 q */
        int8_t exts; /* nonstandard:
           -1: something more complicated, and checking validity is custom.
            0: always valid
            1: introduced by INT
            2: introduced by CI
            3: introduced by PM
            If you add something here, the function that handles this is
            parse_register_name_checked in tc-etca.c.
        */
    } aux;
    enum etca_register_class class;
};

// This enum generates bit indices into the etca_params_kind bitfield.
enum {
    NULLARY,
    REG,
    MEM,
    IMM,
    REG_IMM,
    REG_REG,
    REG_MEM,
    MEM_REG,
    MEM_IMM,

    REG_CTRL,

    OTHER,
};

/* A bitfield used to represent a legal combinations of argument types
 * Not all combinations that can appear are listed here. Specifically
 * the `mov` pseduop is special cased so that stuff only needed by it
 * does not need to be considered here. This for example includes
 * ASP-style pre- and post-decrement and other nested memory locations
 */
struct etca_params_kind {
    uint16_t e: 1; // No Arguments (Empty)
    uint16_t r: 1; // Single Register
    uint16_t m: 1; // Single Memory
    uint16_t i: 1; // Single Immediate
    uint16_t ri: 1; // Register-Immediate (any size immediate)
    uint16_t rr: 1; // Register-Register
    uint16_t rm: 1; // Register-Memory
    uint16_t mr: 1; // Memory-Register
    uint16_t mi: 1; // Memory-Immediate

    uint16_t rc: 1; // register, Control reg

    uint16_t other: 1; // Other, used by the disassembler to select pseudo ops
};

enum etca_args_size {
    OPR = 1, // one operand
    ADR,     // one address (register)
    LBL,     // one label (that is, a non-concrete expression)
    OPR_OPR, // two operands
    OPR_ADR, // one operand, then one address
    OPR_ANY, // one operand, then something which is unchecked
             // for example a control register or immediate.
    // if NUM_ARGS_SIZES ever exceeds 32767, etca_opc_size_info
    // needs to become larger.
    NUM_ARGS_SIZES,
};

struct etca_opc_size_info {
    uint16_t args_size: 15;
    uint16_t suffix_allowed: 1; // can a size suffix follow the opcode?
};

/* The maximal length in bytes any legal instruction can ever reach */
#define MAX_INSTRUCTION_LENGTH 15

/* The maximal length in bytes any legal instruction can ever reach */
#define MAX_INSTRUCTION_LENGTH 15

/* The various instruction formats to be used to get a specific assembler or disassembler function */
// If you add a format, be sure to adjust the `format_assemblers` table in tc-etca.c.
enum etca_iformat {
    ETCA_IF_ILLEGAL,   /* An illegal/unknown instruction, which we can't further encode/decode */
    ETCA_IF_SPECIAL,   /* A pseudo instruction that takes over *before* argument pairing*/
    ETCA_IF_PSEUDO,    /* A pseudo instruction that takes over *after* argument pairing */
    ETCA_IF_BASE_ABM,  /* A base instruction with an RI or ABM byte, potentially with FI/MO1/MO2 */
    ETCA_IF_EXOP_ABM,  /* A exop instruction with an RI or ABM byte, potentially with FI/MO1/MO2 */
    ETCA_IF_BASE_JMP,  /* A base cond jump with a 9bit displacement */
    ETCA_IF_SAF_CALL,  /* A saf call with a 12-bit displacement */
    ETCA_IF_SAF_JMP,   /* A saf cond jump or call, with a register */
    ETCA_IF_SAF_STK,   /* A saf push/pop. Recovers %sp, then defers to BASE_ABM. */
    ETCA_IF_EXOP_JMP,  /* A exop jump (or SaF-EXOP call) with a 8/16/32/64 bit displacement */
    ETCA_IFORMAT_COUNT
};

struct etca_opc_info {
    const char *name;
    enum etca_iformat format;
    uint16_t opcode; /* Exact meaning depends on format */
    union etca_opc_params_field {
        struct etca_params_kind kinds;
        uint16_t uint;
    } params;
    struct etca_opc_size_info size_info;
    struct etca_cpuid_pattern requirements;
    char try_next_assembly; /* bool - will be set correctly during md_begin*/
};

/* An enumeration of pseudo names so that we don't accidentally create
    clashes in the table. */
// if you add pseudoinstruction formats, be sure to also add them to
// the pseudo_functions table in tc-etca.c.
enum etca_pseudo_opcode {
    ETCA_MOV,
    ETCA_PSEUDO_COUNT
};

#define ETCA_BASE_ABM_IMM_SIGNED(opcode) ((opcode) < 8 || (opcode) == 9)
#define ETCA_BASE_ABM_IMM_UNSIGNED(opcode) (!ETCA_BASE_ABM_IMM_SIGNED(opcode))

extern size_t etca_calc_mov_ri_byte_count(const struct etca_cpuid *, int8_t, reg_num, int64_t *);
extern enum elf_etca_reloc_type etca_build_mov_ri(const struct etca_cpuid *, int8_t, reg_num, int64_t *, char*);
extern void etca_build_nop(const struct etca_cpuid *, size_t, char *);

extern const struct etca_reg_info etca_registers[];

/* For convenience, we have an extra extensions name=NULL to mark the end of the list. */
extern const struct etca_extension etca_extensions[ETCA_EXTCOUNT + 1];

/* For convenience, we have an extra opcode with name=NULL  to mark the end of the list. */
extern struct etca_opc_info etca_opcodes[];

#endif /* _ETCA_H_ */
