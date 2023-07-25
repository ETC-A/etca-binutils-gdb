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

#include <stdint.h>

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

#define MK_ETCA_CPI(cp1, cp2, feat) ((struct etca_cpuid){(cp1), (cp2), (feat)})
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

struct etca_extension {
    const char *name;
    enum etca_ext_index index;
    /* The CPU ID bit for this extension. This is not a cpuid_pattern! */
    struct etca_cpuid cpi;
};

#define CLASS_WIDTH 2

enum etca_register_class {
    /* Not a register. */
    RegClassNone,
    /* A general-purpose register. */
    Reg,
    /* A control register. */
    CReg
// no enum case for things like the instruction pointer;
// references to the instruction pointer are handled in
// etca_mem_arg.
};

// This enum generates bit indices into the etca_arg_type bitfield.
enum {
    Class = CLASS_WIDTH - 1,
    /* A 5-bit immediate in base or exop formats. */
    Imm5,
    /* An 8-bit immediate in the `int` instruction format, and by the i8
    FI/MO2 instruction templates. One of the sign attributes below will be
    marked whenever this is present. */
    Imm8,
    /* An unqualified immediate. Used by FI/MO2 instruction templates.
    To validate the size of an immediate, you need to also retrieve
    the signedness, and obtain an operand size attribute. That size attribute
    might come from an instruction being assembled, or from an instruction
    being disassembled. */
    ImmAny,
    /* The immediate (described above) is unsigned. */
    ImmZ,
    /* The immediate (described above) is signed. */
    ImmS,
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
}

/* A single operand to an ETCa instruction. Operands can be types of registers,
  immediates, displacements, or memory references. Some instructions have
  implicit operands (like push and pop). Those operands must be representable
  by this struct.

  We use the term "arg" in place of "operand" to prevent confusion with
  "opcode" and "operation" in abbreviations. */
struct etca_arg {

}

enum etca_iformat {
    ETCA_IF_ILLEGAL = 0x0001,   /* An illegal/unknown instruction, which we can't further decode */
    ETCA_IF_BASE_RR = 0x0002,   /* 00 SS CCCC 	RRR RRR 00 */
    ETCA_IF_BASE_RI = 0x0004,   /* 01 SS CCCC 	RRR IIIII */
    ETCA_IF_BASE_JMP = 0x0008,  /* 100 D CCCC 	DDDDDDDD */
    ETCA_IF_SPECIAL = 0x0010,   /* Some other encoding. Specialized logic is required*/
};

struct etca_opc_info {
    const char *name;
    enum etca_iformat format;
    uint16_t opcode; /* Exact meaning depends on format */
    struct etca_cpuid requirements;
};

extern const char etca_register_saf_names[16][3];

extern const struct etca_extension etca_extensions[ETCA_EXTCOUNT];

/* The various groups of etca instructions. They are seperated into different tables to make decoding easier. */
extern const struct etca_opc_info etca_base_rr[];
extern const struct etca_opc_info etca_base_ri[];
extern const struct etca_opc_info etca_base_jmp[];


#endif /* _ETCA_H_ */
