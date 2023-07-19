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

struct etca_cpuid {
    uint64_t cpuid1;
    uint64_t cpuid2;
    uint64_t feat;
};

#define ETCA_CPI_BASE   ((struct etca_cpuid){0, 0, 0})

#define ETCA_CPI_FI     ((struct etca_cpuid){1<<0, 0, 0})
#define ETCA_CPI_SAF    ((struct etca_cpuid){1<<1, 0, 0})
#define ETCA_CPI_INT    ((struct etca_cpuid){1<<2, 0, 0})
#define ETCA_CPI_BYTE   ((struct etca_cpuid){1<<3, 0, 0})
#define ETCA_CPI_COND   ((struct etca_cpuid){1<<4, 0, 0})
#define ETCA_CPI_REX    ((struct etca_cpuid){1<<5, 0, 0})
#define ETCA_CPI_CI     ((struct etca_cpuid){1<<6, 0, 0})
#define ETCA_CPI_ASP    ((struct etca_cpuid){1<<7, 0, 0})

#define ETCA_CPI_MO2    ((struct etca_cpuid){1<<13, 0, 0})
#define ETCA_CPI_DW     ((struct etca_cpuid){1<<14, 0, 0})
#define ETCA_CPI_QW     ((struct etca_cpuid){1<<15, 0, 0})
#define ETCA_CPI_DWAS   ((struct etca_cpuid){1<<16, 0, 0})
#define ETCA_CPI_PG16   ((struct etca_cpuid){1<<17, 0, 0})
#define ETCA_CPI_PG32   ((struct etca_cpuid){1<<18, 0, 0})

#define ETCA_CPI_QWAS   ((struct etca_cpuid){1ull<<32, 0, 0})
#define ETCA_CPI_PG48   ((struct etca_cpuid){1ull<<33, 0, 0})
#define ETCA_CPI_PG57   ((struct etca_cpuid){1ull<<34, 0, 0})
#define ETCA_CPI_PG64   ((struct etca_cpuid){1ull<<35, 0, 0})


#define ETCA_CPI_EXOP     ((struct etca_cpuid){0, 1<<0, 0})
#define ETCA_CPI_MO1      ((struct etca_cpuid){0, 1<<1, 0})
#define ETCA_CPI_PM       ((struct etca_cpuid){0, 1<<2, 0})
#define ETCA_CPI_MD       ((struct etca_cpuid){0, 1<<3, 0})
#define ETCA_CPI_BM1      ((struct etca_cpuid){0, 1<<4, 0})

#define ETCA_CPI_VON    ((struct etca_cpuid){0, 0, 1<<0})
#define ETCA_CPI_UMA    ((struct etca_cpuid){0, 0, 1<<1})
#define ETCA_CPI_CC     ((struct etca_cpuid){0, 0, 1<<2})
#define ETCA_CPI_MMAI   ((struct etca_cpuid){0, 0, 1<<3})

struct etca_extension {
    const char *name;
    enum etca_ext_index index;
    struct etca_cpuid pattern;
};

enum etca_iformat {
    ETCA_IF_ILLEGAL = 0x0001,   /* An illegal/unknown instruction, which we can't further decode */
    ETCA_IF_BASE_RR = 0x0002,   /* 00 SS CCCC 	RRR RRR 00 */
    ETCA_IF_BASE_RI = 0x0004,   /* 01 SS CCCC 	RRR IIIII */
    ETCA_IF_BASE_JMP = 0x0008,  /* 10 0 D CCCC 	DDDDDDDD */
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
