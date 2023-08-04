
/* etca-opc.c -- Definitions for ETCa opcodes.
   Copyright 2023 Free Software Foundation, Inc.

   This file is part of the GNU opcodes library.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this file; see the file COPYING.  If not, write to the
   Free Software Foundation, 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "../include/opcode/etca.h"

#define EXTENSION(abbr) { #abbr ,  ETCA_EXT_ ## abbr , ETCA_CPI_ ## abbr }
#define FEATURE(abbr) { #abbr ,  ETCA_FEAT_ ## abbr , ETCA_CPI_ ## abbr }

const struct etca_extension etca_extensions[ETCA_EXTCOUNT + 1] = {
        EXTENSION(BASE),

        EXTENSION(FI),
        EXTENSION(SAF),
        EXTENSION(INT),
        EXTENSION(BYTE),
        EXTENSION(COND),
        EXTENSION(REX),
        EXTENSION(CI),
        EXTENSION(ASP),
        EXTENSION(MO2),
        EXTENSION(DW),
        EXTENSION(QW),
        EXTENSION(DWAS),
        EXTENSION(PG16),
        EXTENSION(PG32),
        EXTENSION(QWAS),
        EXTENSION(PG48),
        EXTENSION(PG57),
        EXTENSION(PG64),

        EXTENSION(EXOP),
        EXTENSION(MO1),
        EXTENSION(PM),
        EXTENSION(MD),
        EXTENSION(BM1),

        FEATURE(VON),
        FEATURE(UMA),
        FEATURE(CC),
        FEATURE(MMAI),
	{NULL}
};

#undef EXTENSION
#undef FEATURE

unsigned
etca_match_cpuid_pattern(const struct etca_cpuid_pattern *pat, const struct etca_cpuid *cpuid)
{
    if (pat->match_all) {
        return (pat->pat.cpuid1 == (pat->pat.cpuid1 & cpuid->cpuid1))
               && (pat->pat.cpuid2 == (pat->pat.cpuid2 & cpuid->cpuid2))
               && (pat->pat.feat   == (pat->pat.feat   & cpuid->feat));
    } else {
        return (pat->pat.cpuid1 & cpuid->cpuid1)
               || (pat->pat.cpuid2 & cpuid->cpuid2)
               || (pat->pat.feat   & cpuid->feat);
    }
}

const char etca_register_saf_names[16][3] = {
    "a0", "a1", "a2",
    "s0", "s1",
    "bp", "sp", "ln",
    "t0", "t1", "t2", "t3", "t4",
    "s2", "s3", "s4",
};

#define PARAMS1(a) ((union etca_opc_params_field) {.uint = (1 << a)})
#define PARAMS2(a,b) ((union etca_opc_params_field) {.uint = (1 << a)|(1 << b)})
#define PARAMS3(a,b,c) ((union etca_opc_params_field) {.uint = (1 << a)|(1 << b)|(1 << c)})
#define PARAMS4(a,b,c,d) ((union etca_opc_params_field) {.uint = (1 << a)|(1 << b)|(1 << c)|(1 << d)})
#define PARAMS5(a,b,c,d,e) ((union etca_opc_params_field) {.uint = (1 << a)|(1 << b)|(1 << c)|(1 << d)|(1<<e)})

#define ANY_ABM PARAMS5(REG_IMM, REG_REG, REG_MEM, MEM_REG, MEM_IMM)

struct etca_opc_info etca_opcodes[] = {
        /* name, iformat, opcode, params, requirements, try_next*/
        {"add",    ETCA_IF_BASE_ABM, 0, ANY_ABM, ETCA_PAT(BASE), 0},
        {"sub",    ETCA_IF_BASE_ABM, 1, ANY_ABM, ETCA_PAT(BASE), 0},
        {"rsub",   ETCA_IF_BASE_ABM, 2, ANY_ABM, ETCA_PAT(BASE), 0},
        {"comp",   ETCA_IF_BASE_ABM, 3, ANY_ABM, ETCA_PAT(BASE), 0},
        {"or",     ETCA_IF_BASE_ABM, 4, ANY_ABM, ETCA_PAT(BASE), 0},
        {"xor",    ETCA_IF_BASE_ABM, 5, ANY_ABM, ETCA_PAT(BASE), 0},
        {"and" ,   ETCA_IF_BASE_ABM, 6, ANY_ABM, ETCA_PAT(BASE), 0},
        {"test",   ETCA_IF_BASE_ABM, 7, ANY_ABM, ETCA_PAT(BASE), 0},
        {"movz",   ETCA_IF_BASE_ABM, 8, ANY_ABM, ETCA_PAT(BASE), 0},
        {"movs",   ETCA_IF_BASE_ABM, 9, ANY_ABM, ETCA_PAT(BASE), 0},

        {"load",   ETCA_IF_BASE_ABM, 10, PARAMS2(REG_IMM, REG_REG),          ETCA_PAT(BASE), 0},
        {"load",   ETCA_IF_BASE_ABM, 10, PARAMS3(MEM_IMM, MEM_REG, REG_MEM), ETCA_PAT(MMAI), 0},
        {"store",  ETCA_IF_BASE_ABM, 11, PARAMS2(REG_IMM, REG_REG),          ETCA_PAT(BASE), 0},
        {"store",  ETCA_IF_BASE_ABM, 11, PARAMS3(MEM_IMM, MEM_REG, REG_MEM), ETCA_PAT(MMAI), 0},

        {"slo",    ETCA_IF_BASE_ABM, 12, PARAMS1(REG_IMM), ETCA_PAT(BASE), 0}, /* Or do we need to communicate stricter conditions here?*/

        {"readcr",  ETCA_IF_BASE_ABM, 14, PARAMS1(REG_IMM), ETCA_PAT(BASE), 0},
        {"writecr", ETCA_IF_BASE_ABM, 15, PARAMS1(REG_IMM), ETCA_PAT(BASE), 0},

#define BASE_JMP(name, opcode) {name, ETCA_IF_BASE_JMP, opcode, PARAMS1(IMM), ETCA_PAT(BASE), 0}, \
                               {name, ETCA_IF_SAF_JMP,  opcode, PARAMS1(REG), ETCA_PAT(SAF), 0}
        BASE_JMP("jz",   0),
        BASE_JMP("jnz",  1),
        BASE_JMP("jn",   2),
        BASE_JMP("jnn",  3),
        BASE_JMP("jc",   4),
        BASE_JMP("jnc",  5),
        BASE_JMP("jv",   6),
        BASE_JMP("jnv",  7),
        BASE_JMP("jbe",  8),
        BASE_JMP("ja",   9),
        BASE_JMP("jl",  10),
        BASE_JMP("jge", 11),
        BASE_JMP("jle", 12),
        BASE_JMP("jg",  13),
        BASE_JMP("jmp", 14),
        BASE_JMP("j",   14),
#undef BASE_JMP

/* the 1 bit set in the opcode is used to indicate that we have a register call, not a jump. */
#define SAF_COND_CALL(name, opcode) {name, ETCA_IF_SAF_JMP, (0b00010000|opcode), PARAMS1(REG), ETCA_PAT(SAF), 0}
	SAF_COND_CALL("callz",   0),
	SAF_COND_CALL("callnz",  1),
	SAF_COND_CALL("calln",   2),
	SAF_COND_CALL("callnn",  3),
	SAF_COND_CALL("callc",   4),
	SAF_COND_CALL("callnc",  5),
	SAF_COND_CALL("callv",   6),
	SAF_COND_CALL("callnv",  7),
	SAF_COND_CALL("callbe",  8),
	SAF_COND_CALL("calla",   9),
	SAF_COND_CALL("calll",  10),
	SAF_COND_CALL("callge", 11),
	SAF_COND_CALL("callle", 12),
	SAF_COND_CALL("callg",  13),
	SAF_COND_CALL("call",   14),
        /* Also the SAF uncond call i, which shares the opcode name with call r */
        {"call", ETCA_IF_SAF_CALL, 0, PARAMS1(IMM), ETCA_PAT(SAF), 0},
#undef SAF_COND_CALL

        {0, 0, 0, ((union etca_opc_params_field) {.uint = 0}), ETCA_PAT(BASE), 0}
};

#undef PARAMS1
#undef PARAMS2
#undef PARAMS3
#undef PARAMS4
#undef PARAMS5
#undef ANY_ABM