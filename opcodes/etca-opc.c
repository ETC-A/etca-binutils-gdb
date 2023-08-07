
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


/* Register info table. */
const struct etca_reg_info etca_registers[] = {
#define INFIX(before, after, num) {before after, num, {-1}, GPR}, \
                                  {before "h" after, num, {0}, GPR}, \
                                  {before "x" after, num, {1}, GPR}, \
                                  {before "d" after, num, {2}, GPR}, \
                                  {before "q" after, num, {3}, GPR}
#define INFIX_R(num) INFIX("r", #num, num)
#define POSTFIX(name, num)        {name, num, {-1}, GPR}, \
                                  {name "h", num, {0}, GPR}, \
                                  {name "x", num, {1}, GPR}, \
                                  {name "d", num, {2}, GPR}, \
                                  {name "q", num, {3}, GPR}
#define CONTROL(name, num, exts)  {name, num, {exts}, CTRL}
#define EXTS_COMPLEX -1
#define EXTS_ANY      0
#define EXTS_INT      1
#define EXTS_CI       2
#define EXTS_PM       3
    /* base (+ sizes) */
    INFIX_R(0), INFIX_R(1), INFIX_R(2), INFIX_R(3),
    INFIX_R(4), INFIX_R(5), INFIX_R(6), INFIX_R(7),
    /* rex (+ sizes) */
    INFIX_R(8), INFIX_R(9), INFIX_R(10), INFIX_R(11),
    INFIX_R(12), INFIX_R(13), INFIX_R(14), INFIX_R(15),
    /* reserved for rex2 (+ sizes) */
    INFIX_R(16), INFIX_R(17), INFIX_R(18), INFIX_R(19),
    INFIX_R(20), INFIX_R(21), INFIX_R(22), INFIX_R(23),
    INFIX_R(24), INFIX_R(25), INFIX_R(26), INFIX_R(27),
    INFIX_R(28), INFIX_R(29), INFIX_R(30), INFIX_R(31),

    /* base abi names (+ sizes). We accept these even without SAF. */
    INFIX("a", "0", 0), INFIX("a", "1", 1), INFIX("a", "2", 2), INFIX("s", "0", 3),
    INFIX("s", "1", 4), POSTFIX("bp", 5), POSTFIX("sp", 6), POSTFIX("ln", 7),
    /* rex abi names (+ sizes). */
    INFIX("t", "0", 8), INFIX("t", "1", 9), INFIX("t", "2", 10), INFIX("t", "3", 11),
    INFIX("t", "4", 12), INFIX("s", "2", 13), INFIX("s", "3", 14), INFIX("s", "4", 15),

    /* base control registers */
    CONTROL("cpuid1", 0, EXTS_ANY), CONTROL("cpuid2", 1, EXTS_ANY), CONTROL("feat", 2, EXTS_ANY),
    /* INT control registers */
    CONTROL("flags", 3, EXTS_INT), CONTROL("int_pc", 4, EXTS_INT),
    CONTROL("int_sp", 5, EXTS_INT), CONTROL("int_mask", 6, EXTS_INT),
    CONTROL("int_pending", 7, EXTS_INT), CONTROL("int_cause", 8, EXTS_INT),
    CONTROL("int_data", 9, EXTS_INT), CONTROL("int_ret_pc", 10, EXTS_INT),
    CONTROL("int_ret_sp", 11, EXTS_INT),
    /* PM control registers */
    CONTROL("priv", 12, EXTS_PM), CONTROL("int_ret_priv", 13, EXTS_PM),
    /* CI control registers */
    CONTROL("cache_line_size", 14, EXTS_CI), CONTROL("no_cache_start", 15, EXTS_CI),
    CONTROL("no_cache_end", 16, EXTS_CI),
    /* and... mode */
    CONTROL("address_mode", 17, EXTS_COMPLEX),
#undef INFIX
#undef INFIX_R
#undef POSTFIX
#undef CONTROL
#undef EXTS_COMPLEX
#undef EXTS_ANY
#undef EXTS_INT
#undef EXTS_CI
#undef EXTS_PM

    { 0, 0, {0}, 0 }
};

#define PARAMS1(a) ((union etca_opc_params_field) {.uint = (1 << a)})
#define PARAMS2(a,b) ((union etca_opc_params_field) {.uint = (1 << a)|(1 << b)})
#define PARAMS3(a,b,c) ((union etca_opc_params_field) {.uint = (1 << a)|(1 << b)|(1 << c)})
#define PARAMS4(a,b,c,d) ((union etca_opc_params_field) {.uint = (1 << a)|(1 << b)|(1 << c)|(1 << d)})
#define PARAMS5(a,b,c,d,e) ((union etca_opc_params_field) {.uint = (1 << a)|(1 << b)|(1 << c)|(1 << d)|(1<<e)})

#define ANY_ABM PARAMS5(REG_IMM, REG_REG, REG_MEM, MEM_REG, MEM_IMM)

// operations that allow a size suffix
#define SUFFIX(info) ((struct etca_opc_size_info) {.suffix_allowed=1, .args_size=info})
// operations that don't allow a size suffix
#define NOSUFFIX(info) ((struct etca_opc_size_info) {.suffix_allowed=0, .args_size=info})

struct etca_opc_info etca_opcodes[] = {
        /* name, iformat, opcode, params, requirements, try_next*/

#define BASE_COMPUTE(name, c) \
        { name, ETCA_IF_BASE_ABM, c, ANY_ABM, \
          SUFFIX(OPR_OPR), ETCA_PAT(BASE), 0}
        BASE_COMPUTE("add",  0),
        BASE_COMPUTE("sub",  1),
        BASE_COMPUTE("rsub", 2),
        BASE_COMPUTE("cmp",  3),
        BASE_COMPUTE("or",   4),
        BASE_COMPUTE("xor",  5),
        BASE_COMPUTE("and",  6),
        BASE_COMPUTE("test", 7),
        BASE_COMPUTE("movz", 8),
        BASE_COMPUTE("movs", 9),
#undef  BASE_COMPUTE
        // pseudoinstruction takes over without params being checked, but size is computed.
        { "mov", ETCA_IF_SPECIAL, ETCA_MOV, {0}, SUFFIX(OPR_OPR), ETCA_PAT(BASE), 0},

#define BASE_MEMORY(name, c) \
        { name, ETCA_IF_BASE_ABM, c, PARAMS2(REG_IMM, REG_REG), SUFFIX(OPR_ADR), ETCA_PAT(BASE), 0}, \
        { name, ETCA_IF_BASE_ABM, c, PARAMS3(MEM_IMM, MEM_REG, REG_MEM), SUFFIX(OPR_ADR), ETCA_PAT(MMAI), 0}
        BASE_MEMORY("load", 10),
        BASE_MEMORY("store", 11),
#undef  BASE_MEMORY

        // tc-etca.c currently implements the check that the operand here is a
        // concrete immediate as a special-case check.
        {"slo",    ETCA_IF_BASE_ABM, 12, PARAMS1(REG_IMM), SUFFIX(OPR_ANY), ETCA_PAT(BASE), 0},

        {"readcr",  ETCA_IF_BASE_ABM, 14, PARAMS2(REG_IMM, REG_CTRL), SUFFIX(OPR_ANY), ETCA_PAT(BASE), 0},
        {"writecr", ETCA_IF_BASE_ABM, 15, PARAMS2(REG_IMM, REG_CTRL), SUFFIX(OPR_ANY), ETCA_PAT(BASE), 0},

#define BASE_JMP(name, opcode) {name, ETCA_IF_BASE_JMP, opcode, PARAMS1(IMM), NOSUFFIX(LBL), ETCA_PAT(BASE), 0}, \
                               {name, ETCA_IF_SAF_JMP,  opcode, PARAMS1(REG), NOSUFFIX(ADR), ETCA_PAT(SAF), 0}
/* the 1 bit set in the opcode is used to indicate that we have a register call, not a jump. */
#define SAF_COND_CALL(name, opcode) {name, ETCA_IF_SAF_JMP, (0b00010000|opcode), PARAMS1(REG), NOSUFFIX(ADR), ETCA_PAT(SAF), 0}
// doing things this way simplifies adding aliases and the c<code> prefix in the future.
#define CONDITIONAL(ccode, value) BASE_JMP("j" ccode, value), SAF_COND_CALL("call" ccode, value)
        CONDITIONAL("z",   0), CONDITIONAL("e", 0),
        CONDITIONAL("nz",  1), CONDITIONAL("ne", 1),
        CONDITIONAL("n",   2),
        CONDITIONAL("nn",  3),
        CONDITIONAL("c",   4), CONDITIONAL("b", 4), CONDITIONAL("nae", 4),
        CONDITIONAL("nc",  5), CONDITIONAL("ae", 5), CONDITIONAL("nb", 5),
        CONDITIONAL("v",   6),
        CONDITIONAL("nv",  7),
        CONDITIONAL("be",  8), CONDITIONAL("na", 8),
        CONDITIONAL("a",   9), CONDITIONAL("nbe", 9),
        CONDITIONAL("l",  10), CONDITIONAL("nge", 10),
        CONDITIONAL("ge", 11), CONDITIONAL("nl", 11),
        CONDITIONAL("le", 12), CONDITIONAL("ng", 12),
        CONDITIONAL("g",  13), CONDITIONAL("nle", 13),
#undef CONDITIONAL

        BASE_JMP("jmp", 14),
        BASE_JMP("j",   14),
#undef BASE_JMP

	SAF_COND_CALL("call",   14),
        /* Also the SAF uncond call i, which shares the opcode name with call r */
        {"call", ETCA_IF_SAF_CALL, 0, PARAMS1(IMM), NOSUFFIX(LBL), ETCA_PAT(SAF), 0},
#undef SAF_COND_CALL


        {0, 0, 0, ((union etca_opc_params_field) {.uint = 0}), NOSUFFIX(0), ETCA_PAT(BASE), 0}
};

#undef PARAMS1
#undef PARAMS2
#undef PARAMS3
#undef PARAMS4
#undef PARAMS5
#undef ANY_ABM
#undef SUFFIX
#undef NOSUFFIX
