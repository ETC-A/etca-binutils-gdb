
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

const struct etca_extension etca_extensions[ETCA_EXTCOUNT] = {
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
};

#undef EXTENSION
#undef FEATURE

/* An instruction template. */
struct etca_template {
    // other things go here
    struct etca_arg_kind operand_kinds[MAX_OPERANDS];
};

const char etca_register_saf_names[16][3] = {
    "a0", "a1", "a2",
    "s0", "s1",
    "bp", "sp", "ln",
    "t0", "t1", "t2", "t3", "t4",
    "s2", "s3", "s4",
};

const struct etca_opc_info etca_base_rr[16] = {
        {"add",   ETCA_IF_BASE_RR, 0, ETCA_CPI_BASE},
        {"sub",   ETCA_IF_BASE_RR, 1, ETCA_CPI_BASE},
        {"rsub",  ETCA_IF_BASE_RR, 2, ETCA_CPI_BASE},
        {"cmp",   ETCA_IF_BASE_RR, 3, ETCA_CPI_BASE},
        {"or",    ETCA_IF_BASE_RR, 4, ETCA_CPI_BASE},
        {"xor",   ETCA_IF_BASE_RR, 5, ETCA_CPI_BASE},
        {"and",   ETCA_IF_BASE_RR, 6, ETCA_CPI_BASE},
        {"test",  ETCA_IF_BASE_RR, 7, ETCA_CPI_BASE},
        {"movz",  ETCA_IF_BASE_RR, 8, ETCA_CPI_BASE},
        {"movs",  ETCA_IF_BASE_RR, 9, ETCA_CPI_BASE},
        {"load",  ETCA_IF_BASE_RR, 10, ETCA_CPI_BASE},
        {"store", ETCA_IF_BASE_RR, 11, ETCA_CPI_BASE},
        {0,      ETCA_IF_ILLEGAL, 12, ETCA_CPI_BASE},
        {0,      ETCA_IF_ILLEGAL, 13, ETCA_CPI_BASE},
        {0,      ETCA_IF_ILLEGAL, 14, ETCA_CPI_BASE},
        {0,      ETCA_IF_ILLEGAL, 15, ETCA_CPI_BASE},
};

const struct etca_opc_info etca_base_ri[16] = {
        {"add",     ETCA_IF_BASE_RI, 0, ETCA_CPI_BASE},
        {"sub",     ETCA_IF_BASE_RI, 1, ETCA_CPI_BASE},
        {"rsub",    ETCA_IF_BASE_RI, 2, ETCA_CPI_BASE},
        {"cmp",     ETCA_IF_BASE_RI, 3, ETCA_CPI_BASE},
        {"or",      ETCA_IF_BASE_RI, 4, ETCA_CPI_BASE},
        {"xor",     ETCA_IF_BASE_RI, 5, ETCA_CPI_BASE},
        {"and",     ETCA_IF_BASE_RI, 6, ETCA_CPI_BASE},
        {"test",    ETCA_IF_BASE_RI, 7, ETCA_CPI_BASE},
        {"movz",    ETCA_IF_BASE_RI, 8, ETCA_CPI_BASE},
        {"movs",    ETCA_IF_BASE_RI, 9, ETCA_CPI_BASE},
        {"load",    ETCA_IF_BASE_RI, 10, ETCA_CPI_BASE},
        {"store",   ETCA_IF_BASE_RI, 11, ETCA_CPI_BASE},
        {"slo",     ETCA_IF_BASE_RI, 12, ETCA_CPI_BASE},
        {0,         ETCA_IF_ILLEGAL, 13, ETCA_CPI_BASE},
        {"readcr",  ETCA_IF_BASE_RI, 14, ETCA_CPI_BASE},
        {"writecr", ETCA_IF_BASE_RI, 15, ETCA_CPI_BASE},
};
const struct etca_opc_info etca_base_jmp[16] = {
        {"jz",    ETCA_IF_BASE_JMP, 0,  ETCA_CPI_BASE},
        {"jnz",   ETCA_IF_BASE_JMP, 1,  ETCA_CPI_BASE},
        {"jn",    ETCA_IF_BASE_JMP, 2,  ETCA_CPI_BASE},
        {"jnn",   ETCA_IF_BASE_JMP, 3,  ETCA_CPI_BASE},
        {"jc",    ETCA_IF_BASE_JMP, 4,  ETCA_CPI_BASE},
        {"jnc",   ETCA_IF_BASE_JMP, 5,  ETCA_CPI_BASE},
        {"jv",    ETCA_IF_BASE_JMP, 6,  ETCA_CPI_BASE},
        {"jnv",   ETCA_IF_BASE_JMP, 7,  ETCA_CPI_BASE},
        {"jbe",   ETCA_IF_BASE_JMP, 8,  ETCA_CPI_BASE},
        {"ja",    ETCA_IF_BASE_JMP, 9,  ETCA_CPI_BASE},
        {"jl",    ETCA_IF_BASE_JMP, 10, ETCA_CPI_BASE},
        {"jge",   ETCA_IF_BASE_JMP, 11, ETCA_CPI_BASE},
        {"jle",   ETCA_IF_BASE_JMP, 12, ETCA_CPI_BASE},
        {"jg",    ETCA_IF_BASE_JMP, 13, ETCA_CPI_BASE},
        {"jmp",   ETCA_IF_BASE_JMP, 14, ETCA_CPI_BASE},
        {"never", ETCA_IF_BASE_JMP, 15, ETCA_CPI_BASE},
};