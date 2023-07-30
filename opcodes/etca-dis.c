
/* Disassemble etca instructions.
   Free Software Foundation, Inc.

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
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include <stdio.h>

#define STATIC_TABLE
#define DEFINE_TABLE

#include "../include/opcode/etca.h"
#include "disassemble.h"

static fprintf_ftype fpr;
static void *stream;

const char* size_names[4] = {"h", "x", "d", "q"};

int
print_insn_etca(bfd_vma addr, struct disassemble_info *info) {
    int status;
    stream = info->stream;
    unsigned char opcode;
    fpr = info->fprintf_func;

    if ((status = info->read_memory_func(addr, &opcode, 1, info))) {
        goto fail;
    }
#if 0
    unsigned char buffer[8];
    const struct etca_opc_info *opc_info;
    switch (opcode >> 6) { /* top two bits are the (general) format. */
        case 0b00: /* rr */
            opc_info = &etca_base_rr[opcode & 0xF];
            if (opc_info->format != ETCA_IF_BASE_RR) {
                fpr(stream, "bad");
                break;
            } else {
                uint8_t size = (opcode & 0x30) >> 4;
                if ((status = info->read_memory_func(addr+1, buffer, 1, info))) {
                    goto fail;
                }
                uint8_t reg_a = (buffer[0] & 0xE0)>>5;
                uint8_t reg_b = (buffer[0] & 0x1C)>>2;
                fpr(stream, "%s%s\t%%r%s%d, %%r%s%d", opc_info->name, size_names[size],
                    size_names[size], reg_a,
                    size_names[size], reg_b);
            }
            break;
        case 0b01:
            opc_info = &etca_base_ri[opcode & 0xF];
            if (opc_info->format != ETCA_IF_BASE_RI) {
                fpr(stream, "bad");
                break;
            } else {
                uint8_t size = (opcode & 0x30) >> 4;
                if ((status = info->read_memory_func(addr+1, buffer, 1, info))) {
                    goto fail;
                }
                uint8_t reg_a = (buffer[0] & 0xE0)>>5;
                int8_t imm = buffer[0] & 0x1F;
                imm |=  (imm & 0x10) ? 0xF0 : 0x0;
                fpr(stream, "%s%s\t%%r%s%d, %i", opc_info->name, size_names[size],
                    size_names[size], reg_a,
                    imm);
            }
            break;
        case 0b10:
            opc_info = &etca_base_jmp[opcode & 0xF];
            if (opc_info->format != ETCA_IF_BASE_JMP) {
                fpr(stream, "bad");
                break;
            } else {
                if ((status = info->read_memory_func(addr+1, buffer, 1, info))) {
                    goto fail;
                }
                int16_t disp = buffer[0];
                disp |=  (opcode & 0x10) ? 0xFF00 : 0x0000;
                fpr(stream, "%s\t%i", opc_info->name, disp);
            }
            break;
        case 0b11:
            fpr(stream, "bad");
            break;
    }
#endif
    fpr(stream, "bad");

    return 2;
    fail:
    info->memory_error_func(status, addr, info);
    return -1;
}