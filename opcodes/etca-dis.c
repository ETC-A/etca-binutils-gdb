
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
#include "libiberty.h"
#include <stdio.h>
#include <inttypes.h>

#define DEFINE_TABLE

#include "../include/opcode/etca.h"
#include "disassemble.h"

static fprintf_ftype fpr;
static void *stream;

static bool no_pseudo = false;


extern void print_etca_disassembler_options (FILE * s) {

    fprintf (s, "\n\
The following ETCa specific disassembler options are supported for use\n\
with the -M switch (multiple options should be separated by commas):\n");
    fprintf (s, "\n");
    fprintf (s, "  no-pseudo      Disassemble only into canonical instructions.\n");
    fprintf (s, "\n");

}

/* Parse ETCa disassembler option (without arguments).  */
static bool
parse_etca_dis_option_without_args (const char *option)
{
    if (strcmp (option, "no-pseudo") == 0)
	no_pseudo = true;
    else
	return false;
    return true;
}

static void
parse_etca_dis_options (const char *opts_in)
{
    char *opts = xstrdup (opts_in), *opt = opts, *opt_end = opts;

    //set_default_etca_dis_options ();

    for ( ; opt_end != NULL; opt = opt_end + 1)
    {
	if ((opt_end = strchr (opt, ',')) != NULL)
	    *opt_end = 0;
	if (!parse_etca_dis_option_without_args (opt)) {
	    opcodes_error_handler ("unrecognized disassembler option: %s", opt);
	    return;
	}
    }

    free (opts);
}

const char size_names[4] = {'h', 'x', 'd', 'q'};
struct decoded_arg {
    struct etca_arg_kind kinds;
    union {
	reg_num reg;
	uint64_t imm;
    } as;
};

struct decode_info {
    const struct etca_opc_info *opc_info;
    int8_t size;
    uint16_t opcode;
    enum etca_iformat format;
    union etca_opc_params_field params;
    size_t argc;
    struct decoded_arg args[2];
};

/* decode the instruction or prefix at the current location in the buffer
 * This is potentially called multiple times to decode prefixes or situations where more bytes are needed
 * byte_count should be the number of bytes that are currently valid in buffer
 * Will return 0 if the instruction is finished and valid
 * If the return value is positive, that is an amount of extra bytes required to parse the insn
 * This function should then be called again with the same buffer pointer.
 * If the return value is -1, the instruction is illegal. Anything inside di should be ignored
 * If the return value is -2, we parsed a prefix and added it to di. Read one more byte and call decode_insn starting there */
static int
decode_insn(struct decode_info *di, unsigned char *insn, size_t byte_count) {
    if (byte_count == 0) { return 1; }
    switch ((insn[0] & 0xC0) >> 6) {
	case 0b00:
	    if (byte_count < 2) { return 1; }
	    di->format = ETCA_IF_BASE_ABM;
	    di->size = (insn[0] & 0x30) >> 4;
	    di->opcode = insn[0] & 0x0F;
	    di->argc = 2;
	    if ((insn[1] & 3) == 0) {
		di->params.kinds.rr = 1;
		di->args[0].kinds.reg_class = GPR;
		di->args[0].as.reg = (insn[1] & 0xE0) >> 5;
		di->args[1].kinds.reg_class = GPR;
		di->args[1].as.reg = (insn[1] & 0x1C) >> 2;
	    } else {
		return -1;
	    }
	    return 0;
	case 0b01:
	    if (byte_count < 2) { return 1; }
	    di->format = ETCA_IF_BASE_ABM;
	    di->size = (insn[0] & 0x30) >> 4;
	    di->opcode = insn[0] & 0x0F;
	    di->params.kinds.ri = 1;
	    di->argc = 2;
	    di->args[0].kinds.reg_class = GPR;
	    di->args[0].as.reg = (insn[1] & 0xE0) >> 5;
	    di->args[1].kinds.immAny = 1;
	    di->args[1].kinds.imm5s = ETCA_BASE_ABM_IMM_SIGNED(di->opcode);
	    di->args[1].kinds.imm5z = !di->args[1].kinds.imm5s;
	    di->args[1].as.imm =
		    (insn[1] & 0x1F) | ((di->args[1].kinds.imm5s && insn[1] & 0x10) ? ((uint64_t)(-1) << 5) : 0);
	    return 0;
	case 0b10:
	    if (byte_count < 2) { return 1; }
            if (insn[0] == 0xAF) {
                di->format = ETCA_IF_SAF_JMP;
                di->params.kinds.r = 1;
                di->opcode = insn[1] & 0x1F;
                di->argc = 1;
                di->args[0].kinds.reg_class = GPR;
                di->args[0].as.reg = (insn[1] & 0xE0) >> 5;
                return 0;
            }
	    if ((insn[0] & 0x20) != 0) { return -1; }
            // otherwise, regular base jmp
	    di->format = ETCA_IF_BASE_JMP;
	    di->params.kinds.i = 1;
	    di->opcode = insn[0] & 0x0F;
	    di->argc = 1;
	    di->args[0].kinds.immAny = 1;
	    di->args[0].as.imm = ((insn[0] & 0x10) ? (((uint64_t)(-1)) << 8) : 0) | insn[1];
	    return 0;
	case 0b11:
	    return -1;
    }
    return -1;
}

static const char*
get_reg_name(enum etca_register_class cls, reg_num index, int8_t size) {
    for (const struct etca_reg_info *info = etca_registers; info->name != NULL; info++) {
	if (info->class == cls && info->reg_num == index && (cls != GPR || info->aux.reg_size == size)) {
	    return info->name;
	}
    }
    return NULL;
}
static
bool transform_pop(struct decode_info *di) {
    if (di->args[1].as.reg == 6) {
	di->format = ETCA_IF_SAF_STK;
	di->params.kinds.r = di->params.kinds.rr;
	di->params.kinds.m = di->params.kinds.mr;
	di->params.kinds.rr = di->params.kinds.mr = 0;
	di->argc = 1; /* We can just ignore the second argument from now on */
	return true;
    } else {
	/* Don't worry about ASP right now */
	return false;
    }
}
static
bool transform_push(struct decode_info *di) {
    if (di->args[0].as.reg == 6) {
	di->format = ETCA_IF_SAF_STK;
	di->params.kinds.r = di->params.kinds.rr;
	di->params.kinds.m = di->params.kinds.rm;
	di->params.kinds.i = di->params.kinds.ri;
	di->params.kinds.rr = di->params.kinds.rm = di->params.kinds.ri = 0;
	di->argc = 1; /* We can just ignore the second argument from now on */
	di->args[0] = di->args[1];
	return true;
    } else {
	/* Don't worry about ASP right now */
	return false;
    }
}

#define SELECT_MOV_PSEUDO(di) \
do {\
(di).format = ETCA_IF_SPECIAL;\
(di).opcode = ETCA_MOV;\
(di).params.uint = (1 << OTHER);\
} while (0)

static
bool beaut_readcr(struct decode_info *di) {
    SELECT_MOV_PSEUDO(*di);
    di->args[1].kinds = (struct etca_arg_kind) {.reg_class=CTRL};
    di->args[1].as.reg = di->args[1].as.imm;
    return true;
}
static
bool beaut_writecr(struct decode_info *di) {
    SELECT_MOV_PSEUDO(*di);
    struct decoded_arg source = di->args[0];
    di->args[0].kinds = (struct etca_arg_kind) {.reg_class=CTRL};
    di->args[0].as.reg = di->args[1].as.imm;
    di->args[1] = source;
    return true;
}

static struct beautifier {
    /* Should return true if this beautifier fully handle the opcode */
    bool (*callback)(struct decode_info *);

    enum etca_iformat format;
    union etca_opc_params_field params;
    uint16_t opcode;

    /* This beautifier does not produce a pseudo instruction and can therefore not be deactivated */
    uint16_t no_pseudo: 1;
} beautifiers[] = {
	/* For the case we ever implement a fast lookup for this table,
	 * all entries with the same format should be consecutive */
	{transform_pop, ETCA_IF_BASE_ABM, {.kinds={.rr=1, .mr=1}}, 12, 1},
	{transform_push, ETCA_IF_BASE_ABM, {.kinds={.rr=1, .ri=1, .rm=1}}, 13, 1},
	{beaut_readcr, ETCA_IF_BASE_ABM, {.kinds={.ri=1}}, 14, 0},
	{beaut_writecr, ETCA_IF_BASE_ABM, {.kinds={.ri=1}}, 15, 0},
	{ NULL, ETCA_IF_ILLEGAL, {.uint=0}, 0, 0 }
};


int
print_insn_etca(bfd_vma addr, struct disassemble_info *info) {

#define READ_BYTES(n)                                                             \
    do {                                                                          \
	if ((status = info->read_memory_func(addr + idx, &insn[idx], n, info))) { \
	    goto fail;                                                            \
	};									  \
	idx += n;                                                                 \
    } while (0)

    int status;
    int action;
    stream = info->stream;
    unsigned char insn[MAX_INSTRUCTION_LENGTH];
    char buffer[128];
    fpr = info->fprintf_func;
    size_t idx = 0;
    size_t offset = 0;
    if (info->disassembler_options) {
	parse_etca_dis_options(info->disassembler_options);
	info->disassembler_options = NULL;
    }
    struct decode_info di = {
	    .opc_info = NULL,
	    .format = ETCA_IF_ILLEGAL,
	    .params = {.uint=0},
	    .argc = 0,
	    .args = {},
	    .size = -1,
	    .opcode = 0,
    };
    READ_BYTES(1);
    while (1) {
	action = decode_insn(&di, &insn[offset], (idx - offset));
	if (action == 0) { /* Instruction fully decoded */
	    break;
	} else if (action > 0) { /* We need this many more bytes*/
	    READ_BYTES(action);
	    continue; /* Try again */
	} else if (action == -2) { /* We got a prefix */
	    offset = idx;
	    READ_BYTES(1);
	    continue; /* Parse the next prefix or the actual instruction */
	} else if (action == -1) { /* Illegal instruction (or unrecognizable) */
	    fpr(stream, "bad"); /* TODO: We could probably print something better */
	    return idx;
	}
    }

#define MATCH(a, di) ((a).format == (di).format \
       && ((a).params.uint & (di).params.uint) == (di).params.uint \
       && (a).opcode == (di).opcode)
    /* TODO: once push and pop are implemented, they need to be special cased here
     *       This is also the place where special casing should be implemented if we want to
     *       sometimes emit a mov pseudo invocation */
    for (struct beautifier *beautifier = beautifiers; beautifier->callback != NULL; beautifier++) {
	if (MATCH(*beautifier, di) && (beautifier->no_pseudo || !no_pseudo)) {
	    if (beautifier->callback(&di)) {
		break;
	    }
	}
    }
    for (struct etca_opc_info *opc_info = etca_opcodes; opc_info->name != NULL; opc_info++) {
	if (MATCH(*opc_info, di)) {
	    /* We have a match */
	    di.opc_info = opc_info;
            break;
	}
    }

    if (!di.opc_info) {
        // We weren't able to find a match in the table. This is a disassembler bug,
        // unless in theory the format makes sense but is made illegal by the spec.
        // Anyway, we could kill the disassembler, but in the interest of trying to
        // be useful as much as possible, we print a bad opcode and keep going.
	snprintf(buffer, sizeof(buffer), "<unknown opcode:%" PRIu16 "> ", di.opcode);
    }
    else if (di.opc_info->size_info.suffix_allowed) {
	/* Outputting ? here is also a disassembler bug */
	snprintf(buffer, sizeof(buffer),
		 "%s%c ", di.opc_info->name, di.size >= 0 ? size_names[di.size] : '?');
    } else {
	snprintf(buffer, sizeof(buffer), "%s", di.opc_info->name);
    }
    fpr(stream, "%-7s ", buffer);
    for (size_t i = 0; i < di.argc; i++) {
	if (i != 0) { fpr(stream, ", "); };
	if (di.args[i].kinds.reg_class != RegClassNone) {
	    fpr(stream, "%%%s", get_reg_name(di.args[i].kinds.reg_class, di.args[i].as.reg, di.size));
	} else if (di.args[i].kinds.immAny && di.opc_info && di.opc_info->size_info.args_size == LBL) {
	    info->print_address_func(addr + di.args[i].as.imm, info);
	} else if (di.args[i].kinds.imm5z || di.args[i].kinds.imm8z) {
	    fpr(stream, "%" PRIu64, di.args[i].as.imm);
	} else if (di.args[i].kinds.immAny) {
	    fpr(stream, "%" PRId64, (int64_t) di.args[i].as.imm);
	} else {
	    fpr(stream, "<unknown operand>");
	}
    }


    return idx;
fail:
    info->memory_error_func(status, addr, info);
    return -1;
#undef READ_ONE_BYTE
}