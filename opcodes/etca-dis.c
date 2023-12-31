
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

static fprintf_styled_ftype fprs;
static void *stream;

static bool no_pseudo = false;
static enum etca_size_attr address_size = SA_WORD;

extern void print_etca_disassembler_options (FILE * s) {

    fprintf (s, "\n\
The following ETCa specific disassembler options are supported for use\n\
with the -M switch (multiple options should be separated by commas):\n");
    fprintf (s, "\n");
    fprintf (s, "  no-pseudo      Disassemble only into canonical instructions.\n");
    fprintf (s, "  addr32         Assume 32-bit address size (default 16).\n");
    fprintf (s, "\n");
}

/* Parse ETCa disassembler option (without arguments).  */
static bool
parse_etca_dis_option_without_args (const char *option)
{
    if (strcmp (option, "no-pseudo") == 0)
    	no_pseudo = true;
    else if (strcmp (option, "addr32") == 0)
        address_size = SA_DWORD;
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

// Locally rename enum etca_size_attr to something easier.
typedef enum etca_size_attr size_attr;

struct decoded_arg {
    struct etca_arg_kind kinds;
    union {
	reg_num reg;
	uint64_t imm;
        struct decoded_mem {
            int64_t disp;
            reg_num base_reg;
            reg_num index_reg;
            uint8_t scale;
            bool iprel;
        } memory;
    } as;
};

struct decode_info {
    bfd_byte insn[MAX_INSTRUCTION_LENGTH];
    bfd_vma addr;
    bfd_size_type idx;
    bfd_size_type offset;
    const struct etca_opc_info *opc_info;
    size_attr size;
    uint16_t opcode;
    enum etca_iformat format;
    union etca_opc_params_field params;
    size_t argc;
    struct decoded_arg args[2];
    struct {
        condition_code ccode;
        bfd_byte full;
    } cond;
    struct {
	uint8_t x: 1;
	uint8_t b: 1;
	uint8_t a: 1;
	uint8_t q: 1;
	bfd_byte full;
    } rex;
};

#define SIGN_EXTEND(value, bit) ((((value) & ((1ULL << (bit)) -1)) ^ (1ULL << ((bit) - 1))) - (1ULL << ((bit) - 1)))

static int decode_abm_mode(struct decode_info*, bfd_byte*, size_t);
static size_attr get_ptr_size(void);

/* decode the instruction or prefix at the current location in the buffer
 * This is potentially called multiple times to decode prefixes or situations where more bytes are needed
 * byte_count should be the number of bytes that are currently valid in buffer
 * Will return 0 if the instruction is finished and valid
 * If the return value is positive, that is an amount of extra bytes required to parse the insn
 * This function should then be called again with the same buffer pointer.
 * If the return value is -1, the instruction is illegal. Anything inside di should be ignored
 * If the return value is -2, we parsed a prefix and added it to di. Read one more byte and call decode_insn starting there
 * If the return value is -3, we tried to read extra bytes but failed, raise a memory error */
static int
decode_insn(struct disassemble_info *info, bfd_byte *insn, size_t byte_count) {
#define REX(name, value) ( (reg_num) (value) | (di->rex.name << 3))
    struct decode_info *di = (struct decode_info *) info->private_data;
    if (byte_count == 0) { return 1; }
    switch ((insn[0] & 0xC0) >> 6) {
	case 0b00:
	    if (byte_count < 2) { return 1; }
	    info->insn_info_valid = 1;
	    info->insn_type = dis_nonbranch;
	    di->format = ETCA_IF_BASE_ABM;
	    di->size =  (int8_t) ((insn[0] & 0x30) >> 4);
	    di->opcode = insn[0] & 0x0F;
            if (di->opcode == 15 && (insn[1] & 0x13) == 0x11) { /* mtcr misc format: syscall,eret,wait */
                di->format = ETCA_IF_MTCR_MISC;
                info->insn_type = dis_nonbranch;
                di->params.kinds.e = 1;
                di->argc = 0;
                di->opcode = (insn[0] & 0x30) >> 4;
                return 0;
            }
	    if (di->opcode == 10 || di->opcode == 11) { /* LOAD or STORE */
		info->data_size = (1 << di->size);
		info->insn_type = dis_dref;
	    }
	    di->argc = 2;
            int res = decode_abm_mode(di, insn+1, byte_count-1);
            if (di->opcode == 15 && (di->params.kinds.mr || di->params.kinds.rm)) {
                // mtcr operands cannot be mr or rm (but mi is fine).
                return -1;
            }
	    return res;
	case 0b01:
	    if (byte_count < 2) { return 1; }
	    info->insn_info_valid = 1;
	    info->insn_type = dis_nonbranch;
	    di->format = ETCA_IF_BASE_ABM;
	    di->size =  (int8_t) ((insn[0] & 0x30) >> 4);
	    di->opcode = insn[0] & 0x0F;
	    di->params.kinds.ri = 1;
	    di->argc = 2;
	    di->args[0].kinds.reg_class = GPR;
	    di->args[0].as.reg = REX(a, (insn[1] & 0xE0) >> 5);
	    di->args[1].kinds.immAny = 1;
	    di->args[1].kinds.imm5s = ETCA_BASE_ABM_IMM_SIGNED(di->opcode);
	    di->args[1].kinds.imm5z = !di->args[1].kinds.imm5s;
	    di->args[1].as.imm  = insn[1] & 0x1F;
	    if (di->args[1].kinds.imm5s) {
		di->args[1].as.imm = SIGN_EXTEND(di->args[1].as.imm, 5);
	    }
	    if (di->opcode == 10 || di->opcode == 11) { /* LOAD or STORE */
		info->insn_type = dis_dref;
		info->data_size = (1 << di->size);
		info->target = di->args[1].as.imm;
	    }
	    return 0;
	case 0b10:
	    if (insn[0] == 0xAE) { /* One byte nop */
		di->format = ETCA_IF_PSEUDO;
		di->opcode = ETCA_NOP;
		di->argc = 0;
		di->size = 0;
		di->params.kinds.e = 1;
		return 0;
	    }
            // must check for ! 0xAF, as that is the register jump header byte
            if ((insn[0] & 0xF0) == 0xA0 && insn[0] != 0xAF) { /* COND prefix */
                di->cond.ccode = insn[0] & 0x0F;
                di->cond.full = insn[0];
                return -2;
            }
	    if (byte_count < 2) { return 1; }
            if (insn[0] == 0xAF) {
                di->format = ETCA_IF_SAF_JMP;
                di->params.kinds.r = 1;
                di->opcode = insn[1] & 0x1F;
                di->argc = 1;
                di->args[0].kinds.reg_class = GPR;
                di->args[0].as.reg = REX(a, (insn[1] & 0xE0) >> 5);
		info->insn_info_valid = 1;
		info->insn_type = (insn[1] & 0x10) ? dis_branch : dis_jsr;
		info->insn_type += (insn[1] & 0xF) != 0xE; // relies on the order of the enum
		info->target = 0;
                return 0;
            }
            if ((insn[0] & 0xF0) == 0xB0) { /* SAF 12-bit call */
                di->format = ETCA_IF_SAF_CALL;
                // the opcode is arbitrary so the table has 0. We have to match the table.
                di->opcode = 0;
                di->params.kinds.i = 1;
                di->argc = 1;
                di->args[0].kinds.disp12 = di->args[0].kinds.dispAny = 1;
                di->args[0].as.imm = (((insn[0] & 0xF) << 8) | insn[1]);
                di->args[0].as.imm = di->addr + SIGN_EXTEND(di->args[0].as.imm, 12);
		info->insn_info_valid = 1;
		info->insn_type = dis_jsr;
		info->target = di->args[0].as.imm;
                return 0;
            }
	    if ((insn[0] & 0x20) != 0) { return -1; }
            // otherwise, regular base jmp
	    di->format = ETCA_IF_BASE_JMP;
	    di->params.kinds.i = 1;
	    di->opcode = insn[0] & 0x0F;
	    di->argc = 1;
	    di->args[0].kinds.disp9 = di->args[0].kinds.dispAny = 1;
	    di->args[0].as.imm = di->addr + (((insn[0] & 0x10) ? (((uint64_t)(-1)) << 8) : 0) | insn[1]);
	    info->insn_info_valid = 1;
	    info->insn_type = (di->opcode == 0xE) ? dis_branch : dis_condbranch;
	    info->target = di->args[0].as.imm;
	    return 0;
	case 0b11:
            if ((insn[0] & 0xF0) == 0xE0) { /* EXOP computation */
                if (byte_count < 3) { return 3 - byte_count; }
                di->format = ETCA_IF_EXOP_ABM;
                di->params.kinds.ri = !!(insn[1] & 0x40);
                di->size   = (insn[1] & 0x30) >> 4;
                di->opcode = ((insn[0] & 0x0F) << 5)
                           | ((insn[1] & 0x80) >> 3)
                           | ((insn[1] & 0x0F)     );
                info->insn_type = dis_nonbranch;
                di->argc = 2;
                if (di->params.kinds.ri) {
                    di->args[0].kinds.reg_class = GPR;
                    di->args[0].as.reg = REX(a, (insn[2] & 0xE0) >> 5);
                    di->args[1].kinds.immAny = di->args[1].kinds.imm5s = 1;
                    di->args[1].as.imm = SIGN_EXTEND(insn[2], 5);
                    return 0;
                } else {
                    return decode_abm_mode(di, insn+2, byte_count-2);
                }
            }
            else if ((insn[0] & 0xF0) == 0xF0) { /* EXOP jump/call */
                uint8_t size = insn[0] & 0x03;
                size_t nptr_bytes = 1ULL << size;
                bool absolute;
                if (byte_count < 1 + nptr_bytes) {
                    return 1 + nptr_bytes - byte_count;
                }
                di->format = ETCA_IF_EXOP_JMP;
                di->opcode = insn[0] & 0x08;
                absolute = !!(insn[0] & 0x04);
                info->insn_type = di->cond.full ? dis_condbranch : dis_branch;
                info->insn_info_valid = true;
                di->argc = di->params.kinds.i = 1;
                di->args[0].kinds.dispAny = 1;
                di->args[0].kinds.disp8 = size == SA_BYTE; // set this accurately
                memcpy(&di->args[0].as.imm, insn + 1, nptr_bytes);
                if (absolute) {
                    bfd_vma mask = 1ULL << (8 * nptr_bytes);
                    mask = ~(mask-1);
                    di->args[0].as.imm = (di->addr & mask) | di->args[0].as.imm;
                } else {
                    // sign extend the immediate; but not if it's 8 bytes as the macro
                    // doesn't seem to work in that case (still not sure why).
                    if (nptr_bytes != 8) {
                        di->args[0].as.imm = SIGN_EXTEND(di->args[0].as.imm, 8 * nptr_bytes);
                    }
                    di->args[0].as.imm = di->addr + di->args[0].as.imm;
                }
                info->target = di->args[0].as.imm;
                return 0;
            }
	    else if ((insn[0] & 0b00110000) == 0) { /* REX prefix */
		if (di->rex.full) return -1;
		di->rex.full = insn[0];
		di->rex.x = (insn[0] & 0x1) != 0;
		di->rex.b = (insn[0] & 0x2) != 0;
		di->rex.a = (insn[0] & 0x4) != 0;
		di->rex.q = (insn[0] & 0x8) != 0;
		return -2;
	    }
	    return -1;
    }
    return -1;
}

static int decode_abm_mode(struct decode_info *di, bfd_byte *abm, size_t byte_count) {
    if (byte_count == 0) return 1; // this shouldn't happen, but be defensive.
        // require at least the ABM byte.

    if ((abm[0] & 3) == 0) { /* RR */
        di->params.kinds.rr = 1;
        di->args[0].kinds.reg_class = GPR;
        di->args[0].as.reg = REX(a, (abm[0] & 0xE0) >> 5);
        di->args[1].kinds.reg_class = GPR;
        di->args[1].as.reg = REX(b, (abm[0] & 0x1C) >> 2);
        return 0;
    }
    if ((abm[0] & 0x1B) == 0x09) { /* FI */
        size_t num_fi_bytes;
        bool is_signed = !(di->format == ETCA_IF_BASE_ABM && ETCA_BASE_ABM_IMM_UNSIGNED(di->opcode));
        if ( !(abm[0] & 0x04) ) { /* 8-bit format */
            num_fi_bytes = 1;
            di->args[1].kinds.imm8s = is_signed;
            di->args[1].kinds.imm8z = !is_signed;
        } else { /* SS attr -bit format */
            num_fi_bytes = di->size;
            // clamp if we didn't see rex.Q
            if (num_fi_bytes == SA_QWORD && !di->rex.q) num_fi_bytes = SA_DWORD;
            num_fi_bytes = 1 << num_fi_bytes;
        }
        if (byte_count < 1 + num_fi_bytes) { return 1 + num_fi_bytes - byte_count; }
        di->params.kinds.ri = 1;
        di->args[0].kinds.reg_class = GPR;
        di->args[0].as.reg = REX(a, (abm[0] & 0xE0) >> 5);
        di->args[1].kinds.immAny = 1;
        di->args[1].as.imm = 0;
        memcpy(&di->args[1].as.imm, abm + 1, num_fi_bytes);
        if (is_signed) {
            size_t num_bits = num_fi_bytes * 8;
            if (num_bits < 64) {
                di->args[1].as.imm = SIGN_EXTEND(di->args[1].as.imm, num_bits);
            }
        }
        return 0;
    }
    if ((abm[0] & 0x1B) == 0x01) { /* m,i operands */
        size_attr ptr_attr = get_ptr_size();
        size_attr imm_attr = (abm[0] & 0x04) ? di->size : SA_BYTE;
        size_t num_ptr_bytes = 0;
        size_t num_imm_bytes = 0;
        unsigned char field_A = (abm[0] & 0xE0) >> 5; // should REX.A be illegal here?
        bool have_disp = !!(field_A & 0x01);
        bool have_base = !!(field_A & 0x02);
        bool have_idx  = !!(field_A & 0x04);

        // A = 0 and A = 4 are illegal
        if (field_A == 0 || field_A == 4) return -1;

        // can't have REX.Q with a displacement
        if (ptr_attr == SA_QWORD) ptr_attr = SA_DWORD;
        // but we can with an immediate, if there's no displacement. Check later.
        if (imm_attr == SA_QWORD && !di->rex.q) imm_attr = SA_DWORD;

        if (have_disp) num_ptr_bytes = 1U << ptr_attr;
        num_imm_bytes = 1U << imm_attr;

        if (byte_count < 2/*abm+sib*/ + num_ptr_bytes + num_imm_bytes)
            return 2 + num_ptr_bytes + num_imm_bytes - byte_count;

        // start filling in fields...
        di->params.kinds.mi = 1;
        di->args[0].kinds.memory = 1;
        di->args[0].as.memory.base_reg = -1;
        di->args[0].as.memory.index_reg = -1;
        di->args[0].as.memory.disp = 0;
        di->args[1].kinds.immAny = 1;
        if (num_imm_bytes == 1) {
            if (di->format == ETCA_IF_BASE_ABM && ETCA_BASE_ABM_IMM_UNSIGNED(di->opcode)) {
                di->args[1].kinds.imm8z = 1;
            } else {
                di->args[1].kinds.imm8s = 1;
            }
        }

        if (have_disp) {
            if (di->rex.q) return -1; // can't have rex.q with disp and imm
            di->args[0].kinds.dispAny = di->args[0].kinds.dispPtr = 1;
            memcpy(&di->args[0].as.memory.disp, abm+2, num_ptr_bytes);
            if (num_ptr_bytes < 8) {
                di->args[0].as.memory.disp =
                    SIGN_EXTEND(di->args[0].as.memory.disp, 8*num_ptr_bytes);
            }
        }
        if (have_base) {
            di->args[0].as.memory.base_reg = REX(b, (abm[1] & 0x07));
        }
        if (have_idx) {
            di->args[0].as.memory.index_reg = REX(x, (abm[1] & 0x38) >> 3);
            di->args[0].as.memory.scale = 1U << ((abm[1] & 0xC0) >> 6);
        }
        memcpy(&di->args[1].as.imm, abm + 2 + num_ptr_bytes, num_imm_bytes);
        if (num_imm_bytes < 8) {
            di->args[1].as.imm = SIGN_EXTEND(di->args[1].as.imm, 8*num_imm_bytes);
        }
        return 0;
    }

    if ((abm[0] & 0x1B) == 0x11) { /* r,[ip]*/
        size_attr disp_attr = (abm[0] & 0x04) ? get_ptr_size() : SA_BYTE;
        size_t num_disp_bytes;

        // ensure we have enough bytes (no SIB byte)
        if (disp_attr == SA_QWORD && !di->rex.q) disp_attr = SA_DWORD;
        num_disp_bytes = 1U << disp_attr;

        if (byte_count < 1 + num_disp_bytes) return 1 + num_disp_bytes - byte_count;

        // now fill in fields.
        di->args[0].kinds.reg_class = GPR;
        di->params.kinds.rm = di->args[1].kinds.memory = 1;
        di->args[1].as.memory.iprel = true;
        di->args[1].as.memory.base_reg = -1;
        di->args[1].as.memory.index_reg = -1;

        di->args[0].as.reg = REX(a, (abm[0] & 0xE0) >> 5);

        if (disp_attr == SA_BYTE) {
            di->args[1].kinds.disp8 = 1;
        } else {
            di->args[1].kinds.dispPtr = 1;
        }
        di->args[1].kinds.dispAny = 1;
        memcpy(&di->args[1].as.memory.disp, abm+1, num_disp_bytes);
        if (num_disp_bytes < 8) {
            di->args[1].as.memory.disp =
                SIGN_EXTEND(di->args[1].as.memory.disp, 8*num_disp_bytes);
        }
        return 0;
    }
    if ((abm[0] & 0x02) || ((abm[0] & 0x1B) == 0x19)) { /* r,m or m,r */
        struct decoded_arg *mem_arg, *reg_arg;
        bool have_d8, have_dP, have_base, have_index;
        size_attr disp_attr = SA_UNKNOWN;
        size_t num_disp_bytes = 0;
        have_d8 = have_dP = have_base = have_index = 0;
        if ((abm[0] & 0x1B) == 0x19) { /* r,[B+S*X] (&0x04 == 0) and the reverse. */
            if (abm[0] & 0x04) {
                mem_arg = &di->args[0];
                reg_arg = &di->args[1];
                di->params.kinds.mr = 1;
            } else {
                reg_arg = &di->args[0];
                mem_arg = &di->args[1];
                di->params.kinds.rm = 1;
            }
            have_base = have_index = true;
        } else { /* MO1 reversible modes */
            if (abm[0] & 0x01) { /* m,r */
                mem_arg = &di->args[0];
                reg_arg = &di->args[1];
                di->params.kinds.mr = 1;
            } else { /* r,m */
                reg_arg = &di->args[0];
                mem_arg = &di->args[1];
                di->params.kinds.rm = 1;
            }
            have_dP = !!(abm[0] & 0x04);
            // we have a d8 if there's no dP, _unless_ ABM.regB is 0.
            have_d8 = !have_dP && (abm[0] & 0x1C);
            have_base  = !!(abm[0] & 0x08) || ((abm[0] & 0x1C) == 0);
            have_index = !!(abm[0] & 0x10);
        }

        // how many bytes do we need? Hopefully, the compiler is smart
        // enough to sink all of the otherwise-irrelevant base/index
        // work above to below this. Moving it ourselves complicates the code.
        if (have_d8 || have_dP) {
            disp_attr = have_dP ? get_ptr_size() : SA_BYTE;
            if (disp_attr == SA_QWORD && !di->rex.q) disp_attr = SA_DWORD;
            num_disp_bytes = 1U << disp_attr;
        }
        // we need this ABM byte, the SIB byte, and the disp bytes.
        if (byte_count < 2 + num_disp_bytes) return 2 + num_disp_bytes - byte_count;

        // OK, we have enough bytes. Decode the fields.
        reg_arg->kinds.reg_class = GPR;
        reg_arg->as.reg = REX(a, (abm[0] & 0xE0) >> 5);
        mem_arg->kinds.memory = 1;
        mem_arg->as.memory.base_reg = -1;
        mem_arg->as.memory.index_reg = -1;
        // the rest of this is a copy of the m,i case and can maybe be pulled into a function.
        if (have_base) {
            mem_arg->as.memory.base_reg = REX(b, (abm[1] & 0x07));
        }
        if (have_index) {
            mem_arg->as.memory.index_reg = REX(x, (abm[1] & 0x38) >> 3);
            mem_arg->as.memory.scale = 1U << ((abm[1] & 0xC0) >> 6);
        }
        if (have_d8 || have_dP) {
            mem_arg->kinds.dispAny = 1;
            if (have_d8) mem_arg->kinds.disp8 = 1;
            else         mem_arg->kinds.dispPtr = 1;

            memcpy(&mem_arg->as.memory.disp, abm+2, num_disp_bytes);
            if (num_disp_bytes < 8) {
                mem_arg->as.memory.disp = SIGN_EXTEND(
                    mem_arg->as.memory.disp, 8*num_disp_bytes
                );
            }
        }
        return 0;
    }

    // otherwise, we have no clue what this is.
    return -1;
}

static size_attr get_ptr_size(void) {
    return address_size;
}

static const char*
get_reg_name(enum etca_register_class cls, reg_num index, int8_t size) {
    for (const struct etca_reg_info *info = etca_registers; info->name != NULL; info++) {
	if (info->class == cls && info->reg_num == index && (cls != GPR || info->aux.reg_size == size)) {
	    return info->name;
	}
    }
    printf("\n%d, %d\n", index, size);
    return NULL;
}

#define SELECT_MOV_PSEUDO(di) \
do {\
(di).format = ETCA_IF_SPECIAL;\
(di).opcode = ETCA_MOV;\
(di).params.kinds = (struct etca_params_kind) {.other=1};\
} while (0)

static
bool transform_pop(struct disassemble_info * info) {
    struct decode_info *di = (struct decode_info*)info->private_data;
    if (di->args[1].as.reg == 6) {
	di->format = ETCA_IF_SAF_STK;
	di->params.kinds.r = di->params.kinds.rr;
	di->params.kinds.m = di->params.kinds.mr;
	di->params.kinds.rr = di->params.kinds.mr = 0;
	di->argc = 1; /* We can just ignore the second argument from now on */
    } else {
        // in some sense, ASP is a pseudo-syntax, but there's no _actual_
        // syntax, so doing it in this no-pseudo transformer is fine.
        SELECT_MOV_PSEUDO(*di);
        di->args[1].kinds.postinc = 1; // leave it in the GPR though, that's fine.
    }
    return true;
}
static
bool transform_push(struct disassemble_info * info) {
    struct decode_info *di = (struct decode_info*)info->private_data;
    if (di->args[0].as.reg == 6) {
	di->format = ETCA_IF_SAF_STK;
	di->params.kinds.r = di->params.kinds.rr;
	di->params.kinds.m = di->params.kinds.rm;
	di->params.kinds.i = di->params.kinds.ri;
	di->params.kinds.rr = di->params.kinds.rm = di->params.kinds.ri = 0;
	di->argc = 1; /* We can just ignore the second argument from now on */
	di->args[0] = di->args[1];
    } else {
        // in some sense, ASP is a pseudo-syntax, but there's no _actual_
        // syntax, so doing it in this no-pseudo transformer is fine.
        SELECT_MOV_PSEUDO(*di);
        di->args[0].kinds.predec = 1; // leave it in the GPR though, that's fine.
    }
    return true;
}


static
bool transform_never_jump(struct disassemble_info * info) {
    struct decode_info *di = (struct decode_info*)info->private_data;
    di->format = ETCA_IF_PSEUDO;
    di->opcode = ETCA_NOP;
    di->params.kinds = (struct etca_params_kind) {.e=1};
    di->size = 1;
    switch (di->args[0].as.imm - di->addr) {
	case 0:
	    di->argc = 0;
	    return true;
	default:
	    /* Print the immediate argument for this unknown non-canonical NOP. That isn't valid
	     * syntax, but it should highlight that something is weird here. */
	    di->argc = 1;
	    return false;
    }
}

static
bool beaut_exop_jmp(struct disassemble_info * info) {
    struct decode_info *di = info->private_data;

    // FIXME: temporarily disabled along with automatic exop promotion in gas
    return true;

    if (di->opcode != 0) {
        // we have an exop `lcall'
        // change it to an saf `call' but we can't do anything
        // about the possibility of a COND prefix.
        di->opcode = 0;
        di->format = ETCA_IF_SAF_CALL;
    } else {
        // we have an exop `ljmp'
        // Change it to a base `jmp', and move the COND info to the opcode.
        if (di->cond.full) {
            di->opcode = di->cond.ccode;
            di->cond.ccode = di->cond.full = 0;
        } else {
            di->opcode = ETCA_COND_ALWAYS;
        }
        di->format = ETCA_IF_BASE_JMP;
    }
    return true;
}

static
bool beaut_mov_slo(struct disassemble_info * info) {
    struct decode_info *di = (struct decode_info*)info->private_data;
    int status;
    bfd_byte extra[3];
    SELECT_MOV_PSEUDO(*di);
    const bfd_byte slo_expected = 0b01001100 | (di->size << 4);
    const unsigned int delta = di->rex.full ? 3 : 2;

    while ((info->stop_vma == 0) || (di->addr + di->idx + delta <= info->stop_vma)) {
	if ((status = info->read_memory_func(di->addr + di->idx, &extra[0], delta, info)) != 0) {
	    break;
	}
	if (di->rex.full && extra[0] != di->rex.full) {
	    break;
	}
	if (extra[delta-2] != slo_expected) {
	    break;
	}
	if (extra[delta-1] >> 5 != (di->args[0].as.reg & 7)) {
	    break;
	}
	di->idx += delta;
	di->args[1].as.imm = (di->args[1].as.imm << 5) | (extra[delta - 1] & 0x1F);
    }
    return true;
}

static
bool beaut_readcr(struct disassemble_info * info) {
    struct decode_info *di = (struct decode_info*)info->private_data;
    SELECT_MOV_PSEUDO(*di);
    di->args[1].kinds = (struct etca_arg_kind) {.reg_class=CTRL};
    di->args[1].as.reg = (reg_num) di->args[1].as.imm;
    return true;
}
static
bool beaut_writecr(struct disassemble_info * info) {
    struct decode_info *di = (struct decode_info*)info->private_data;
    SELECT_MOV_PSEUDO(*di);
    struct decoded_arg source = di->args[0];
    di->args[0].kinds = (struct etca_arg_kind) {.reg_class=CTRL};
    di->args[0].as.reg = (reg_num) di->args[1].as.imm;
    di->args[1] = source;
    return true;
}

static
bool beaut_load(struct disassemble_info *info) {
    struct decode_info *di = info->private_data;
    reg_num ptr_reg = di->args[1].as.reg;
    SELECT_MOV_PSEUDO(*di);
    // args[0] is fine
    di->args[1].kinds = (struct etca_arg_kind){.memory = 1};
    di->args[1].as.memory.base_reg = ptr_reg;
    di->args[1].as.memory.index_reg = -1;
    di->args[1].as.memory.disp = 0;
    return true;
}
static
bool beaut_store(struct disassemble_info *info) {
    struct decode_info *di = info->private_data;
    reg_num ptr_reg = di->args[1].as.reg;
    SELECT_MOV_PSEUDO(*di);
    // args[0] has the mov src operand so we have to move it over.
    di->args[1] = di->args[0];
    di->args[0].kinds = (struct etca_arg_kind){.memory = 1};
    di->args[0].as.memory.base_reg = ptr_reg;
    di->args[0].as.memory.index_reg = -1;
    di->args[0].as.memory.disp = 0;
    return true;
}

static
bool beaut_ret(struct disassemble_info *info) {
    struct decode_info *di = info->private_data;
    // if this is a call, don't touch anything!
    if (di->opcode & 0x10) return true;
    // we "fully handle" jumps that are not through %r7 by doing nothing.
    if (di->args[0].as.reg != 7) return true;
    // otherwise, delete the arg. It'll then match the 'ret' patterns.
    di->argc = 0;
    di->params.kinds = (struct etca_params_kind){.e=1};
    return true;
}

#undef SELECT_MOV_PSEUDO

static struct beautifier {
    /* Should return true if this beautifier fully handle the opcode */
    bool (*callback)(struct disassemble_info *);

    enum etca_iformat format;
    union etca_opc_params_field params;
    int16_t opcode; // if this is -1, we should match any opcode

    /* This beautifier does not produce a pseudo instruction and can therefore not be deactivated */
    uint16_t no_pseudo: 1;
} beautifiers[] = {
	/* For the case we ever implement a fast lookup for this table,
	 * all entries with the same format should be consecutive */
	{transform_pop, ETCA_IF_BASE_ABM, {.kinds={.rr=1, .mr=1}}, 12, 1},
	{transform_push, ETCA_IF_BASE_ABM, {.kinds={.rr=1, .ri=1, .rm=1}}, 13, 1},
	{beaut_readcr, ETCA_IF_BASE_ABM, {.kinds={.ri=1}}, 14, 0},
	{beaut_writecr, ETCA_IF_BASE_ABM, {.kinds={.ri=1}}, 15, 0},
	{beaut_mov_slo, ETCA_IF_BASE_ABM, {.kinds={.ri=1}}, 8, 0},
	{beaut_mov_slo, ETCA_IF_BASE_ABM, {.kinds={.ri=1}}, 9, 0},
        {beaut_load,    ETCA_IF_BASE_ABM, {.kinds={.rr=1}}, 10, 0},
        {beaut_store,   ETCA_IF_BASE_ABM, {.kinds={.rr=1}}, 11, 0},
	{transform_never_jump, ETCA_IF_BASE_JMP, {.kinds={.i=1}}, 15, 1},
        // temporarily disabled along with automatic exop promotion; fix in the function
        {beaut_exop_jmp, ETCA_IF_EXOP_JMP, {.kinds={.i=1}}, -1, 0},
        {beaut_ret,     ETCA_IF_SAF_JMP,  {.kinds={.r=1}}, -1, 0},
	{ NULL, ETCA_IF_ILLEGAL, {.uint=0}, 0, 0 }
};

struct beautifier mov_starts[2] = {
	{NULL, ETCA_IF_BASE_ABM, {.kinds={.ri=1}}, 8, 0},
	{NULL, ETCA_IF_BASE_ABM, {.kinds={.ri=1}}, 9, 0},
};


int
print_insn_etca(bfd_vma addr, struct disassemble_info *info) {

    int status;
    int action;
    char buffer[128];
    struct decoded_mem *needs_addr_comment = NULL;
    stream = info->stream;
    fprs = info->fprintf_styled_func;
    if (info->disassembler_options) {
	parse_etca_dis_options(info->disassembler_options);
	info->disassembler_options = NULL;
    }
    struct decode_info di = {
	    .insn = {},
	    .addr = addr,
	    .idx = 0,
	    .offset = 0,
	    .opc_info = NULL,
	    .format = ETCA_IF_ILLEGAL,
	    .params = {},
	    .argc = 0,
	    .args = {},
	    .size = -1,
	    .opcode = 0,
            .cond = {},
            .rex = {},
    };
    info->private_data = &di;


#define READ_BYTES(n)                                                             \
    do {                                                                          \
	if ((status = info->read_memory_func(di.addr + di.idx, &di.insn[di.idx], n, info))) { \
	    goto memory_error;                                                            \
	};									  \
	di.idx += n;                                                              \
    } while (0)

    READ_BYTES(1);
    while (1) {
	action = decode_insn(info, &di.insn[di.offset], (di.idx - di.offset));
	if (action == 0) { /* Instruction fully decoded */
	    break;
	} else if (action > 0) { /* We need this many more bytes*/
	    if (di.idx + action > MAX_INSTRUCTION_LENGTH) {
		fprs(stream, dis_style_text, "<illegal instruction, too long>");
		return di.idx + action;
	    }
	    if (di.addr + di.idx + action)
	    READ_BYTES(action);
	    continue; /* Try again */
	} else if (action == -2) { /* We finished a prefix */
	    di.offset = di.idx;
	    READ_BYTES(1);
	    continue; /* Parse the next prefix or the actual instruction */
	} else if (action == -3) { /* Memory error */
	    goto memory_error;
	} else if (action == -1) { /* Illegal instruction (or unrecognizable) */
	    fprs(stream, dis_style_text, "<unknown instruction>");
	    info->private_data = NULL;
	    return di.idx;
	}
    }

#define MATCH(a, di) ((a).format == (di).format \
       && ((a).params.uint & (di).params.uint) == (di).params.uint \
       && ((a).opcode == (di).opcode || (a).opcode == -1))

    for (struct beautifier *beautifier = beautifiers; beautifier->callback != NULL; beautifier++) {
	if (MATCH(*beautifier, di) && (beautifier->no_pseudo || !no_pseudo)) {
	    if (beautifier->callback(info)) {
		break;
	    }
	}
    }

    // if we found a conditional prefix and it wasn't beautified away; seek it and print it.
    if (di.cond.full) {
        bool found = false;
        for (struct etca_opc_info *opc_info = etca_opcodes; opc_info->name != NULL; opc_info++) {
            if (opc_info->format == ETCA_IF_COND_PRE && opc_info->opcode == di.cond.ccode) {
                fprs(stream, dis_style_sub_mnemonic, "%s ", opc_info->name);
                found = true;
                break;
            }
        }
        if (!found) abort();
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
		 "%s%c ", di.opc_info->name, di.size >= 0 ? etca_size_chars[di.size] : '?');
    } else {
	snprintf(buffer, sizeof(buffer), "%s", di.opc_info->name);
    }
    fprs(stream, dis_style_mnemonic, "%-7s ", buffer);

    for (size_t i = 0; i < di.argc; i++) {
	if (i != 0) { fprs(stream, dis_style_text, ", "); };
        if (di.args[i].kinds.predec || di.args[i].kinds.postinc) {
            fprs(stream, dis_style_text, "[%s",
                di.args[i].kinds.predec ? "--" : ""
            );
            fprs(stream, dis_style_register, "%%%s",
                get_reg_name(di.args[i].kinds.reg_class, di.args[i].as.reg, get_ptr_size())
            );
            fprs(stream, dis_style_text, "%s]",
                di.args[i].kinds.postinc ? "++" : ""
            );
        } else if (di.args[i].kinds.nested_memory || di.args[i].kinds.memory) {
            bool have_thing = false; // should we print a + before the next term?
            if (di.args[i].kinds.nested_memory) fprs(stream, dis_style_text, "[");
            fprs(stream, dis_style_text, "[");

            if (di.args[i].as.memory.iprel) {
                fprs(stream, dis_style_register, "%%ip%c", etca_size_chars[get_ptr_size()]);
                have_thing = true;
            }
            if (di.args[i].as.memory.base_reg >= 0) {
                fprs(stream, dis_style_register, "%%%s", get_reg_name(GPR, di.args[i].as.memory.base_reg, get_ptr_size()));
                have_thing = true;
            }
            if (di.args[i].as.memory.index_reg >= 0) {
                if (have_thing) fprs(stream, dis_style_text, " + ");
                fprs(stream, dis_style_text, "%" PRIu8 "*",
		     di.args[i].as.memory.scale);
                fprs(stream, dis_style_register, "%%%s",
                    get_reg_name(GPR, di.args[i].as.memory.index_reg, get_ptr_size()));
                have_thing = true;
            }
            if (di.args[i].kinds.dispAny) {
                int64_t disp = di.args[i].as.memory.disp;
                uint64_t pos_disp = (uint64_t)(-disp); // this way INT_MIN properly becomes INT_MAX+1
                if (disp >= 0) pos_disp = disp;
                if (have_thing) {
                    // if we have a term already, print a base-10 offset from that
                    if (disp >= 0) {
                        fprs(stream, dis_style_text, " + ");
                    }
                    if (disp < 0)      fprs(stream, dis_style_text, " - ");
                    fprs(stream, dis_style_address_offset, "%" PRIu64, pos_disp);
                } else {
                    // otherwise, this is a constant address; print it in hex at approprite width.
                    size_attr address_width = get_ptr_size();
                    uint64_t mask = (address_width == SA_QWORD) 
                        ? (uint64_t)-1 
                        : (1ULL << (1U << (address_width+3))) - 1;
                    fprs(stream, dis_style_address, "0x%" PRIx64, disp & mask);
                }

                if (di.args[i].as.memory.iprel || !have_thing) {
                    // print the target as a comment if this is an absolute or ip-relative address
                    // (but not if we have a base or index, then it's probably just an offset).
                    needs_addr_comment = &di.args[i].as.memory;
                }
            }
            fprs(stream, dis_style_text, "]");
            if (di.args[i].kinds.nested_memory) fprs(stream, dis_style_text, "]");
        } else if (di.args[i].kinds.reg_class != RegClassNone) {
	    fprs(stream, dis_style_register, "%%%s", get_reg_name(di.args[i].kinds.reg_class, di.args[i].as.reg, di.size));
	} else if (di.args[i].kinds.dispAny && di.opc_info && di.opc_info->size_info.args_size == LBL) {
	    info->print_address_func(di.args[i].as.imm, info);
	} else if (di.args[i].kinds.imm5z || di.args[i].kinds.imm8z
                    || (di.args[i].kinds.immAny
                        && di.opc_info->format == ETCA_IF_BASE_ABM
                        && ETCA_BASE_ABM_IMM_UNSIGNED(di.opcode))) {
	    fprs(stream, dis_style_immediate, "%" PRIu64, di.args[i].as.imm);
	} else if (di.args[i].kinds.immAny) {
	    fprs(stream, dis_style_immediate, "%" PRId64, (int64_t) di.args[i].as.imm);
	} else {
	    fprs(stream, dis_style_text, "<unknown operand>");
	}
    }

    if (needs_addr_comment) {
        // The idea here is to print the address and name of the symbol defined
        // there. But this doesn't seem to work for labels outside of the text
        // segment at all. I suspect this is a BFD deficiency. Regardless, x86
        // also doesn't print names in this situation, so I think we're SOL.
        /*
        bfd_vma target = needs_addr_comment->disp;
        asymbol *sym = NULL;
        // some memory operand had an address (lone displacement or was iprel).
        // Add a comment to display what was there.
        fprs(stream, dis_style_text, "\t; ");
        if (needs_addr_comment->iprel) {
            target += di.addr;
        }
        sym = info->symbol_at_address_func(target, info);
        if (sym) {
            fprs(stream, dis_style_address, "%ld ", target);
            fprs(stream, dis_style_text,    "<");
            fprs(stream, dis_style_symbol,  "%s", sym->name);
            fprs(stream, dis_style_text,    ">");
        } else {
            info->print_address_func(target, info);
        }
        */
    }

    info->private_data = NULL;
    return di.idx;
memory_error:
    info->memory_error_func(status, addr, info);
    info->private_data = NULL;
    return -1;
#undef READ_ONE_BYTE
#undef MATCH
}