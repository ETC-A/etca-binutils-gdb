
/* tc-etca.c -- Assemble code for ETCa
   Copyright 2023
   Free Software Foundation, Inc.

   This file is part of GAS, the GNU Assembler.

   GAS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GAS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GAS; see the file COPYING.  If not, write to
   the Free Software Foundation, 51 Franklin Street - Fifth Floor,
   Boston, MA 02110-1301, USA.  */


#include "as.h"
#include "safe-ctype.h"
#include "../../include/opcode/etca.h"
#include <assert.h>
#include <string.h>

/* A single operand to an ETCa instruction. Operands can be types of registers,
  immediates, displacements, or memory references. Some instructions have
  implicit operands (like push and pop). Those operands must be representable
  by this struct.

  We use the term "arg" in place of "operand" to prevent confusion with
  "opcode" and "operation" in abbreviations. */
struct etca_arg {
    struct etca_arg_kind kind;
    union {
	reg_num gpr_reg_num;
	reg_num ctrl_reg_num;
    } reg;
    int8_t reg_size;

    /* Contains the value of the imm.
     * When imm_expr.X_op == O_constant, we have a concrete value.
     * Otherwise, it's not resolved yet and we have to emit a fixup.
     * (We can emit a fixup anyway if we don't want to deal with it right now)
     * If need be, we can use imm_expr.X_md for our purposes.
     *
     * This field is also used for displacements.
     */
    struct expressionS imm_expr;

    struct etca_mem_arg {
	/* -1 if we don't have a base register. */
	reg_num base_reg;
	/* -1 if we don't have an index register. */
	reg_num index_reg;
	/* The (log) value of the scale. If there's no index_reg,
	    this _should_ be zero, but it also shouldn't matter. */
	unsigned char scale;
	/* Nonzero if we have an [ip+d] arg, zero otherwise. */
	unsigned char have_ip;
    } memory;
};

struct _rex_fields {
    uint8_t X:1;
    uint8_t B:1;
    uint8_t A:1;
    uint8_t Q:1;
};

typedef struct _rex_fields rex_fields;

/* The ETCa intra-line assembler state. Records information as we parse
and update it. Cleared at the start of md_assemble. */
struct _assemble_info {
    /* The opcode info that we found in the table. After the opcode lookup,
        you can be sure that this is non-null.
        The pointer is const because assembly lines should not be modifying the table! */
    const struct etca_opc_info *opcode;
    /* The size marker attached to the opcode, one of -1 (none),0 (h),1 (x),2 (d),3 (q).
        after compute_operand_size, this is the actual operand size attribute. */
    int8_t opcode_size; 
    union etca_opc_params_field params;
    size_t argc;
    struct etca_arg args[MAX_OPERANDS];

    bool imm_signed; // is an immediate to this instruction signed? don't-care if imm is not allowed.

    condition_code cond_prefix_code;
    bool cond_prefix_emitted;

    rex_fields rex;
    bool rex_initialized; // a canary bit to catch mistakes in tricky pseudos.
    bool rex_emitted; // a canary bit to catch critical mistakes emitting REX twice.
    // struct etca_prefix prefixes[MAX_PREFIXES]; // (or would it be better to have the indvidual prefixes seperated?
};

typedef struct _assemble_info assemble_info;

/* Info for the instruction we are currently assembling. */
static assemble_info ai;
#define CLEAR_AI \
do {\
    ai = (assemble_info){0};\
    ai.opcode_size = -1;\
} while (0)

// any half-decent compiler will optimize this the same as if we had used a union, so why bother?
#define NEED_REX() (ai.rex.Q || ai.rex.A || ai.rex.B || ai.rex.X)
/* Generically initialize the fields of `ai.rex' based on `ai.params.kinds' and `ai.args'.
 * REX.Q is untouched by this function - it used to be cleared, but this function is now
 * usually called much later and preserving REX.Q is valuable.
 * size (which might not be a simple decision - unclear?) must check that REX is enabled itself.
 * Since this function can only activate the register fields, you can be sure the result is
 * consistent with whether or not REX is enabled without otherwise checking.
 *  - rr: Assume index 0 is A and index 1 is B
 *  - ri: Assume index 0 is A. 
 *  - rc: Assume index 0 is A.
 *  - r: Assume A (which will be wrong for `push')
 *  - m: Assume memory.base_reg is B and memory.index_reg is X
 *  - mi: Ditto.
 *  - rm/mr: Ditto; then the register is assumed A.
 *  - if none of those (e.g. i, or params not computed for IF_SPECIAL), all (register)
 *    fields are cleared.
 */
static void generic_rex_init(void);
/* Assemble the REX info in `ai.rex' to the next frag byte, if a REX byte is needed. 
    otherwise, do nothing. Returns whether a REX byte was assembled. */
static bool assemble_rex_prefix(void);
/* Assemble the COND condition code in `ai.cond_prefix_code' to the next frag byte,
    if it's not ETCA_COND_ALWAYS. Otherwise, do nothing.
    Return whether a COND prefix was emitted. */
static bool assemble_cond_prefix(void);

// shortcuts for assembling register numbers into the A, B, SIBB, or SIBX fields
// of a byte.

// The offset of an 'A' register field in an ABM or SAF register jump format.
#define ETCA_A_OFS 5
// The offset of a 'B' register field in an ABM byte.
#define ETCA_B_OFS 2
// The offset of a 'B'[ase] register field in an SIB byte.
#define ETCA_SIBB_OFS 3
// The offset of an [inde]'X' register field in an SIB byte.
#define ETCA_SIBX_OFS 0
// Place the (bottom 3 bits of the) given register number into a byte
// at the given field.
#define DEPOSIT_REG(regnum, field) ((regnum & 7) << ETCA_ ## field ## _OFS)

/* Tables of character mappings for various contexts. 0 indicates that the character is not lexically that thing.
Initialized by md_begin. */
static char register_chars[256];
static char mnemonic_chars[256];

/* An opcode-assembler function.
Assembles a particular instruction family, using the information in `ai'.
Should confirm (or assert) that it actually handles that opcode.
Similarly, should confirm that the params_kind it got is expected. */
typedef void(*assembler)(void);

static int parse_extension_list(const char *extensions, struct etca_cpuid *out);

static int8_t parse_size_attr(char value);

static struct etca_reg_info *lookup_register_name_checked(char **str, int have_prefix);
static char *parse_register_name(char *str, struct etca_arg *result);

static char *parse_immediate(char *str, struct etca_arg *result);

static void  check_adr_size(int8_t adr_size);
static char *parse_memory_inner(char *str, struct etca_arg *result);
static char *parse_asp         (char *str, struct etca_arg *result);
static char *parse_memory_outer(char *str, struct etca_arg *result);

static char *parse_operand(char *str, struct etca_arg *result);

enum etca_code_model {
    /* The 'small' code model. All pointers can be represented by
        sign-extended 16-bit values, and any of those pointers can
        be used. There is no explicit support for position-independent
        code, and no guarantee that any value is accessible by a
        16-bit displacement from ipx from everywhere. However as long
        as the image size remainds under 32KB, this should just be true. */
    etca_model_small,
    /* The 'medany' code model. All pointers can be represented by
        sign-extended 32-bit values. The actual pointer values may
        be anywhere given that restriction, but every symbol is accessible
        by a 32-bit displacement from ipd, from anywhere in the code.
        If the image is too large to have this property (about 2GB),
        the linker will fail. */
    etca_model_medany,

    ETCA_NUM_CODE_MODELS,
    etca_model_invalid
};

typedef enum etca_code_model etca_code_model_type;

// as always, 1=x, 2=d, 3=q
// Remember, pointers may be wider than specified here on the actual
// architecture, but the promise is just that they can be represented
// by the sign extension of a value of this width.
uint8_t code_model_pointer_width[ETCA_NUM_CODE_MODELS] = {
    [etca_model_small] = 1,
    [etca_model_medany] = 2,
};

/* The known predefined archs. Needs to be kept in sync with gcc manually */
static struct etca_known_arch {
    const char *name;
    struct etca_cpuid cpuid;
    char is_concrete;
    etca_code_model_type default_code_model;
} known_archs[] = {
	/* unknown, the default. Also used when only -mextensions is used. */
	{"unknown", ETCA_CPI_BASE,              0, etca_model_small},
	/* base-isa with no predefined instructions */
	{"base",    ETCA_CPI_BASE,              1, etca_model_small},
	/* The core extension set: FI, SAF, INT, BYTE, EXOP, VON  */
	{"core",    MK_ETCA_CPI(0xF, 0x1, 0x1), 0, etca_model_small},
	{0, {0, 0, 0},                          0, etca_model_invalid}
};


#define MARCH_LEN 32
/*
 * The global settings for this backend. Set by the commandline options and modified
 * by the pseudos.
 */
struct etca_settings {
    /* The currently active cpuid. Can be modified by pseduo instructions */
    struct etca_cpuid current_cpuid;
    /* The name of the architecture given in the commandline or an empty string
     * Since the user might provide a custom name, we make a copy of it. */
    char march[MARCH_LEN];
    /* The original cpuid that corresponds to the march (without any additional -mextensions)*/
    struct etca_cpuid march_cpuid;
    /* The addition extensions specified via a `ARCH+ABBR...` or via `-mextensions` */
    struct etca_cpuid mextensions;

    etca_code_model_type code_model;
    /* Various fields*/
    uint32_t arch_name: 1; /* We got an explicit ARCH name */
    uint32_t custom_name: 1; /* We got a custom ARCH name */
    uint32_t manual_cpuid: 1; /* We got a -mcpuid. When not custom_name, this needs to exactly match the predefined one */
    uint32_t require_prefix: 1; /* Are % register prefixes required? (default yes) */
    uint32_t pedantic: 1; /* At the moment, just: Are sizes required on registers/opcodes? (default no) */
} settings = {
	.current_cpuid = ETCA_CPI_BASE,
	.march = "",
	.march_cpuid = ETCA_CPI_BASE,
	.mextensions = ETCA_CPI_BASE,
	.arch_name = 0,
	.custom_name = 0,
	.manual_cpuid = 0,
        .code_model = etca_model_invalid,
        .require_prefix = 1,
        .pedantic = 0,
};
// todo: use this more
#define CHECK_PAT(pat) etca_match_cpuid_pattern(&(pat), &settings.current_cpuid)

/* Determine the operand size for the parsed opcode and operands.
    If the opcode was suffixed, place that size in ai.opcode_size.
    The computed size is placed in ai.opcode_size. If we are unable
    to determine the operand size, as_bad is called and 1 is used. */
static int8_t compute_operand_size(void);
/* Validate the size of a (concrete) immediate operand. Before this
    is called, you should have already set imm{5/8}{s/z} appropriately,
    presumably in parse_immediate. You should also have already set
    `ai.opcode_size', presumably in compute_operand_size.
    It is checked that if there is an immediate which is _not_ imm8
    of the appropriate signedness, that it is within the bounds
    for a full-sized immediate of the given operation width.
    If the width is quad, and the immediate does not fit in 32 bits,
    and REX is available, then REX.Q is set. Otherwise,
    as_bad is called.  */
static void validate_conc_imm_size(void);

/* Compute a value for ai.params from the parsed ai.argc and ai.args. */
static bool compute_params(void);

static void process_mov_pseudo(void);
static void process_nop_pseudo(void);
static void process_hlt_pseudo(void);

static void assemble_base_abm(void);
static void assemble_exop_abm(void);
static void assemble_mtcr_misc(void);
static void assemble_base_jmp(void);
static void assemble_saf_call(void);
static void assemble_saf_jmp (void);
static void assemble_saf_stk (void);

static assembler pseudo_functions[ETCA_PSEUDO_COUNT] = {
	[ETCA_MOV] = process_mov_pseudo, /* mov */
	[ETCA_NOP] = process_nop_pseudo, /* nop */
	[ETCA_HLT] = process_hlt_pseudo, /* hlt */
};
static assembler format_assemblers[ETCA_IFORMAT_COUNT] = {
	[ETCA_IF_ILLEGAL] = 0, /* ILLEGAL */
	[ETCA_IF_SPECIAL] = 0, /* SPECIAL (handled via pseudo_functions) */
	[ETCA_IF_PSEUDO] = 0, /* PSEUDO (handled via pseudo_functions) */
	[ETCA_IF_BASE_ABM] = assemble_base_abm, /* BASE_ABM */
	[ETCA_IF_EXOP_ABM] = assemble_exop_abm, /* EXOP_ABM */
        [ETCA_IF_MTCR_MISC] = assemble_mtcr_misc, /* MISC (writecr RR) */
	[ETCA_IF_BASE_JMP] = assemble_base_jmp, /* BASE_JMP */
	[ETCA_IF_SAF_CALL] = assemble_saf_call, /* SAF_CALL */
	[ETCA_IF_SAF_JMP] = assemble_saf_jmp, /* SAF_JMP  */
	[ETCA_IF_SAF_STK] = assemble_saf_stk, /* SAF_STK  */
};

const char comment_chars[] = ";";
/* Additional characters beyond newline which should be treated as line separators.
  ETCa has none. */
const char line_separator_chars[] = "";
const char line_comment_chars[] = ";";

/* These are extra characters (beyond $ . _ and alphanum) which may appear
   in ETCa operands. % is a register prefix and [ is used for memory operands.
   We only need to give ones that might start operands. This affects the way in
   which GAS removes whitespace before passing the string to `md_assemble`. */
const char *tc_symbol_chars = "%[";

static int pending_reloc;
static htab_t opcode_hash_control;
static htab_t reg_hash_tbl;

const pseudo_typeS md_pseudo_table[] =
	{
		{0, 0, 0}
	};

/* Characters which indicate a floating point constant, 
   for example 0f0.5. */
const char FLT_CHARS[] = "rRsSfFdD";
/* Characters which may be used as the exponent char in a float number. */
const char EXP_CHARS[] = "eE";

/* parses a size char (one of "hxdq") into the correct size attribute for opcodes
 * Used in instruction postfixes and inside of register references.
 * Returns -1 if the char is not a valid size marker.
 */
static int8_t parse_size_attr(char value) {
    switch (value) {
	case 'h':
	    return 0b00;
	case 'x':
	    return 0b01;
	case 'd':
	    return 0b10;
	case 'q':
	    return 0b11;
    }
    return -1;
}

static struct etca_cpuid_pattern rex_pat = ETCA_PAT(REX);
static struct etca_cpuid_pattern cond_pat= ETCA_PAT(COND);
static struct etca_cpuid_pattern fi_pat  = ETCA_PAT(FI);
// static struct etca_cpuid_pattern mo1_pat = ETCA_PAT(MO1);
static struct etca_cpuid_pattern mo2_pat = ETCA_PAT(MO2);
static struct etca_cpuid_pattern exop_pat= ETCA_PAT(EXOP);
static struct etca_cpuid_pattern int_pat = ETCA_PAT(INT);
static struct etca_cpuid_pattern pm_pat  = ETCA_PAT(PM);
static struct etca_cpuid_pattern ci_pat  = ETCA_PAT(CI);
static struct etca_cpuid_pattern mode_pat =
    { .match_all=0,
      .pat = {
        .cpuid1 = ETCA_CP1_DWAS | ETCA_CP1_QWAS | ETCA_CP1_PG16 | ETCA_CP1_PG32
                | ETCA_CP1_PG48 | ETCA_CP1_PG57 | ETCA_CP1_PG64,
        .cpuid2 = 0,
        .feat   = 0
      }
    };

static struct etca_cpuid_pattern size_pats[4] = {
    ETCA_PAT(BYTE),
    ETCA_PAT(BASE),
    ETCA_PAT(DW),
    ETCA_PAT(QW)
};
static struct etca_cpuid_pattern any_size_pat =
    ETCA_PAT_OR3(BYTE, DW, QW);
static struct etca_cpuid_pattern any_vwi_pat =
    ETCA_PAT_OR6(FI, COND, REX, MO1, MO2, EXOP);

/* Lookup the given name (passed by pointer) as a register.
 * The name should have a '%' prefix stripped. Also say if there was a '%' prefix.
 *
 * The given string pointer is advanced past all consumed characters.
 * NULL is returned if and only if we should backtrack and try parsing an
 * expression instead (note that this can only happen if we don't have a prefix).
 * Otherwise, we return a usable etca_reg_info*.
 * 
 * as_bad is called if we are sure that the name is a mis-used or reserved register.
 * In these cases, we spoof an etca_reg_info to return so that parsing and error
 * discovery can continue.
 */
static struct etca_reg_info *lookup_register_name_checked(char **str, int have_prefix) {
    struct etca_reg_info *reg;
    // + 1 is needed for nul terminator
    char processed_str[MAX_REG_NAME_SIZE + 1];
    char *p;
    char *save_str = *str;
    static const char reserved_msg[] = "%%%s is a reserved register name";
    // msg + 2 skips the %% bit when we don't have a prefix.
    const char *reserved_fmt = have_prefix ? reserved_msg : (reserved_msg + 2);
    // We use this if we have to return a register after calling as_bad. Otherwise,
    // we'll try and backtrack even though we know we are supposed to
    // be looking at a register here.
    static struct etca_reg_info spoofed = { .name = "error-reg", .class=GPR, .aux.reg_size=-1 };

    // If we don't have a prefix, but prefixes are required, that's not an error.
    // What it actually means is that anything that might've looked like a register name
    // is in fact a valid label, so we should return NULL here and backtrack.
    if (!have_prefix && settings.require_prefix) return NULL;

    // start by lexically analyzing str. If it can't be a register name, don't bother.
    p = processed_str;
    while ((*p++ = register_chars[(unsigned char) **str]) != 0) {
        if (p > processed_str + MAX_REG_NAME_SIZE) goto not_a_reg;
        (*str)++;
    }
    // note after the loop, processed_str is nul terminated

    // once it's lexically analyzed, try looking that up...
    reg = str_hash_find(reg_hash_tbl, processed_str);

    if (!reg) {
not_a_reg:
        if (have_prefix) {
            char tmp;
            // advance *str until the next character isn't a register character.
            // Otherwise, we may find more "errors" that are actually because we split
            // a long bogus register name (like %nonsensenonsensenonsen) into two parts.
            while (register_chars[(unsigned char) **str] != 0) (*str)++;
            tmp = **str;
            **str = '\0';
            as_bad("Not a register name: %s", save_str);
            **str = tmp;
            return &spoofed;
        }
        // otherwise, no prefix, but prefixes aren't required, so just backtrack.
        return NULL;
    }

    // Determine if the register is valid in this context. If it's not, then
    // - GPR:  emit an error about the name being reserved
    // - CTRL: return NULL. (these are not intended to be portable)
    // But if it is, then we can simply return reg.
    switch (reg->class) {
    case GPR:
        // does that register (entity) exist with current cpuid?
        if (reg->reg_num >= 16
            || (reg->reg_num >= 8
                && !etca_match_cpuid_pattern(&rex_pat, &settings.current_cpuid))) {
            as_bad(reserved_fmt, reg->name);
            // if it doesn't exist, we shouldn't check sizes.
            return &spoofed;
        }
        // does that register size exist with current cpuid?
        if (reg->aux.reg_size == -1) {
            // no size marker. Fine unless we're being pedantic.
            if (settings.pedantic) {
                as_bad("[-pedantic] %s is missing a size marker", reg->name);
                return &spoofed;
            }
        }
        else if (!etca_match_cpuid_pattern(&size_pats[reg->aux.reg_size], &settings.current_cpuid)) {
            // we have a size, but it's not available in the cpuid.
            as_bad(reserved_fmt, reg->name);
            return &spoofed;
        }
        return reg;
    case CTRL:
        {
            static struct etca_cpuid_pattern *patterns[5] =
                {&mode_pat, 0, &int_pat, &ci_pat, &pm_pat};
            if (reg->aux.exts == -1) {
                // will lead to a check against MODE, however,
                // if more 'complex' checks are needed in the future,
                // it can be broken out fairly easily.
                assert(!strcmp(reg->name, "address_mode"));
            }
            else if (reg->aux.exts == 0) {
                return reg; // always valid
            }
            if (etca_match_cpuid_pattern(patterns[reg->aux.exts + 1], &settings.current_cpuid))
                return reg;
            // Otherwise we have a control register which is not valid in this CPUID.
            // We don't reserve control register names, so this is "not a register."
            goto not_a_reg;
        }
    default:
        abort();
    }
    return NULL; // this is impossible, but gcc doesn't know that abort doesn't return.
}

/* Parse a register (ISA, ABI, or Control, REX included) name into its numeric value and puts it into result,
 * setting the kind to one of GPR or CTRL and storing the correct register index.
 * Sets the size attr of the result according to the register parsed.
 * If it succeeds, the char* from which to continue parsing is returned.
 * If it fails to parse a register, but a '%' was present, as_bad is called.
 * Otherwise, NULL is returned, and you should try parsing a symbol instead.
 * (presumably with parse_immediate).
 */
static char *parse_register_name(char *str, struct etca_arg *result) {
    int have_prefix = 0;
    struct etca_reg_info *reg_info;

    // skip whitepsace
    while (ISSPACE(*str))
        str++;
    
    // Check for '%' prefix...
    if (*str == '%') {
        have_prefix = 1;
        str++;
    }

    // try lookup the name. If we don't find it, simply return null -
    // it's not a register, we should backtrack.
    // If we found a register which is erroneous in some way, errors are already
    // emitted and we're handed a "spoofed" register suitable for
    // continuing to seek errors.
    reg_info = lookup_register_name_checked(&str, have_prefix);
    if (!reg_info) return NULL;

    result->kind.reg_class = reg_info->class;
    // this sets ctrl reg nums correctly as well, as it is unioned with gpr_reg_num.
    result->reg.gpr_reg_num = reg_info->reg_num;
    if (reg_info->class == GPR) {
        // if the class is CTRL, this would set reg_size to the extension info...
        // it wouldn't really matter, because reg_size should be a don't-care for
        // control registers, but let's be defensive.
        result->reg_size = reg_info->aux.reg_size;
    } else if (reg_info->class == CTRL) {
        // If the class is CTRL, the size must be determined by something else.
        result->reg_size = -1;
    } else {
        // If we looked up a register and got something other than GPR or CTRL,
        // something is wrong in our lookup code - fail fast!
        abort();
    }

    return str;
}

/* Parse a potentially complex immediate expression and analyze it as far as possible.
 */
static char *parse_immediate(char *str, struct etca_arg *result) {
    char *save = input_line_pointer;
    input_line_pointer = str;
    expression(&result->imm_expr);
    str = input_line_pointer;
    input_line_pointer = save;
    int64_t  signed_value;
    uint64_t unsigned_value;

    switch (result->imm_expr.X_op) {
	case O_constant:
	    signed_value = (int64_t)result->imm_expr.X_add_number;
            unsigned_value = (uint64_t)signed_value;
	    result->kind.immAny = 1;
	    result->kind.immConc = 1;
            result->kind.imm5s = (-16 <= signed_value && signed_value < 16);
            result->kind.imm5z = (unsigned_value < 32);
            result->kind.imm8s = (-128 <= signed_value && signed_value < 128);
            result->kind.imm8z = (unsigned_value < 256);
	    break;
	case O_symbol:
	    result->kind.immAny = 1;
	    break;
	default:
	case O_illegal:
	case O_absent:
	    as_bad("Can't parse immediate expression");
	    return NULL;
    }

    result->reg_size = -1;
    return str;
}

// helpers for parsing memory_inner
static char *parse_ptr_register(char *str, struct etca_arg *result);

// impl helpers for parsing memory_inner
static char *parse_ptr_register(char *str, struct etca_arg *result) {
    str = parse_register_name(str, result);
    // not a register; indicate as such (and probably try something else).
    if (!str) return NULL;
    if (result->kind.reg_class == CTRL) {
        as_bad("invalid use of control register");
        result->reg.gpr_reg_num = 0;
        result->kind.reg_class = GPR;
        return str; // try to keep going as though we found a register.
    }
    // check address size is good
    check_adr_size(result->reg_size);
    return str;
}

/* Parse a non-nested memory location, setting the fields in result correctly.

    Only handles the simplest case of one register and no displacement for now.
 */
static char *parse_memory_inner(char *str, struct etca_arg *result) {
    struct etca_arg a_reg;

    // initialize the memory parameters as all absent.
    result->imm_expr.X_op = O_absent;
    result->memory.base_reg = -1;
    result->memory.index_reg = -1;

    str = parse_ptr_register(str, &a_reg);

    // if that wasn't a ptr register, or next isn't ']', give up:
    if (!str || *str != ']') {
        as_fatal("Generic memory location syntax not implemented");
        return NULL;
    }
    str++; // consume ']'

    result->memory.base_reg = a_reg.reg.gpr_reg_num;
    result->kind.memory = 1;
    result->reg_size = -1;

    return str;
}

/* Parse an ASP memory location. We accept both postdec and preinc grammatically
    for the purpose of rejecting them semantically with a better error message.
    The other ones still need to be checked for order, which process_mov_pseudo
    will handle.

    A return value of NULL indicates an error.
    A return value equal to the input str indicates that we should
    backtrack and try a regular MemoryInner.

 * ASP ::=
     | '++' REG ']'  { error }
     | '--' REG ']'  { predec $2 }
     | REG '++' ']'  { postinc $1 }
     | REG '--' ']'  { error }
 */
static char *parse_asp(char *str, struct etca_arg *result) {
    // TODO: Gas's scrubber currently turns `[%r0 + +]` into `[%r0++]`.
    // Decide: should that be allowed? If no, figure out how to fix.
    static const char *not_reg = "operand of `%s' must be a register";
    static const char *bad_op  = "`%s' of ptr register is not allowed";
    enum asp_ops {
        PREINC,
        PREDEC,
        POSTINC,
        POSTDEC
    };
    static const char *op_sym[4] = {
        "preinc", "predec", "postinc", "postdec"
    };
    enum asp_ops op;
    char *backtrack = str;
    bool got_register = true;

    // if ASP isn't available, backtrack immediately.
    if (!(settings.current_cpuid.cpuid1 & ETCA_CP1_ASP)) {
        return backtrack;
    }

    if (*str == '+' && *(str+1) == '+') {
        op = PREINC;
        str = parse_register_name(str+2, result);
        // if we didn't get a register, wait to return until we're
        // done searching for a closing ']'.
        if (!str || result->kind.reg_class != GPR) {
            as_bad(not_reg, op_sym[op]);
            got_register = false;
        }
    } else if (*str == '-' && *(str+1) == '-') {
        op = PREDEC;
        str = parse_register_name(str+2, result);
        if (!str || result->kind.reg_class != GPR) {
            as_bad(not_reg, op_sym[op]);
            got_register = false;
        }
        result->kind.predec = 1;
    } else {
        str = parse_register_name(str, result);
        // in this case it might just be a regular memory operand,
        // so definitely don't call as_bad. We can't check for postinc
        // or postdec here since we don't know how much parse_register_name
        // tried to consume.
        if (!str) return backtrack;
        // otherwise check for postinc/postdec. If it's not one of those,
        // it's still not an error... just backtrack.
        if (*str == '+' && *(str+1) == '+') {
            op = POSTINC;
            str += 2;
            result->kind.postinc = 1;
        } else if (*str == '-' && *(str+1) == '-') {
            op = POSTDEC;
            str += 2;
        } else {
            return backtrack;
        }
        if (result->kind.reg_class != GPR) {
            as_bad(not_reg, op_sym[op]);
            got_register = false;
        }
    }

    // if we did get a register, ensure the size agrees with address.
    if (got_register) {
        check_adr_size(result->reg_size);
        // we're later going to run this past an opr_opr check,
        // if it is indeed a mov pseudo, so don't let a ptr size
        // fail an opr check!
        result->reg_size = -1;
    }

    // ensure that result is an acceptable spoof before
    // we go onto returning (potentially with a recoverable error).
    // That means: it does **not** say this is a register,
    // or in fact anything at all except possibly a true
    // predec/postinc. Anything else may cause or prevent
    // params kinds check errors incorrectly.
    // Leave the register in the reg.gpr_reg_num field for convenience though.
    result->kind.reg_class = 0;

    if (*str != ']') {
        char *end = str;
        as_bad("generic memory operands cannot contain ASP syntax");
        // search for a ']' or ',' and proceed from there. If we can't find one... rip.
        while (*++str != ']' && *str != ',' && *str != '\0') {}
        if (*str == '\0') return end;
        if (*str == ',') return str;
        return str+1; // found ']', consume it
    }
    str++; // consume ']'

    // if we didn't actually get a register, quit now.
    if (!got_register) {
        return str;
    }

    // otherwise we've successfully parsed an ASP operand. Check
    // that it's one of the ops that's actually legal...
    if (op == PREINC || op == POSTDEC) {
        as_bad(bad_op, op_sym[op]);
        return str;
    }

    return str;
}

/* Grammar:
 * Operand ::= '[' MemoryOuter | ...
 * MemoryOuter ::=
    | ASP
    | MemoryInner
    | '[' MemoryInner ']'

   Note that ASP and MemoryInner both consume the trailing ']'.
 */
static char *parse_memory_outer(char *str, struct etca_arg *result) {
    // ASP and MEM have some grammatical overlap; rather than trying to
    // factor it (which is tricky but possible), ASP just backtracks
    // if it fails.
    char *start_str = str;

    if (*str == '[') {
        str++;
        str = parse_memory_inner(str, result);
        if (*str == ']') {
            str++;
        } else {
            as_bad("unmatched '['");
        }
        result->kind.nested_memory = result->kind.memory;
        result->kind.memory = 0;
        return str;
    }

    str = parse_asp(str, result);
    // if str is NULL, we found an error, return NULL.
    // if str is start_str, don't return that though - then we backtrack.
    if (!str || str != start_str) return str;

    return parse_memory_inner(start_str, result);
}

/* Parse an arbitrary component, deferring to the correct parse_* function.
 */
char *parse_operand(char *str, struct etca_arg *result) {
    while (ISSPACE(*str)) str++;
    switch (*str) {
	case '[':
	    str++;
	    return parse_memory_outer(str, result);
	default: {
            char *save_str = str;
            // Try parsing a register name...
	    str = parse_register_name(str, result);
            // if that succeeded, we're done.
            if (str) return str;
            // Otherwise, backtrack and try parsing an immediate.
            // Any register-related errors have already been raised.
	    return parse_immediate(save_str, result);
	}
    }
}

void
md_operand(expressionS *op __attribute__((unused))) {
    /* Empty for now. */
}


/* This function is called once, at assembler startup time.  It sets
   up the hash table with all the opcodes in it, and also initializes
   some aliases for compatibility with other assemblers.  */
void
md_begin(void) {
    struct etca_opc_info *opcode;
    struct etca_opc_info *prev = NULL;
    const struct etca_reg_info *reg;
    int c;

    opcode_hash_control = str_htab_create();

    /* Insert opcodes into hash table.  */
    for (opcode = etca_opcodes; opcode->name != 0; opcode++) {
	struct etca_opc_info *old_opcode = str_hash_find(opcode_hash_control, opcode->name);
	if (old_opcode) {
	    if (!prev || strcmp(prev->name, opcode->name) != 0) {
		abort();
	    }
	    prev->try_next_assembly = 1;
	} else {
	    str_hash_insert(opcode_hash_control, opcode->name, opcode, 1);
	}
	prev = opcode;
    }
    bfd_set_arch_mach(stdoutput, TARGET_ARCH, 0);

    /* Insert registers into hash table. */
    reg_hash_tbl = str_htab_create();
    for (reg = etca_registers; reg->name != 0; reg++) {
        // check if we have duplicated a register by mistake in the table
        struct etca_reg_info *old_reg = str_hash_find(reg_hash_tbl, reg->name);
        if (old_reg) as_fatal("duplicate (%s)", reg->name);
        str_hash_insert(reg_hash_tbl, reg->name, reg, 1);
    }

    /* Fill in lexical tables. */
    for (c = 0; c < 256; c++) {
        if (ISDIGIT(c) || ISLOWER(c)) {
            register_chars[c] = c;
            mnemonic_chars[c] = c;
        }
        else if (ISUPPER(c)) {
            // make register names case-insensitive. Do we want that?
            register_chars[c] = TOLOWER(c);
            mnemonic_chars[c] = register_chars[c];
        }
    }
    register_chars['_'] = '_';
}

/* Based on the list of parsed arguments, correctly set ai.params.
 * If the list of parsed arguments doesn't match a known params kind,
 * no fields are set, as_bad is **not** called, and false is returned.
 */
bool compute_params(void) {
#define IS_REG(arg) ((arg).kind.reg_class == GPR)
#define IS_CTRL_REG(arg) ((arg).kind.reg_class == CTRL)
#define IS_IMM(arg) ((arg).kind.immAny) // this covers it unless parse_immediate screws up.
#define IS_SPECIAL(arg) ((arg).kind.nested_memory || (arg).kind.predec || (arg.kind.postinc))
    /* This can probably be solved better... */
    if (ai.argc == 0) {
	ai.params.kinds.e = 1;
	return true;
    } else if (ai.argc == 1) {
	if (IS_SPECIAL(ai.args[0]) || IS_CTRL_REG(ai.args[0])) {
	    return false;
	}
	if (IS_REG(ai.args[0])) {
	    ai.params.kinds.r = 1;
	    return true;
	} else if (IS_IMM(ai.args[0])) {
	    ai.params.kinds.i = 1;
	    return true;
	} else {
	    abort(); // incomplete matching
	}
    } else if (ai.argc == 2) {
	if (IS_SPECIAL(ai.args[0]) || IS_SPECIAL(ai.args[1])) {
	    return false;
	}
	if (IS_REG(ai.args[0])) {
	    if (IS_IMM(ai.args[1])) {
		ai.params.kinds.ri = 1;
		return true;
	    } else if (IS_REG(ai.args[1])) {
		ai.params.kinds.rr = 1;
		return true;
            } else if (IS_CTRL_REG(ai.args[1])) {
                ai.params.kinds.rc = 1;
                return true;
	    } else {
		abort(); // incomplete matching
	    }
	} else if (IS_IMM(ai.args[0]) || IS_CTRL_REG(ai.args[0])) {
            return false; // not feasible
	} else {
            abort(); // incomplete matching
	}
    } else {
	abort(); // argc not in [0,1,2]?
    }
#undef IS_REG
#undef IS_IMM
#undef IS_SPECIAL
}

/* This is the guts of the machine-dependent assembler.  STR points to
   a machine dependent instruction.  This function is supposed to emit
   the frags/bytes it assembles to.  */

void
md_assemble(char *str) {
    char *save_str = str; // for error messages
    char *opc_p; // for scanning
    char processed_opcode[MAX_MNEM_SIZE + 1]; // the scanned opcode

    // First stop: reset ai. Any information from the last insn is now bad.
    CLEAR_AI;

    /* Drop leading whitespace.  */
    while (ISSPACE(*str)) str++;

    /* Scan an opcode. */
    opc_p = processed_opcode;
    while ((*opc_p++ = mnemonic_chars[(unsigned char) *str]) != 0) {
        if (opc_p > processed_opcode + MAX_MNEM_SIZE) goto not_an_opcode;
        str++;
    }
    // note after the loop, processed_str is nul terminated

    // There might be a size indicator on the opcode, or there might not.
    // We could handle this by putting all opcodes with and without them into the table,
    // but this is actually for more trouble than it's worth as the table becomes quite
    // messy with exactly what has to be where since same-name opcodes must be adjacent.
    
    // first: check assuming no size.
    ai.opcode = str_hash_find(opcode_hash_control, processed_opcode);
    if (!ai.opcode) {
        char size;
        // we might have failed to find an entry because it actually ended with a size.
        // In that case, opc_p is pointing one past the NUL, so bring it back...
        opc_p -= 2;
        size = *opc_p;
        *opc_p = '\0'; // delete the size from processed_opcode...
        // and try looking up that instead.
        ai.opcode = str_hash_find(opcode_hash_control, processed_opcode);
        // restore the size to processed_opcode, in case of error.
        *opc_p = size;
        // if the second lookup succeeded, check if a size suffix was not allowed
        // or if the given suffix was bad (in general or in this context).
        if ( ai.opcode 
            && (!ai.opcode->size_info.suffix_allowed
                || (ai.opcode_size = parse_size_attr(size)) < 0
                || !etca_match_cpuid_pattern(&size_pats[ai.opcode_size], &settings.current_cpuid))) {
            // If that's the case, this isn't an opcode.
            ai.opcode = NULL;
        }
    }

    // reporting errors if we couldn't find any/a valid opcode...
    if (processed_opcode[0] == 0) {
	as_bad(_("can't find opcode")); // this might happen if a line is just %, for example.
	return;
    }
    if (ai.opcode == NULL) {
not_an_opcode:
        // str may not be advanced to the end of the opcode yet.
        while (mnemonic_chars[(unsigned char) *str] != 0) str++;
        *str = '\0';
	as_bad(_("unknown opcode %s"), save_str);
	return;
    }
    // we've pulled up the first opcode entry. But this one might not be
    // valid. We must try to find one which is enabled (ignorant of params).
    // If none are enabled, we have an unknown opcode (and need to jump back).
    {
        bool opcode_enabled = false;
        const struct etca_opc_info *sweep = ai.opcode;
        do {
            if (etca_match_cpuid_pattern(&sweep->requirements, &settings.current_cpuid)) {
                opcode_enabled = true;
                break;
            }
        } while ((sweep++)->try_next_assembly);
        if (!opcode_enabled) goto not_an_opcode;
    }

    // beyond this point, we are guaranteed that ai.opcode is valid!

    // check for opcode suffix pedantically
    if (settings.pedantic && ai.opcode->size_info.suffix_allowed && ai.opcode_size == -1) {
        as_bad("[-pedantic] no size suffix given for `%s'", ai.opcode->name);
    }
    // but if we don't have any size extensions, allow a default of word.
    // FIXME: this check happens on every line and should probably be cached in settings.
    if (ai.opcode->size_info.suffix_allowed &&
        !etca_match_cpuid_pattern(&any_size_pat, &settings.current_cpuid)) {
        ai.opcode_size = 1;
    }

    if (ai.opcode->format == ETCA_IF_ILLEGAL) {
	as_bad("Illegal opcode %s", processed_opcode);
	return;
    }

    while (ISSPACE(*str)) str++;
    while (*str != '\0' && ai.argc < MAX_OPERANDS) {
	char *arg_end = parse_operand(str, &ai.args[ai.argc]);
	if (!arg_end) {
	    as_bad("Expected an argument");
	    return;
	}
	str = arg_end;
	ai.argc++;
	while (ISSPACE(*str)) str++;
        // when we hit MAX_OPERANDS, don't consume the comma. We can use
        // it to get a better error message in a moment.
	if (*str != ',' || ai.argc == MAX_OPERANDS) break;
	str++;
	while (ISSPACE(*str)) str++;
    }
    if (*str == ',') {
        as_bad("too many operands (maximum is 2)");
    }

    assembler assembly_function;
    // compute params kind.
    // Note there's an important secondary function here: checking that
    // we have the right _number_ of params. For special, we **must**
    // check this as a special case, or else we will hit gas assert
    // failures when we try to compute the operand size.
    if (ai.opcode->format != ETCA_IF_SPECIAL) {
        // if we don't have a feasible list of params, this simply
        // doesn't set any fields of `ai.params.kinds'. Then the
        // operand/param matching loop below will tell us to say
        // "bad operands."
	compute_params();

	uint32_t bit_to_test = ai.params.uint;
	while (
		((ai.opcode->params.uint & bit_to_test) == 0
		 || !etca_match_cpuid_pattern(&ai.opcode->requirements, &settings.current_cpuid))
		&&
		ai.opcode->try_next_assembly) {
	    ai.opcode++;
	}
	if ((ai.opcode->params.uint & bit_to_test) != bit_to_test
	    || !etca_match_cpuid_pattern(&ai.opcode->requirements, &settings.current_cpuid)) {
            as_bad("bad operands for `%s'", ai.opcode->name);
	    return;
	}

        // not special and is valid: are immediates signed?
        ai.imm_signed = ai.opcode->format != ETCA_IF_BASE_ABM || ETCA_BASE_ABM_IMM_SIGNED(ai.opcode->opcode);
    } else {
        // it is special.
        if (ai.opcode->opcode == ETCA_MOV && ai.argc != 2) {
            as_bad("bad operands for `mov'");
            return;
        }
    }

    // compute size attr even for IF_SPECIAL (something is wrong with the
    // syntax if the operands of a name are overloaded).
    compute_operand_size();
    // note that this does not do _anything at all_ for `mov'!
    validate_conc_imm_size();
    // I tried putting this here but it turned out to be simpler to just let the format_assemblers do it.
    // generic_rex_init();

    if (ai.opcode->format == ETCA_IF_SPECIAL || ai.opcode->format == ETCA_IF_PSEUDO) {
	assembly_function = pseudo_functions[ai.opcode->opcode];
    } else {
	assembly_function = format_assemblers[ai.opcode->format];
    }
    if (!assembly_function) {
	as_fatal("Missing for %s (%d)\n", ai.opcode->name, ai.opcode->format);
	return;
    }
    assembly_function();


    while (ISSPACE(*str)) str++;
    if (*str != 0)
	as_warn("extra stuff on line ignored");

    if (pending_reloc)
	as_bad("Something forgot to clean up\n");
}

/* Turn a string in input_line_pointer into a floating point constant
   of type type, and store the appropriate bytes in *LITP.  The number
   of LITTLENUMS emitted is stored in *SIZEP .  An error message is
   returned, or NULL on OK.  */

const char *
md_atof(int type, char *litP, int *sizeP) {
    int prec;
    LITTLENUM_TYPE words[4];
    char *t;
    int i;

    switch (type) {
	case 'f':
	    prec = 2;
	    break;

	case 'd':
	    prec = 4;
	    break;

	default:
	    *sizeP = 0;
	    return _("bad call to md_atof");
    }

    t = atof_ieee(input_line_pointer, type, words);
    if (t)
	input_line_pointer = t;

    *sizeP = prec * 2;

    for (i = prec - 1; i >= 0; i--) {
	md_number_to_chars(litP, (valueT) words[i], 2);
	litP += 2;
    }

    return NULL;
}

const char *md_shortopts = "";

/* We provide the following possible ways to specify a specifc set of extensions.
 * This needs to be kept in sync with the gcc code manually.
 *  -march=name                  (name being either a predefined name or a custom one)
 *  -march=cpuid:CP1.CP2.FEAT    (hex notation of the CPUID, name is the hexid)
 *  -march=extensions:ABBR(,ABBR)*    (name defaults to `base`)
 *  the first two options can also have a `+ABBR(,ABBR)*` postfix which adds those
 *  extensions on top of the predefined set.
 *  Having an extension mentioned multiple times is not a problem.
 *  There is also `-mcpuid:CP1.CP2.FEAT` which is a shortcut for -march=cpuid
 *  that doesn't support extensions. (and conflicts with -march)
 *  -mextensions=ABBR(,ABBR)* can be added to all of these options as well.
 *
 *  Using a custom name is supported to make it for people creating custom implementations
 *  to use a name for their architecture in the Makefiles which will get reflected in
 *  error messages without having to change the source code of gas. Note that when a name
 *  does get added to gas, it will then be an error to have a mismatch between the given
 *  -mcpuid and the one provided by the predefined name.
 */

enum options {
    OPTION_MARCH = OPTION_MD_BASE,
    // OPTION_MTUNE, // Not supported yet
    OPTION_MEXTENSIONS,
    OPTION_MCPUID,
    OPTION_MCMODEL,
    // OPTION_MPTR, // do we want this? what's the syntax?
    OPTION_NOPREFIX,
    OPTION_PEDANTIC,
};

struct option md_longopts[] =
	{
		{"march",       required_argument, NULL, OPTION_MARCH},
		{"mextensions", required_argument, NULL, OPTION_MEXTENSIONS},
		{"mcpuid",      required_argument, NULL, OPTION_MCPUID},
                {"mcmodel",     required_argument, NULL, OPTION_MCMODEL},
                {"pedantic",    no_argument,       NULL, OPTION_PEDANTIC},
                {"noprefix",    no_argument,       NULL, OPTION_NOPREFIX},
		{NULL,          no_argument,       NULL, 0},
	};
size_t md_longopts_size = sizeof(md_longopts);

/* Parses a comma seperated list of extension abbreviations */
static int parse_extension_list(const char *extensions, struct etca_cpuid *out) {
    const struct etca_extension *ext;
    while (ISSPACE(*extensions)) extensions++;
    while (*extensions != '\0') {
	const char *end = strchr(extensions, ',');
	if (end == NULL) {
	    for (ext = etca_extensions; ext->name != NULL; ext++) {
		if (strcmp(extensions, ext->name) == 0) {
		    out->cpuid1 |= ext->cpi.cpuid1;
		    out->cpuid2 |= ext->cpi.cpuid2;
		    out->feat |= ext->cpi.feat;
		    break;
		}
	    }
	    if (ext->name == NULL) {
		as_bad("Unknown extension abbreviation %s", extensions);
		return 0;
	    }
	    break;
	} else {
	    for (ext = etca_extensions; ext->name != NULL; ext++) {
		if (strncmp(extensions, ext->name, (end - extensions)) == 0) {
		    out->cpuid1 |= ext->cpi.cpuid1;
		    out->cpuid2 |= ext->cpi.cpuid2;
		    out->feat |= ext->cpi.feat;
		    break;
		}
	    }
	    if (ext->name == NULL) {
		as_bad("Unknown extension abbreviation %.*s", (int) (end - extensions), extensions);
		return 0;
	    }
	    extensions = end + 1;
	}
	while (ISSPACE(*extensions)) extensions++;
    }
    return 1;
}

static int parse_hex_cpuid(const char *hex_cpuid, struct etca_cpuid *out) {
    char *a;
    char *b;
    uint64_t values[3];
    gas_assert(sizeof(unsigned long long) == sizeof(uint64_t));
    values[0] = strtoull(hex_cpuid, &a, 16);
    if (hex_cpuid == a || a[0] != '.') {
	as_bad("CPUIDs need to be three dot-seperated hex numbers");
	return 0;
    }
    values[1] = strtoull(a + 1, &b, 16);
    if (a + 1 == b || b[0] != '.') {
	as_bad("CPUIDs need to be three dot-seperated hex numbers");
	return 0;
    }
    values[2] = strtoull(b + 1, &a, 16);
    if (b + 1 == a) {
	as_bad("CPUIDs need to be three dot-seperated hex numbers");
	return 0;
    }
    out->cpuid1 |= values[0];
    out->cpuid2 |= values[1];
    out->feat |= values[2];
    return 1;
}

static int parse_code_model(const char *cmodel, etca_code_model_type *out) {
    if (strcmp(cmodel, "small") == 0) {
        *out = etca_model_small;
        return 1;
    }
    else if (strcmp(cmodel, "medany") == 0) {
        as_warn("selected code model `medany' is unstable and untested");
        *out = etca_model_medany;
        return 1;
    }
    as_bad("Unknown code model `%s'", cmodel);
    return 0;
}

int
md_parse_option(int c, const char *arg) {
    switch (c) {
	case OPTION_MARCH: {
	    if (settings.arch_name) {
		as_warn("Duplicate -march parameter. Ignoring repeated instance");
		return 1;
	    }
	    if (strncmp(arg, "extensions:", strlen("extensions:")) == 0) {
		arg += strlen("extensions:");
		return parse_extension_list(arg, &settings.mextensions);
	    }
	    settings.arch_name = 1;
	    /* We only actually analyze the name in etca_after_parse_args*/
	    const char *after_name = strchr(arg, '+');
	    if (after_name == NULL) {
		settings.march[MARCH_LEN - 1] = '\0';
		strncpy(settings.march, arg, MARCH_LEN - 1);
		if (settings.march[MARCH_LEN - 1] != '\0') {
		    as_warn("Architecture name too long, truncating");
		    settings.march[MARCH_LEN - 1] = '\0';
		}
		return 1;
	    } else { /* we have a list of extensions */
		if (after_name - arg >= MARCH_LEN) {
		    as_warn("Architecture name too long, truncating");
		    strncpy(settings.march, arg, MARCH_LEN - 1);
		    settings.march[MARCH_LEN - 1] = '\0';
		} else {
		    strncpy(settings.march, arg, after_name - arg);
		    settings.march[after_name - arg] = '\0';
		}
		return parse_extension_list(after_name + 1, &settings.mextensions);
	    }
	}
	case OPTION_MEXTENSIONS:
	    return parse_extension_list(arg, &settings.mextensions);
	case OPTION_MCPUID:
	    strncpy(settings.march, arg, MARCH_LEN - 1);
	    return parse_hex_cpuid((char *) arg, &settings.march_cpuid);
        case OPTION_MCMODEL:
            if (settings.code_model != etca_model_invalid) {
                as_warn("Multiple code models specified; choosing the last one");
            }
            return parse_code_model(arg, &settings.code_model);
        case OPTION_NOPREFIX:
            settings.require_prefix = 0;
            return 1;
        case OPTION_PEDANTIC:
            settings.pedantic = 1;
            return 1;
	default:
	    return 0;
    }
}

void
md_show_usage(FILE *stream) {
    // match the format of usage output for default options
    fprintf (stream, "ETCa-specific assembler options:\n");
    fprintf (stream, "  -march=name[+ABBR...]\n");
    fprintf (stream, "\t\t\t  Specify an architecture name as well as optionally\n");
    fprintf (stream, "\t\t\t  a list of extensions implemented on top of it\n");
    fprintf (stream, "  -mextensions=ABBR[,ABBR...]\n");
    fprintf (stream, "\t\t\t  Specify an architecture via a list of extensions\n");
    fprintf (stream, "  -mcpuid=CP1.CP2.FT\t  Specify an architecture via a CPUID triplet\n");
    fprintf (stream, "  -mcmodel={small|medany} Specify a code model. Overrides any arch default.\n");
    fprintf (stream, "\t\t\t  `medany' is only available with DW and DWAS. Recommend MO2.\n");
    fprintf (stream, "  -noprefix\t\t  Allow register names without the '%%' prefix\n");
    fprintf (stream, "  -pedantic\t\t  Enable various forms of pedantry; at the moment,\n");
    fprintf (stream, "\t\t\t  only checks that opcodes and registers have size markers\n");
}

/* Check that our arguments, especially the given -march and -mcpuid make sense*/
void etca_after_parse_args(void) {
    struct etca_cpuid temp_cpuid;
    bool is_concrete = true;
    if(settings.arch_name) {
	if (strncmp(settings.march, "cpuid:", strlen("cpuid:")) == 0) {
	    memmove(settings.march,
		    settings.march + strlen("cpuid:"),
		    strlen(settings.march) + 1 - strlen("cpuid:"));
	    parse_hex_cpuid(settings.march, &temp_cpuid);
	    is_concrete = true;
	} else {
	    for (struct etca_known_arch *arch = known_archs; arch->name != NULL; arch++) {
		if (strcmp(arch->name, settings.march) == 0) {
		    is_concrete = arch->is_concrete;
		    temp_cpuid = arch->cpuid;
                    // if the code model is already set, it overrides us; otherwise apply default.
                    if (settings.code_model == etca_model_invalid) {
                        settings.code_model = arch->default_code_model;
                    }
		    break;
		}
	    }
	}
	if (is_concrete && settings.manual_cpuid) {
	    if (settings.march_cpuid.cpuid1 != temp_cpuid.cpuid1
		|| settings.march_cpuid.cpuid2 != temp_cpuid.cpuid2
		|| settings.march_cpuid.feat != temp_cpuid.feat) {
		as_warn("Manually given -mcpuid does not exactly match the one predefined by the -march name given. Combining the two");
	    }
	}
	settings.march_cpuid.cpuid1 |= temp_cpuid.cpuid1;
	settings.march_cpuid.cpuid2 |= temp_cpuid.cpuid2;
	settings.march_cpuid.feat |= temp_cpuid.feat;
    }

    settings.current_cpuid.cpuid1 |= settings.mextensions.cpuid1 | settings.march_cpuid.cpuid1;
    settings.current_cpuid.cpuid2 |= settings.mextensions.cpuid2 | settings.march_cpuid.cpuid2;
    settings.current_cpuid.feat |= settings.mextensions.feat | settings.march_cpuid.feat;

    // Checks on code model. Warn if one is not specified. Ensure it is consistent with extensions.
    if (settings.code_model == etca_model_invalid) {
        // warn the user that this is happening, because it is likely to break code expecting
        // to have a reasonable amount of memory.
        as_tsktsk("No code model default available and none specified. Choosing `small'.");
        settings.code_model = etca_model_small;
    }
    if (settings.code_model == etca_model_medany) {
        static const struct etca_cpuid_pattern medany_pat = ETCA_PAT_AND2(DW, DWAS);
        if (!CHECK_PAT(medany_pat)) {
            as_fatal("Selected code model `medany' is only available with DW and DWAS.");
        } 
        if (!CHECK_PAT(mo2_pat)) {
            as_warn("Selected code model `medany' may be unlinkable without IP-relative addressing.");
        }
    }
}

/* Apply a fixup to the object file.  */

void
md_apply_fix(fixS *fixP ATTRIBUTE_UNUSED, valueT *valP ATTRIBUTE_UNUSED, segT seg ATTRIBUTE_UNUSED) {
}

/* Translate internal representation of relocation info to BFD target
   format.  */

arelent *
tc_gen_reloc(asection *section ATTRIBUTE_UNUSED, fixS *fixp) {
    arelent *rel;
    bfd_reloc_code_real_type r_type;

    rel = xmalloc(sizeof(arelent));
    rel->sym_ptr_ptr = xmalloc(sizeof(asymbol * ));
    *rel->sym_ptr_ptr = symbol_get_bfdsym(fixp->fx_addsy);
    rel->address = fixp->fx_frag->fr_address + fixp->fx_where;

    r_type = fixp->fx_r_type;
    rel->addend = fixp->fx_offset;
    rel->howto = bfd_reloc_type_lookup(stdoutput, r_type);

    if (rel->howto == NULL) {
	as_bad_where(fixp->fx_file, fixp->fx_line,
		     _("Cannot represent relocation type %s (%d)"),
		     bfd_get_reloc_code_name(r_type), r_type);
	/* Set howto to a garbage value so that we can keep going.  */
	rel->howto = bfd_reloc_type_lookup(stdoutput, BFD_RELOC_32);
	assert(rel->howto != NULL);
    }

    return rel;
}

static void generic_rex_init(void) {
// critical that this says "no" for -1, so can't just test some bits
#define IS_REX_REG(regnum) (8 <= (regnum) && (regnum) < 16)
    // indicate initialized since every good case wants that;
    // clear it again at the end if we missed every case.
    ai.rex_initialized = true;
    // It'd be nice to use a switch for this, but we can't rely on bitfield order.
    // Even if we could, it'd break if there were ever two kinds set. So, try
    // to check in order of commonality.
    // optimization note: I imagine branch prediction is quite good here anyway.
    if (ai.params.kinds.rr) { /* A, B */
        ai.rex.A = IS_REX_REG(ai.args[0].reg.gpr_reg_num);
        ai.rex.B = IS_REX_REG(ai.args[1].reg.gpr_reg_num);
        return;
    }
    if (ai.params.kinds.ri || ai.params.kinds.rc || ai.params.kinds.r) { /* A,- */
        ai.rex.A = IS_REX_REG(ai.args[0].reg.gpr_reg_num);
        return;
    }
    // if (ai.params.kinds.i) {} // don't initialize in this case; right now
    // only push could even cause this, and it should've already adjusted `kinds'.
    // Rather make sure we get an error.
    if (ai.params.kinds.rm || ai.params.kinds.mr) { /* r is A */
        size_t idx = ai.params.kinds.mr; // register is at 1 iff mr
        ai.rex.A = IS_REX_REG(ai.args[idx].reg.gpr_reg_num);
    }
    if (ai.params.kinds.rm || ai.params.kinds.mr
        || ai.params.kinds.mi || ai.params.kinds.m) { /* base:B, index:X */
        size_t idx = ai.params.kinds.rm; // mem is at 0 unless rm
        ai.rex.B = IS_REX_REG(ai.args[idx].memory.base_reg);
        ai.rex.X = IS_REX_REG(ai.args[idx].memory.index_reg);
        return;
    }

    ai.rex.A = ai.rex.B = ai.rex.X = 0;
    ai.rex_initialized = false;
#undef IS_REX_REG
}

static bool assemble_cond_prefix(void) {
    gas_assert(!ai.cond_prefix_emitted);
    gas_assert(!ai.rex_emitted); // enforce order
    if (ai.cond_prefix_code == ETCA_COND_ALWAYS) return false;

    gas_assert((ai.cond_prefix_code & 0x0F) == ai.cond_prefix_code);
    *frag_more(1) = 0xA0 | ai.cond_prefix_code;
    ai.cond_prefix_emitted = true;
    return true;
}

static bool assemble_rex_prefix(void) {
    gas_assert(ai.rex_initialized && !ai.rex_emitted);
    if (!NEED_REX()) return false;

    uint8_t rex = 0xC0;
    rex |= ai.rex.Q << 3;
    rex |= ai.rex.A << 2;
    rex |= ai.rex.B << 1;
    rex |= ai.rex.X << 0;

    *frag_more(1) = rex;
    ai.rex_emitted = true;
    return true;
}

// Various checks to compute the operand size of various classes of instructions.
// They take the opcode name for error messages. It's OK if the opcode name
// doesn't include a size suffix (x86 also doesn't include them).
// If an error is discovered, it is reported with as_bad, then the safe size
// 1 (word) is returned to continue seeking potential errors.

static const char size_chars[4] = { 'h', 'x', 'd', 'q' };
typedef int8_t(*size_checker)(void);
#define SIZE_CHK_HDR(name) static int8_t name(void)

/* Typical computation operand size check: must have a size, all operands agree.
    Note: if some operand is a memory operand, it reports a size of -1 and
    the parser should have already checked that registers agree with address width. */
SIZE_CHK_HDR(compute_opr_opr_size);
/* Operand size check for load/store instructions: must have a size,
    opcode and dst/src operands agree, address operand agrees with address width. */
SIZE_CHK_HDR(compute_opr_adr_size);
// etc.
SIZE_CHK_HDR(compute_opr_any_size);
SIZE_CHK_HDR(compute_opr_size);
SIZE_CHK_HDR(compute_adr_size);
SIZE_CHK_HDR(check_arg_is_lbl);
SIZE_CHK_HDR(compute_nullary_size);
SIZE_CHK_HDR(do_nothing);

static int64_t sign_extend(int64_t val, uint8_t bit) {
    // v = 0x00008000, bit = 16
    uint64_t m = 1ULL << (bit - 1);
    // m = 0x00008000
    val = val & ((m << 1) - 1);
    // val = 0x00008000 & 0x0000FFFF = 0x00008000
    return (val ^ m) - m;
    // val ^ m = 0
    // 0 - 0x00008000 = 0xFFFF8000
}
static uint64_t zero_extend(int64_t val, uint8_t bit) {
    uint64_t m = (1ULL << bit) - 1;
    return val & m;
}
static bool fits_in_bytes_signed(int64_t val, uint8_t nbytes) {
    return val == sign_extend(val, nbytes * 8);
}
static bool fits_in_bytes_unsigned(int64_t val, uint8_t nbytes) {
    return val == (int64_t)zero_extend(val, nbytes * 8);
}
static bool fits_in_bytes(int64_t val, uint8_t nbytes) {
    if (nbytes == 8) return true; // immediate parser handles this already.
    return fits_in_bytes_signed(val, nbytes) || fits_in_bytes_unsigned(val, nbytes);
}

static void validate_conc_imm_size(void) {
    struct etca_arg *the_imm;
    bool have_fi_fmt; // do we have the _correct_ FI format for this?
    bool have_rex;    // are we allowed to set REX.Q?
    // we should only be inspecting ABM formats.
    // If this turns oout to be inconvenient, we can add more.
    // Beware that `int' is a special case.
    if (ai.opcode->format != ETCA_IF_BASE_ABM
        && ai.opcode->format != ETCA_IF_EXOP_ABM) {
        return; // not ABM. Might be an immediate, but we don't care here.
    }
    if (!(ai.params.kinds.i || ai.params.kinds.mi || ai.params.kinds.ri))
        return; // no immediate to check!
    
    if (ai.params.kinds.i) {
        the_imm = &ai.args[0];
        have_fi_fmt = CHECK_PAT(fi_pat);
    }
    else if (ai.params.kinds.ri) {
        the_imm = &ai.args[1];
        have_fi_fmt = CHECK_PAT(fi_pat);
    } else {
        the_imm = &ai.args[1];
        have_fi_fmt = CHECK_PAT(mo2_pat);
    }
    have_rex = CHECK_PAT(rex_pat);

    if (!the_imm->kind.immConc) {
        // have to assume biggest pointer size
        if (code_model_pointer_width[settings.code_model] == 3 && have_rex) {
            ai.rex.Q = 1;
        }
        return; // no (concrete) immediate to check.
    }

    // if we don't have the correct FI format, then we can only have 5 bits.

    int64_t imm_val = the_imm->imm_expr.X_add_number;
    int64_t nbytes  = 1ULL << ai.opcode_size;
    // one of the fits_in_bytesX functions
    bool(*fits_with_signage)(int64_t,uint8_t);

    // If the opcode is mov, then we're doing a validation before a demotion.
    // `mov''s arg has no signage, so needs a special case here.
    if (ai.opcode->format == ETCA_IF_SPECIAL && ai.opcode->opcode == ETCA_MOV) {
        // we don't call this if we're doing slo expansion, so no need
        // to do a 5 bit check. In fact, let's make sure we have FI...
        gas_assert(have_fi_fmt);
        if (the_imm->kind.imm8s || the_imm->kind.imm8z) return;
        fits_with_signage = fits_in_bytes;
    }
    else if (!ai.imm_signed) {
        if (!have_fi_fmt && !the_imm->kind.imm5z) {
        bad_5bit:
            as_bad("bad immediate for `%s'", ai.opcode->name);
            return;
        }
        if (the_imm->kind.imm8z) return; // definitely fine, fits in 8 (or 5) bits.
        fits_with_signage = fits_in_bytes_unsigned;
    }
    else {
        // otherwise, signed.
        if (!have_fi_fmt && !the_imm->kind.imm5s) {
            goto bad_5bit;
        }
        if (the_imm->kind.imm8s) return;
        fits_with_signage = fits_in_bytes_signed;
    }

    // check with no consideration for signage first. We've already
    // knocked out correctness for 8 and 5 bit formats matching the sign.
    // By checking without signage here, we ensure that we still allow
    // a value like 255 for addh with FI (but not without) even though it
    // has to be encoded as -1.
    if (!fits_in_bytes(imm_val, nbytes)) {
    bad_imm:
        as_bad("bad immediate for `%s' with operand size attr `%c'",
            ai.opcode->name, size_chars[ai.opcode_size]);
    }

    // Now to determine if we need REX, we must consider with signage.
    // If the value fits correctly in 4 bytes, there's no need for REX.
    if (nbytes == 8 && !fits_with_signage(imm_val, 4)) {
        if (have_rex) ai.rex.Q = 1;
        // otherwise we can't represent it, so we must error.
        else goto bad_imm;
    }
}

/* Operand size check for one register size and an opcode size.
    The register must agree with the opcode. Shared code for several checkers. */
static int8_t
check_opcode_matches_opr_size(int8_t opcode_size, int8_t reg_size);

// potential errors while computing operand sizes
static void operand_size_mismatch(void);
static void suffix_operand_disagree(int8_t suffix, int8_t opsize);
static void indeterminate_operand_size(void);
static void bad_address_reg_size(int8_t reg_size);
static void must_be_a_label(void);

static const size_checker size_checkers[NUM_ARGS_SIZES] = {
    compute_nullary_size, do_nothing,
    compute_opr_size, compute_adr_size,
    check_arg_is_lbl, compute_opr_opr_size,
    compute_opr_adr_size, compute_opr_any_size
};

static int8_t compute_operand_size() {
    // call the relevant size checker, that's all.
    gas_assert(ai.opcode->size_info.args_size < NUM_ARGS_SIZES);
    ai.opcode_size = size_checkers[ai.opcode->size_info.args_size]();
    return ai.opcode_size;
}

SIZE_CHK_HDR(compute_nullary_size) {
    gas_assert(ai.argc == 0);
    gas_assert(ai.opcode->size_info.args_size == 0);
    // Mostly the opcodes don't have a size. The NOP pseudo instruction
    // deals with potentially absent size itself, so just pass over the existing value
    return ai.opcode_size;
}

SIZE_CHK_HDR(do_nothing) {
    return 0;
}

SIZE_CHK_HDR(compute_opr_size) {
    gas_assert(ai.argc == 1);
    gas_assert(ai.opcode->size_info.args_size == OPR);

    return check_opcode_matches_opr_size(ai.opcode_size, ai.args[0].reg_size);
}

SIZE_CHK_HDR(compute_adr_size) {
    gas_assert(ai.argc == 1);
    gas_assert(ai.opcode->size_info.args_size == ADR);

    check_adr_size(ai.args[0].reg_size);
    // we don't need an operand size for register jumps/calls
    if (ai.opcode->format != ETCA_IF_SAF_JMP && ai.opcode_size < 0) {
        indeterminate_operand_size();
        return 1;
    }
    return ai.opcode_size;
}

SIZE_CHK_HDR(check_arg_is_lbl) {
    const struct expressionS *expr;
    gas_assert(ai.argc == 1);
    gas_assert(ai.opcode->size_info.args_size == LBL);
    // compute_params has been called by now, and we must have an imm to get here.
    gas_assert(ai.args[0].kind.immAny == 1);

    expr = &ai.args[0].imm_expr;

    if (expr->X_op != O_symbol || expr->X_add_number != 0) must_be_a_label();
    return -1;
}

SIZE_CHK_HDR(compute_opr_opr_size) {
    int8_t opcode_size = ai.opcode_size;
    int8_t arg1_size, arg2_size, arg_size;
    gas_assert(ai.argc == 2);

    arg1_size = ai.args[0].reg_size;
    arg2_size = ai.args[1].reg_size;

    // do args disagree?
    if (arg1_size >= 0 && arg2_size >= 0 && arg1_size != arg2_size) {
        operand_size_mismatch();
        return 1;
    }
    // if args agree, compute arg_size
    if (arg1_size >= 0) arg_size = arg1_size;
    else                arg_size = arg2_size;

    return check_opcode_matches_opr_size(opcode_size, arg_size);
}

SIZE_CHK_HDR(compute_opr_adr_size) {
    int8_t opcode_size = ai.opcode_size;
    int8_t arg1_size, // this one should work with opcode size
           arg2_size; // this one should work with address width
    gas_assert(ai.argc == 2);

    arg1_size = ai.args[0].reg_size;
    arg2_size = ai.args[1].reg_size;

    // check that opcode size and arg1 size agree. Check first
    // for order of error messages.
    arg1_size = check_opcode_matches_opr_size(opcode_size, arg1_size);
    // check that arg2 size is consistent with address mode...
    check_adr_size(arg2_size);
    return arg1_size;
}

SIZE_CHK_HDR(compute_opr_any_size) {
    gas_assert(ai.argc == 2);
    return check_opcode_matches_opr_size(ai.opcode_size, ai.args[0].reg_size);
}

static int8_t check_opcode_matches_opr_size(int8_t opcode_size, int8_t reg_size) {
    // do args disagree with opcode?
    if (opcode_size >= 0 && reg_size >= 0 && opcode_size != reg_size) {
        suffix_operand_disagree(opcode_size, reg_size);
        return 1;
    }
    // if args and opcode sizes are all -1, we can't determine the size
    else if (opcode_size == -1 && reg_size == -1) {
        indeterminate_operand_size();
        return 1;
    }
    // otherwise, one of opcode_size or arg_size is known, return that.
    else if (opcode_size >= 0) return opcode_size;
    else                       return reg_size;
}

static void check_adr_size(int8_t adr_size) {
    if (adr_size >= 0 && adr_size != code_model_pointer_width[settings.code_model]) {
        bad_address_reg_size(adr_size);
    }
}

#undef SIZE_CHK_HDR

static void operand_size_mismatch(void) {
    as_bad("operand size mismatch for `%s'", ai.opcode->name);
}
static void suffix_operand_disagree(int8_t suffix, int8_t opsize) {
    as_bad("bad register size `%c' for `%s' used with suffix `%c'",
        size_chars[opsize], ai.opcode->name, size_chars[suffix]);
}
static void indeterminate_operand_size(void) {
    as_bad("can't determine operand size for `%s'", ai.opcode->name);
}
static void bad_address_reg_size(int8_t reg_size) {
    // I think this message looks better without the opcode name usually.
    // In any case, when parsing a memory operand, we don't want the opcode
    // name repeatedly (in case of several errors). With this simple
    // ad-hoc error reporting system, it's quite tricky to find an improvement.
    // Previously, before `ai' was a global variable, we could pass NULL. Alas.
    as_bad("bad ptr register size `%c'", size_chars[reg_size]);
    // as_bad("bad ptr register size `%c' for `%s'", size_chars[reg_size], opc->name);
}
static void must_be_a_label(void) {
    as_bad("the operand of `%s' must be a label", ai.opcode->name);
}

/* Process the nop pseudo instruction. It was already verified that there are no arguments */
static void
process_nop_pseudo(void) {
    size_t byte_count;
    if (ai.opcode_size == -1) {
	if (etca_match_cpuid_pattern(&any_vwi_pat, &settings.current_cpuid)) {
	    ai.opcode_size = 0; /* We are going to use the 1byte NOP by default*/
	} else {
	    ai.opcode_size = 1; /* We need to use the base-isa 2byte NOP*/
	}
    }
    if (((uint8_t)ai.opcode_size) > 3) {
	as_fatal("internal error: Illegal opcode_size=%d", ai.opcode_size);
    }
    byte_count = 1 << ai.opcode_size;
    char *output = frag_more(byte_count);
    etca_build_nop(&settings.current_cpuid, byte_count, output);
}

/* Process the hlt pseudo instruction. It was already verified that there are no arguments */
static void
process_hlt_pseudo(void) {
    char *output = frag_more(2);
    output[0] = 0b10001110; // j +
    output[1] = 0;          //    0
}

/* Process the mov pseudo instruction. The only thing that needs to be guaranteed
    beforehand is that there are two params. */
static void 
process_mov_pseudo(void) {
#define KIND(idx) (ai.args[idx].kind)
// TODO: simple mem should include displacement but no register
#define SIMPLE_MEM(idx) (KIND(idx).memory && ai.args[idx].imm_expr.X_op == O_absent && ai.args[idx].memory.index_reg == -1)
    // simple MEM <- reg: store
    if (SIMPLE_MEM(0) && KIND(1).reg_class == GPR) {
        ai.opcode = str_hash_find(opcode_hash_control, "store");
        struct etca_arg mem = ai.args[0];
        ai.params.kinds.rr = 1;
        ai.args[0] = ai.args[1]; // store #0 is store source, but we have that at #1
        ai.args[1].kind = (struct etca_arg_kind){.reg_class = GPR};
        ai.args[1].reg.gpr_reg_num = mem.memory.base_reg; // specifically the base addr reg
        // ai.args[1].reg_size = -1; // size is already computed so we can skip this
        assemble_base_abm();
        return;
    }
    // reg <- simple MEM: load
    if (KIND(0).reg_class == GPR && SIMPLE_MEM(1)) {
        ai.opcode = str_hash_find(opcode_hash_control, "load");
        ai.params.kinds.rr = 1;
        ai.args[1].kind = (struct etca_arg_kind){.reg_class = GPR};
        ai.args[1].reg.gpr_reg_num = ai.args[1].memory.base_reg; // the base addr reg
        // ai.args[1].memory = (?){0}; // no need, assemble_base_abm won't look at this
        // ai.args[1].reg_size = -1; // size is already computed so no need for this
        assemble_base_abm();
        return;
    }
    // two (GP) registers, or GPR and (any) MEM, or (any) MEM and GPR: it's just movs.
    if ((KIND(0).reg_class == GPR && KIND(1).reg_class == GPR)
        || (KIND(0).reg_class == GPR && KIND(1).memory)
        || (KIND(0).memory && KIND(1).reg_class == GPR)) {
        ai.opcode = str_hash_find(opcode_hash_control, "movs");
        ai.params.kinds.rr = 1;
        assemble_base_abm();
        return;
    }
    // GP register <- CTRL register: readcr
    if (KIND(0).reg_class == GPR && KIND(1).reg_class == CTRL) {
        ai.opcode = str_hash_find(opcode_hash_control, "readcr");
        ai.params.kinds.rc = 1;
        assemble_base_abm();
        return;
    }
    // CTRL register <- GP register: writecr
    // remember writecr needs the ctrl reg on the right, so we have to swap them!
    if (KIND(0).reg_class == CTRL && KIND(1).reg_class == GPR) {
        ai.opcode = str_hash_find(opcode_hash_control, "writecr");
        struct etca_arg tmp = ai.args[0];
        ai.args[0] = ai.args[1];
        ai.args[1] = tmp;
        ai.params.kinds.rc = 1;
        assemble_base_abm();
        return;
    }
    // GP register <- IMM
    // This is the large-immediate mov pseudo. It's mainly handled in elf32-etca.c,
    // but we need to construct the correct fixup if the immediate isn't concrete.
    if (KIND(0).reg_class == GPR && KIND(1).immAny) {
	char *output;

        // if FI is available, demote to movs as needed to make the
        // concrete value fit in the smallest possible encoding. If it's not
        // concrete, prefer movs as addresses are sign-extended.
        // If it is concrete, a selection of movz can sometimes allow
        // us to pick an 8-bit (or 32-bit) FI format instead of a larger one.
        if (CHECK_PAT(fi_pat)) {
            const char *selected_opcode;
            ai.params.kinds.ri = 1;
            validate_conc_imm_size();
            if ((KIND(1).imm8z && !KIND(1).imm8s)
                || (ai.opcode_size == 3
                    && fits_in_bytes_unsigned(ai.args[1].imm_expr.X_add_number, 4)
                    && !fits_in_bytes_signed (ai.args[1].imm_expr.X_add_number, 4))) {
                selected_opcode = "movz";
                ai.imm_signed = false;
            } else {
                selected_opcode = "movs";
                ai.imm_signed = true;
            }
            ai.opcode = str_hash_find(opcode_hash_control, selected_opcode);
            assemble_base_abm();
            return;
        }

	enum elf_etca_reloc_type r_type = etca_calc_mov_ri(
		&settings.current_cpuid,
		ai.opcode_size,
		ai.args[0].reg.gpr_reg_num,
		KIND(1).immConc ? (&ai.args[1].imm_expr.X_add_number) : NULL);
	size_t byte_count = R_ETCA_MOV_TO_BYTECOUNT(r_type);
	output = frag_more(byte_count);
	enum elf_etca_reloc_type reloc_kind = etca_build_mov_ri(
		&settings.current_cpuid,
		ai.opcode_size,
		ai.args[0].reg.gpr_reg_num,
		KIND(1).immConc ? (&ai.args[1].imm_expr.X_add_number) : NULL,
		r_type,
		output);
	if (!KIND(1).immConc) {
	    fix_new_exp(frag_now,
			(output - frag_now->fr_literal),
			byte_count,
			&ai.args[1].imm_expr,
			false,
			(bfd_reloc_code_real_type)(BFD_RELOC_ETCA_BASE_JMP - 1 + reloc_kind));
	    //TODO: Define a function in elf32-etca (I think?) that does the transformation r_type -> bfd_reloc_code correctly.
	}
	return;
    }
    // predec/postinc <- reg/imm: ASP push
    // Can't parse this if ASP isn't available so we don't have to check.
    // Enforce that left arg is predec.
    if ((KIND(0).predec || KIND(0).postinc) && (KIND(1).reg_class == GPR || KIND(1).immAny)) {
        if (KIND(0).postinc) {
            as_bad("ptr postinc can only be the second operand of `mov'");
            // but assemble as predec anyway for simplicity
        }
        ai.opcode = str_hash_find(opcode_hash_control, "push");
        ai.params.kinds.rr = KIND(1).reg_class == GPR;
        ai.params.kinds.ri = KIND(1).immAny;
        // replace the predec arg with just a GPR of the same regnum.
        ai.args[0].kind = (struct etca_arg_kind){.reg_class = GPR};
        // ai.args[0].reg.gpr_reg_num is already set correctly!
        assemble_base_abm();
        return;
    }
    // reg <- predec/postinc: ASP pop
    // Once again, if we parsed this, we know we have ASP (and therefore SAF).
    // Enforce that the right arg is postinc.
    if (KIND(0).reg_class == GPR && (KIND(1).predec || KIND(1).postinc)) {
        if (KIND(1).predec) {
            as_bad("ptr predec can only be the first operand of `mov'");
        }
        ai.opcode = str_hash_find(opcode_hash_control, "pop");
        ai.params.kinds.rr = 1;
        // replace postinc arg with GPR of the same regnum.
        ai.args[1].kind = (struct etca_arg_kind){.reg_class = GPR};
        assemble_base_abm();
        return;
    }

    as_bad("bad operands for `mov'");

#undef KIND
}

static bfd_reloc_code_real_type bfd_reloc_for_size[4] = {
    BFD_RELOC_8, BFD_RELOC_16, BFD_RELOC_32, BFD_RELOC_64,
};

enum abm_mode {
    invalid,
    ri_byte,
    abm_00,
    abm_fi_8,
    abm_fi_big, // decision to set REX.Q should be made already
        // by validate_conc_imm_size. So we don't distinguish further here.
};

// Not declared above since it's a local implementation detail that depends on the above enum.
/* Analyze the assemble_info to determine what needs to be done to
 * emit the ABM byte before assemble_abm takes over
 * (i.e. what assemble_base_abm and assemble_exop_abm need to do).
 * This includes:
 * - Correctly indicate format between RI and ABM (when return value == ri_byte)
 * - Setting the A, B, and X bits of `ai.rex' (but Q must be set already)
 * - Emit a REX prefix
 * The returned int is to be passed to assemble_abm which uses it to shortcut
 * instead of reanalyzing everything. If the return value is 'invalid', `as_bad`
 * has been called and we should stop assembling.
 *
 * Will modify ai to make small adjustments as needed, of course.
 * */
static enum abm_mode find_abm_mode(void);

static void assemble_abm(enum abm_mode);

static enum abm_mode find_abm_mode(void) {
    enum abm_mode mode = invalid;

    if (ai.params.kinds.rr) {
	mode = abm_00;
    } else if (ai.params.kinds.ri) {
        // only base ABM instructions can zext.
        bool zext = !ai.imm_signed;
        struct etca_arg_kind kind = ai.args[1].kind;
        // immediate sizes are already validated, so we can assume that
        // they are OK.
        if ((kind.imm5s && !zext) || (kind.imm5z && zext)) {
            mode = ri_byte;
        } else if ((kind.imm8s && !zext) || (kind.imm8z && zext)) {
            mode = abm_fi_8;
        } else {
            mode = abm_fi_big;
        }
    } else if (ai.params.kinds.rc) {
        // readcr or writecr
        // can't encode a control register number more than 31 (without FI);
        // we don't have any such yet, but ensure we get an error
        // if or when that happens.
        gas_assert(ai.args[1].reg.ctrl_reg_num < 32);
        // set the immediate value to the control reg number
        ai.args[1].imm_expr.X_add_number = ai.args[1].reg.ctrl_reg_num;
        // and encode an ri_byte.
        mode = ri_byte;
    } else {
	as_bad("Unknown params kind for assemble_abm");
	return invalid;
    }
#undef IS_VALID_REG

    generic_rex_init();
    assemble_rex_prefix();
    return mode;
}

/* Assembles just an abm or ri byte, for use by assemble_base_abm and assemble_exop_abm
 * find_abm_mode needs to be called first and the mode passed in here. find_abm_mode
 * potentially does further setup that is required for this function to work.
 */
void assemble_abm(enum abm_mode mode) {
    char *output;
    size_t idx = 0;

    switch (mode) {
	case invalid: /* We shouldn't be called in this case */
	    abort();
	case ri_byte: /* We trust that find_abm_mode verified everything and set known_imm correctly */
	    output = frag_more(1);
	    output[idx++] = DEPOSIT_REG(ai.args[0].reg.gpr_reg_num, A)
                          | ((ai.args[1].imm_expr.X_add_number) & 0x1F);
	    return;
	case abm_00:
	    output = frag_more(1);
	    output[idx++] = DEPOSIT_REG(ai.args[0].reg.gpr_reg_num, A)
                          | DEPOSIT_REG(ai.args[1].reg.gpr_reg_num, B)
                          | 0b00;
	    return;
        case abm_fi_8:
            output = frag_more(2);
            output[idx++] = DEPOSIT_REG(ai.args[0].reg.gpr_reg_num, A) // AAA
                          | 0b00001001; // A x i8
            output[idx++] = ai.args[1].imm_expr.X_add_number;
            // if that value was not concrete, we should never select this mode.
            gas_assert(ai.args[1].kind.immConc);
            break;
        case abm_fi_big:
            fixS *fixp;
            uint8_t bytes_needed = 1; // ABM byte
            uint8_t imm_bytes = ai.opcode_size;
            uint8_t imm_size;
            if (ai.opcode_size == 3 && !ai.rex.Q) imm_bytes = 2; // qword clamping
            imm_size = 1 << imm_bytes; // 1,2,4, rex.Q ? 8 : 4.
            bytes_needed += imm_size;
            output = frag_more(bytes_needed);
            output[idx++] = DEPOSIT_REG(ai.args[0].reg.gpr_reg_num, A)
                          | 0b00001101; // A x iS
            md_number_to_chars(output+idx, ai.args[1].imm_expr.X_add_number, imm_size);
            // if that value was not concrete, emit a fixup...
            if (!ai.args[1].kind.immConc) {
                fixp = fix_new_exp(
                    frag_now,
                    output + idx - frag_now->fr_literal,
                    imm_size,
                    &ai.args[1].imm_expr,
                    false, /* not pcrel */
                    bfd_reloc_for_size[imm_bytes]
                );
                fixp->fx_signed = ai.imm_signed;
            }
            break;
	default:
	    abort();
    }
}

/* Assemble a base-isa style instruction with arbitrary RI/ABM (as long as the current extensions support it)
 */
void assemble_base_abm(void) {
    char *output;
    size_t idx = 0;
    enum abm_mode mode = find_abm_mode(); // sets up and emits the REX byte if needed
    uint8_t size_attr = ai.opcode_size;
    gas_assert(size_attr <= 3); // otherwise we should've errored at compute_size

    if (mode == invalid) { return; }

    // FIXME: This should probably be handled in slo's size_info field.
    if (ai.opcode->name && !strcmp(ai.opcode->name, "slo") && !ai.args[1].kind.imm5z) {
        as_bad("slo operand 2 must be a concrete unsigned 5-bit value");
    }

    if (mode == ri_byte) {
	output = frag_more(1);
	output[idx++] = (0b01000000 | size_attr << 4 | ai.opcode->opcode);
    } else {
	output = frag_more(1);
	output[idx++] = (0b00000000 | size_attr << 4 | ai.opcode->opcode);
    }
    assemble_abm(mode);
}

/* Assemble an EXOP instruction with arbitrary RI/ABM operands. */
void assemble_exop_abm(void) {
    char *output;
    size_t idx = 0;
    enum abm_mode mode = find_abm_mode(); // sets up and emits the REX byte if needed
    uint8_t size_attr = ai.opcode_size;
    uint8_t high_opcode = (ai.opcode->opcode & 0x1E0) >> 5;
    uint8_t mid_opcode  = (ai.opcode->opcode & 0x010) >> 4;
    uint8_t low_opcode  = (ai.opcode->opcode & 0x00F)     ;
    uint8_t fmt_spec    = mode == ri_byte;

    gas_assert(size_attr <= 3);

    if (mode == invalid) { return; }

    output = frag_more(2);
    output[idx++] = 0xE0 | high_opcode;
    output[idx++] = (mid_opcode << 7) | (fmt_spec << 6) 
                  | (size_attr  << 4) | low_opcode;
    assemble_abm(mode);
}

/* Assemble an mtcr-misc format instruction. IRET, INT, WAIT.
    Quite ad-hoc... but it's the misc format. */
void assemble_mtcr_misc(void) {
    char *output = frag_more(2);
    size_t idx = 0;

    switch (ai.opcode->opcode) {
    case ETCA_IRET:
    case ETCA_WAIT:
        gas_assert(ai.argc == 0);
        output[idx++] = 0x0F;
        output[idx++] = ai.opcode->opcode;
        break;
    case ETCA_INT:
        offsetT imm = ai.args[0].imm_expr.X_add_number;
        gas_assert(ai.argc == 1 && ai.args[0].kind.immAny);
        if (!ai.args[0].kind.immConc || imm < 0 || imm > 255)
            as_bad("operand for `int' must be a concrete unsigned 8-bit value");
        output[idx++] = 0x0F | ((imm & 0x80) >> 3);
        output[idx++] = ((imm & 0x7E) << 1) | 0x02 | (imm & 1);
        break;
    default:
        abort();
    }
}

/* Assemble a jump or call which has been promoted to an EXOP-format
    long jump/call. The condition code must be ETCA_COND_ALWAYS
    if COND is not available.
*/
static void assemble_promoted_exop_jump(
    bool call, bool absolute, uint8_t size_attr
) {
    // MAJOR FIXME:
    // These really need to be relaxed to base jump formats,
    // at the very least at assembly-time if we learn that the target is
    // actually close (and in the same section). This is nontrivial
    // and inspection of other backends should be done. Apparently important:
    // - md_apply_fix: seems like this should be critical
    // - md_estimate_size_before_relax: I'm not actually 100% sure what this does.
    //      i386 seems to be doing actual relaxation here.
    // - md_convert_frag: I think this is a frag finalizer, and we must be done
    //      with assembly-time relaxation when... actually, I'm not sure.
    //      Look into how this is expected to work.

    char *output;
    fixS *fixp;
    uint8_t nbytes = 1 << size_attr;

    assemble_cond_prefix();
    output = frag_more(1 + nbytes);

    output[0] = 0xF0 | ((call & 1) << 3) | ((absolute & 1) << 2) | size_attr;
    md_number_to_chars(output+1, 0, nbytes);
    fixp = fix_new_exp(
        frag_now,
        output + 1 - frag_now->fr_literal,
        nbytes,
        &ai.args[0].imm_expr,
        !absolute, /* pcrel? */
        bfd_reloc_for_size[size_attr]
    );
    fixp->fx_signed = true; // not convinced this is correct for absolute
}

/* Assemble a base-isa style jump instruction.
    If EXOP is available, we will initially select an exop format
    using frag_var. We will try to relax that back to the base
    format if we can (since it's shorter) during assembly-time
    relaxation, but if we can't, it'll have to wait until
    (potential) LTO. */
void assemble_base_jmp(void) {
    char *output;
    size_t idx = 0;

    if (CHECK_PAT(exop_pat)
        && (ai.opcode->opcode == ETCA_COND_ALWAYS || CHECK_PAT(cond_pat))
    ) {
        // select the exop jump format matching the configured code model
        // FIXME [mtune]: in the future, when mtune is supported for various
        // known architectures, the choice between an absolute and relative
        // jump can be influenced by performance characteristics.

        // small => absolute, medany => relative by definition.
        // We could make better mtune-guided decisions if we could be sure
        // that a relative/absolute jump in the code model will not
        // overflow the actual pointer size. Actually, absolute jumps
        // are _always_ sound (unless `medany' code overflows out of its
        // 2GB range, violating its promise), but we assume here that
        // a typical device will handle relative displacements better,
        // since the base format also uses them.
        bool absolute = settings.code_model == etca_model_small;
        uint8_t ptr_attr = code_model_pointer_width[settings.code_model];
        ai.cond_prefix_code = ai.opcode->opcode;
        assemble_promoted_exop_jump(false, absolute, ptr_attr);
        return;
    }

    output = frag_more(2);
    fixS *fixp = fix_new_exp(frag_now,
			     (output - frag_now->fr_literal),
			     2,
			     &ai.args[0].imm_expr,
			     true,
			     BFD_RELOC_ETCA_BASE_JMP);
    fixp->fx_signed = true;
    output[idx++] = (0b10000000 | ai.opcode->opcode);
    output[idx++] = 0;
}

/* Assemble a call <label> instruction, as added by SAF.
    If EXOP is available, we will initially select an exop format
    using frag_var. We will try to relax that back to the SAF
    format if we can (since it's shorter) during assembly-time
    relaxation, but if we can't, it'll have to wait until
    (potential) LTO. */
void assemble_saf_call(void) {
    char *output;
    size_t idx = 0;
    gas_assert(ai.argc == 1 && ai.args[0].kind.immAny);

    if (CHECK_PAT(exop_pat)) {
        // select the exop call format matching the configured code model
        // FIXME [mtune]: in the future, when mtune is supported for various
        // known architectures, the choice between an absolute and relative
        // jump can be influenced by performance characteristics.

        // see the description in assemble_base_jmp
        bool absolute = settings.code_model == etca_model_small;
        uint8_t ptr_attr = code_model_pointer_width[settings.code_model];
        ai.cond_prefix_code = ETCA_COND_ALWAYS;
        assemble_promoted_exop_jump(true, absolute, ptr_attr);
        return;
    }

    output = frag_more(2);
    output[idx++] = 0b10110000;
    output[idx++] = 0;
    fixS *fixp = fix_new_exp(frag_now,
			     (output - frag_now->fr_literal),
			     2,
			     &ai.args[0].imm_expr,
			     true,
			     BFD_RELOC_ETCA_SAF_CALL);
    fixp->fx_signed = true;
}

/* Assemble an SAF conditional register jump/call instruction. */
void assemble_saf_jmp(void) {
    char *output;
    size_t idx = 0;
    // nullary is a ret, if there's 1 arg it must be an explicit GPR.
    gas_assert(ai.argc == 0 || (ai.argc == 1 && ai.args[0].kind.reg_class == GPR));

    if (ai.argc == 0) {
        ai.argc = 1;
	ai.params.kinds.e = 0;
	ai.params.kinds.r = 1;
        ai.args[0].reg.gpr_reg_num = 7; // %ln
    }

    generic_rex_init();
    assemble_rex_prefix();
    output = frag_more(2);
    output[idx++] = 0b10101111;
    // we put the opcodes in the table including the "call" bit.
    output[idx++] = DEPOSIT_REG(ai.args[0].reg.gpr_reg_num, A) | ai.opcode->opcode;
}

/* Assemble a SAF push or pop instruction. */
void assemble_saf_stk(void) {
    // 12 => pop;  stack pointer belongs in the B operand
    // 13 => push; stack pointer belongs in the A operand
    gas_assert(ai.opcode->opcode == 12 || ai.opcode->opcode == 13);
    gas_assert(ai.argc == 1);

    // Kind r => rr. Kind i => ri. Kind m needs depends on which opcode we have.
    ai.params.kinds.rr = ai.params.kinds.r;
    ai.params.kinds.ri = ai.params.kinds.i;
    ai.params.kinds.r  = ai.params.kinds.i = 0;
    gas_assert(ai.params.kinds.rr || ai.params.kinds.ri || ai.params.kinds.m);

    if (ai.opcode->opcode == 12) { /* pop */
        // parsed operand is already in the A operand. Just pull in stack pointer...
        ai.argc = 2;
        ai.args[1].kind.reg_class = GPR;
        ai.args[1].reg.gpr_reg_num = 6; // #define this somewhere? or maybe an enum?
        assemble_base_abm();
        return;
    } else if (ai.opcode->opcode == 13) { /* push */
        // parsed operand is in the A operand, but must be moved to B.
        ai.argc = 2;
        ai.args[1] = ai.args[0];
        ai.args[0].kind.reg_class = GPR;
        ai.args[0].reg.gpr_reg_num = 6;
        ai.params.kinds.rr = 1;
        ai.params.kinds.r = 0;
        assemble_base_abm();
        return;
    }
}
