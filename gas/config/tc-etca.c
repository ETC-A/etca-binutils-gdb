
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

    struct {
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

/* State shared between md_assemble and the indivdual assembler functions */
struct parse_info {
    /* The size marker attached to the opcode, one of -1 (none),0 (h),1 (x),2 (d),3 (q).
        after compute_operand_size, this is the actual operand size attribute. */
    int8_t opcode_size; 
    union etca_opc_params_field params;
    size_t argc;
    struct etca_arg args[MAX_OPERANDS];
    // struct etca_prefix prefixes[MAX_PREFIXES]; // (or would it be better to hace the indvidual prefixes seperated?
};

/* Tables of character mappings for various contexts. 0 indicates that the character is not lexically that thing.
Initialized by md_begin. */
static char register_chars[256];
static char mnemonic_chars[256];

/* An opcode-assembler function.
Takes the opc_info being assembled, and should confirm that it actually handles that opcode.
Similarly, should confirm that the params_kind it got is expected. */
typedef void(*assembler)(const struct etca_opc_info *, struct parse_info *);

static int parse_extension_list(const char *extensions, struct etca_cpuid *out);

static int8_t parse_size_attr(char value);

static struct etca_reg_info *lookup_register_name_checked(char **str, int have_prefix);
static char *parse_register_name(char *str, struct etca_arg *result);

static char *parse_immediate(char *str, struct etca_arg *result);

static void
check_adr_size(const struct etca_opc_info *, int8_t adr_size);
static char *parse_memory_inner(char *str, struct etca_arg *result);
static char *parse_asp         (char *str, struct etca_arg *result);
static char *parse_memory_outer(char *str, struct etca_arg *result);

static char *parse_operand(char *str, struct etca_arg *result);

/* Determine the operand size for the given opcode and parse_info. 
    The computed size is placed in pi->opcode_size. If we are unable
    to determine the operand size, as_bad is called and 1 is used. */
static int8_t compute_operand_size(const struct etca_opc_info *, struct parse_info *);

static bool compute_params(struct parse_info *pi);

static void process_mov_pseudo(const struct etca_opc_info *, struct parse_info *);

static void assemble_base_abm(const struct etca_opc_info *, struct parse_info *);
static void assemble_base_jmp(const struct etca_opc_info *, struct parse_info *);
static void assemble_saf_jmp (const struct etca_opc_info *, struct parse_info *);
static void assemble_saf_stk (const struct etca_opc_info *, struct parse_info *);

#define TRY_PARSE_SIZE_ATTR(lval, c) (((lval) = parse_size_attr(c)) >= 0)

/* The known predefined archs. Needs to be kept in sync with gcc manually */
static struct etca_known_arch {
    const char *name;
    struct etca_cpuid cpuid;
    char is_concrete;
} known_archs[] = {
	/* unknown, the default. Also used when only -mextensions is used. */
	{"unknown", ETCA_CPI_BASE,              0},
	/* base-isa with no predefined instructions */
	{"base",    ETCA_CPI_BASE,              1},
	/* The core extension set: FI, SAF, INT, BYTE, EXOP, VON  */
	{"core",    MK_ETCA_CPI(0xF, 0x1, 0x1), 0},
	{0, {0, 0, 0},                          0}
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

    /* Various fields*/
    uint32_t arch_name: 1; /* We got an explicit ARCH name */
    uint32_t custom_name: 1; /* We got a custom ARCH name */
    uint32_t manual_cpuid: 1; /* We got a -mcpuid. When not custom_name, this needs to exactly match the predefined one */

    // I'm not actually sure how we will set this one yet, but we do need it.
    uint32_t address_size_attr: 2; /* 1: word, 2: dword, 3: qword. */

    uint32_t require_prefix: 1; /* Are % register prefixes required? (default yes) */
    uint32_t pedantic: 1; /* At the moment, just: Are sizes required on registers? (default no) */
} settings = {
	.current_cpuid = ETCA_CPI_BASE,
	.march = "",
	.march_cpuid = ETCA_CPI_BASE,
	.mextensions = ETCA_CPI_BASE,
	.arch_name = 0,
	.custom_name = 0,
	.manual_cpuid = 0,
        .address_size_attr = 1, // word
        .require_prefix = 1,
        .pedantic = 0,
};


static assembler pseudo_functions[ETCA_PSEUDO_COUNT] = {
	process_mov_pseudo, /* mov */
};
static assembler format_assemblers[ETCA_IFORMAT_COUNT] = {
	0, /* ILLEGAL */
	0, /* SPECIAL (handled via pseudo_functions) */
	0, /* PSEUDO (handled via pseudo_functions) */
	assemble_base_abm, /* BASE_ABM */
	0, /* EXOP_ABM */
	assemble_base_jmp, /* BASE_JMP */
	0, /* SAF_CALL */
	assemble_saf_jmp, /* SAF_JMP  */
	assemble_saf_stk, /* SAF_STK  */
	0, /* EXOP_JMP */
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
 * Sets the size attr of the result according to the register parsed
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
    if (result->kind.reg_class == CTRL) {
        as_bad("invalid use of control register");
        result->reg.gpr_reg_num = 0;
        result->kind.reg_class = GPR;
        return str; // try to keep going as though we found a register.
    }
    // not a register; indicate as such (and probably try something else).
    if (!str) return NULL;
    // check address size is good
    check_adr_size(NULL, result->reg_size);
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
        check_adr_size(NULL, result->reg_size);
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

/* Based on the list of parsed arguments, correctly set pi->params.
 */
bool compute_params(struct parse_info *pi) {
#define IS_REG(arg) ((arg).kind.reg_class == GPR)
#define IS_IMM(arg) ((arg).kind.immAny) // this covers it unless parse_immediate screws up.
#define IS_SPECIAL(arg) ((arg).kind.nested_memory || (arg).kind.predec || (arg.kind.postinc))
    /* This can probably be solved better... */
    if (pi->argc == 0) {
	pi->params.kinds.e = 1;
	return true;
    } else if (pi->argc == 1) {
	if (IS_SPECIAL(pi->args[0])) {
	    as_bad("Illegal argument");
	    return false;
	}
	if (IS_REG(pi->args[0])) {
	    pi->params.kinds.r = 1;
	    return true;
	} else if (IS_IMM(pi->args[0])) {
	    pi->params.kinds.i = 1;
	    return true;
	} else {
	    abort();
	}
    } else if (pi->argc == 2) {
	if (IS_SPECIAL(pi->args[0])) {
	    as_bad("Illegal argument");
	    return false;
	}
	if (IS_SPECIAL(pi->args[1])) {
	    as_bad("Illegal argument");
	    return false;
	}
	if (IS_REG(pi->args[0])) {
	    if (IS_IMM(pi->args[1])) {
		pi->params.kinds.ri = 1;
		return true;
	    } else if (IS_REG(pi->args[1])) {
		pi->params.kinds.rr = 1;
		return true;
            } else if (pi->args[1].kind.reg_class == CTRL) {
                pi->params.kinds.rc = 1;
                return true;
	    } else {
		abort();
	    }
	} else if (IS_IMM(pi->args[0])) {
	    abort();
	} else {
	    abort();
	}
    } else {
	abort();
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
    const struct etca_opc_info *opcode;
    struct parse_info pi = {
	.opcode_size = -1,
	.params = {.uint = 0},
	.argc = 0,
	.args = {}
    };

    char *save_str = str; // for error messages
    char *opc_p; // for scanning
    char processed_opcode[MAX_MNEM_SIZE + 1]; // the scanned opcode

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
    // TODO: include if a size is allowed in the table so that we can exclude sized opcodes
    // for things like jumps.
    
    // first: check assuming no size.
    opcode = str_hash_find(opcode_hash_control, processed_opcode);
    if (!opcode) {
        char size;
        // we might have failed to find an entry because it actually ended with a size.
        // In that case, opc_p is pointing one past the NUL, so bring it back...
        opc_p -= 2;
        size = *opc_p;
        *opc_p = '\0'; // delete the size from processed_opcode...
        // and try looking up that instead.
        opcode = str_hash_find(opcode_hash_control, processed_opcode);
        // restore the size to processed_opcode, in case of error.
        *opc_p = size;
        // if the second lookup succeeded, check if a size suffix was not allowed
        // or if the given suffix was bad (in general or in this context).
        if ( opcode 
            && (!opcode->size_info.suffix_allowed
                || (pi.opcode_size = parse_size_attr(size)) < 0
                || !etca_match_cpuid_pattern(&size_pats[pi.opcode_size], &settings.current_cpuid))) {
            // If that's the case, this isn't an opcode.
            opcode = NULL;
        }
    }

    // reporting errors if we couldn't find any/a valid opcode...
    if (processed_opcode[0] == 0) {
	as_bad(_("can't find opcode")); // this might happen if a line is just %, for example.
	return;
    }
    if (opcode == NULL) {
not_an_opcode:
        // str may not be advanced to the end of the opcode yet.
        while (mnemonic_chars[(unsigned char) *str] != 0) str++;
        *str = '\0';
	as_bad(_("unknown opcode %s"), save_str);
	return;
    }

    // check for opcode suffix pedantically
    if (settings.pedantic && opcode->size_info.suffix_allowed && pi.opcode_size == -1) {
        as_bad("[-pedantic] no size suffix given for `%s'", opcode->name);
    }
    // but if we don't have any size extensions, allow a default of word.
    // FIXME: this check happens on every line and should probably be cached in settings.
    if (opcode->size_info.suffix_allowed &&
        !etca_match_cpuid_pattern(&any_size_pat, &settings.current_cpuid)) {
        pi.opcode_size = 1;
    }

    if (opcode->format == ETCA_IF_ILLEGAL) {
	as_bad("Illegal opcode %s", processed_opcode);
	return;
    }

    while (ISSPACE(*str)) str++;
    while (*str != '\0' && pi.argc < MAX_OPERANDS) {
	char *arg_end = parse_operand(str, &pi.args[pi.argc]);
	if (!arg_end) {
	    as_bad("Expected an argument");
	    return;
	}
	str = arg_end;
	pi.argc++;
	while (ISSPACE(*str)) str++;
	if (*str != ',') break;
	str++;
	while (ISSPACE(*str)) str++;
    }

    assembler assembly_function;
    // compute params kind.
    // Note there's an important secondary function here: checking that
    // we have the right _number_ of params. For special, we **must**
    // check this as a special case, or else we will hit gas assert
    // failures when we try to compute the operand size.
    if (opcode->format != ETCA_IF_SPECIAL) {
	if (!compute_params(&pi)) {
	    as_bad("Unknown argument pairing");
	    return;
	}
	uint32_t bit_to_test = pi.params.uint;
	while (
		((opcode->params.uint & bit_to_test) != bit_to_test
		 || !etca_match_cpuid_pattern(&opcode->requirements, &settings.current_cpuid))
		&&
		opcode->try_next_assembly) {
	    opcode++;
	}
	if ((opcode->params.uint & bit_to_test) != bit_to_test
	    || !etca_match_cpuid_pattern(&opcode->requirements, &settings.current_cpuid)) {
            as_bad("bad operands for `%s'", opcode->name);
	    return;
	}
    } else {
        // it is special.
        if (opcode->opcode == ETCA_MOV && pi.argc != 2) {
            as_bad("bad operands for `mov'");
            return;
        }
    }

    // do this check even for IF_SPECIAL (something is wrong with the
    // syntax if the operands of a name are overloaded).
    compute_operand_size(opcode, &pi);

    if (opcode->format == ETCA_IF_SPECIAL || opcode->format == ETCA_IF_PSEUDO) {
	assembly_function = pseudo_functions[opcode->opcode];
    } else {
	assembly_function = format_assemblers[opcode->format];
    }
    if (!assembly_function) {
	as_fatal("Missing for %s (%d)\n", opcode->name, opcode->format);
	return;
    }
    assembly_function(opcode, &pi);


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
    OPTION_NOPREFIX,
    OPTION_PEDANTIC,
};

struct option md_longopts[] =
	{
		{"march",       required_argument, NULL, OPTION_MARCH},
		{"mextensions", required_argument, NULL, OPTION_MEXTENSIONS},
		{"mcpuid",      required_argument, NULL, OPTION_MCPUID},
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
    fprintf (stream, "\t-march=name[+ABBR...]\n");
    fprintf (stream, "\t\t\t  Specify an architecture name as well as optionally\n");
    fprintf (stream, "\t\t\t  a list of extensions implemented on top of it\n");
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

// Various checks to compute the operand size of various classes of instructions.
// They take the opcode name for error messages. It's OK if the opcode name
// doesn't include a size suffix (x86 also doesn't include them).
// If an error is discovered, it is reported with as_bad, then the safe size
// 1 (word) is returned to continue seeking potential errors.

static const char size_chars[4] = { 'h', 'x', 'd', 'q' };
typedef int8_t(*size_checker)(const struct etca_opc_info *, const struct parse_info *);
#define SIZE_CHK_HDR(name) static int8_t name(const struct etca_opc_info *opc, const struct parse_info *pi)

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


/* Operand size check for one register size and an opcode size.
    The register must agree with the opcode. Shared code for several checkers. */
static int8_t
check_opcode_matches_opr_size(const struct etca_opc_info *, int8_t opcode_size, int8_t reg_size);

// potential errors while computing operand sizes
static void operand_size_mismatch(const struct etca_opc_info *);
static void suffix_operand_disagree(const struct etca_opc_info *, int8_t suffix, int8_t opsize);
static void indeterminate_operand_size(const struct etca_opc_info *);
static void bad_address_reg_size(const struct etca_opc_info *, int8_t reg_size);
static void must_be_a_label(const struct etca_opc_info *);

static const size_checker size_checkers[NUM_ARGS_SIZES] = {
    compute_nullary_size, compute_opr_size,
    compute_adr_size, check_arg_is_lbl,
    compute_opr_opr_size, compute_opr_adr_size,
    compute_opr_any_size
};

static int8_t compute_operand_size(const struct etca_opc_info *opcode, struct parse_info *pi) {
    // call the relevant size checker, that's all.
    gas_assert(opcode->size_info.args_size < NUM_ARGS_SIZES);
    pi->opcode_size = size_checkers[opcode->size_info.args_size](opcode, pi);
    return pi->opcode_size;
}

SIZE_CHK_HDR(compute_nullary_size) {
    gas_assert(pi->argc == 0);
    gas_assert(opc->size_info.args_size == 0);
    // the expectation is that these opcodes don't have sizes. But if we add
    // suffixes for nop at some point, for example, this might need revisiting.
    return pi->opcode_size;
}

SIZE_CHK_HDR(compute_opr_size) {
    gas_assert(pi->argc == 1);
    gas_assert(opc->size_info.args_size == OPR);

    return check_opcode_matches_opr_size(opc, pi->opcode_size, pi->args[0].reg_size);
}

SIZE_CHK_HDR(compute_adr_size) {
    gas_assert(pi->argc == 1);
    gas_assert(opc->size_info.args_size == ADR);

    check_adr_size(opc, pi->args[0].reg_size);
    // we don't need an operand size for register jumps/calls
    if (opc->format != ETCA_IF_SAF_JMP && pi->opcode_size < 0) {
        indeterminate_operand_size(opc);
        return 1;
    }
    return pi->opcode_size;
}

SIZE_CHK_HDR(check_arg_is_lbl) {
    const struct expressionS *expr;
    gas_assert(pi->argc == 1);
    gas_assert(opc->size_info.args_size == LBL);
    // compute_params has been called by now, and we must have an imm to get here.
    gas_assert(pi->args[0].kind.immAny == 1);

    expr = &pi->args[0].imm_expr;

    if (expr->X_op != O_symbol || expr->X_add_number != 0) must_be_a_label(opc);
    return -1;
}

SIZE_CHK_HDR(compute_opr_opr_size) {
    int8_t opcode_size = pi->opcode_size;
    int8_t arg1_size, arg2_size, arg_size;
    gas_assert(pi->argc == 2);

    arg1_size = pi->args[0].reg_size;
    arg2_size = pi->args[1].reg_size;

    // do args disagree?
    if (arg1_size >= 0 && arg2_size >= 0 && arg1_size != arg2_size) {
        operand_size_mismatch(opc);
        return 1;
    }
    // if args agree, compute arg_size
    if (arg1_size >= 0) arg_size = arg1_size;
    else                arg_size = arg2_size;

    return check_opcode_matches_opr_size(opc, opcode_size, arg_size);
}

SIZE_CHK_HDR(compute_opr_adr_size) {
    int8_t opcode_size = pi->opcode_size;
    int8_t arg1_size, // this one should work with opcode size
           arg2_size; // this one should work with address width
    gas_assert(pi->argc == 2);

    arg1_size = pi->args[0].reg_size;
    arg2_size = pi->args[1].reg_size;

    // check that opcode size and arg1 size agree. Check first
    // for order of error messages.
    arg1_size = check_opcode_matches_opr_size(opc, opcode_size, arg1_size);
    // check that arg2 size is consistent with address mode...
    check_adr_size(opc, arg2_size);
    return arg1_size;
}

SIZE_CHK_HDR(compute_opr_any_size) {
    gas_assert(pi->argc == 2);
    return check_opcode_matches_opr_size(opc, pi->opcode_size, pi->args[0].reg_size);
}

static int8_t check_opcode_matches_opr_size(const struct etca_opc_info *opc, int8_t opcode_size, int8_t reg_size) {
    // do args disagree with opcode?
    if (opcode_size >= 0 && reg_size >= 0 && opcode_size != reg_size) {
        suffix_operand_disagree(opc, opcode_size, reg_size);
        return 1;
    }
    // if args and opcode sizes are all -1, we can't determine the size
    else if (opcode_size == -1 && reg_size == -1) {
        indeterminate_operand_size(opc);
        return 1;
    }
    // otherwise, one of opcode_size or arg_size is known, return that.
    else if (opcode_size >= 0) return opcode_size;
    else                       return reg_size;
}

static void check_adr_size(const struct etca_opc_info *opc, int8_t adr_size) {
    if (adr_size >= 0 && adr_size != settings.address_size_attr) {
        bad_address_reg_size(opc, adr_size);
    }
}

#undef SIZE_CHK_HDR

static void operand_size_mismatch(const struct etca_opc_info *opc) {
    as_bad("operand size mismatch for `%s'", opc->name);
}
static void suffix_operand_disagree(const struct etca_opc_info *opc, int8_t suffix, int8_t opsize) {
    as_bad("bad register size `%c' for `%s' used with suffix `%c'",
        size_chars[opsize], opc->name, size_chars[suffix]);
}
static void indeterminate_operand_size(const struct etca_opc_info *opc) {
    as_bad("can't determine operand size for `%s'", opc->name);
}
static void bad_address_reg_size(const struct etca_opc_info *opc, int8_t reg_size) {
    // while parsing memory operands we may call this without wanting
    // to print the opcode name; support that here.
    if (!opc) {
        as_bad("bad ptr register size `%c'", size_chars[reg_size]);
    } else {
        as_bad("bad ptr register size `%c' for `%s'", size_chars[reg_size], opc->name);
    }
}
static void must_be_a_label(const struct etca_opc_info *opc) {
    as_bad("the operand of `%s' must be a label", opc->name);
}

/* Process the mov pseudo instruction. The only thing that needs to be guaranteed
    beforehand is that there are two params. */
static void 
process_mov_pseudo(
    const struct etca_opc_info *opcode ATTRIBUTE_UNUSED,
    struct parse_info *pi
) {
#define KIND(idx) (pi->args[idx].kind)
// TODO: simple mem should include displacement but no register
#define SIMPLE_MEM(idx) (KIND(idx).memory && pi->args[idx].imm_expr.X_op == O_absent && pi->args[idx].memory.index_reg == -1)
    // simple MEM <- reg: store
    if (SIMPLE_MEM(0) && KIND(1).reg_class == GPR) {
        struct etca_opc_info *store = str_hash_find(opcode_hash_control, "store");
        struct etca_arg mem = pi->args[0];
        pi->params.kinds.rr = 1;
        pi->args[0] = pi->args[1]; // store #0 is store source, but we have that at #1
        pi->args[1].kind = (struct etca_arg_kind){0}; // 0 out whatever kind info we had
        pi->args[1].kind.reg_class = GPR; // and we have a GPR
        pi->args[1].reg.gpr_reg_num = mem.memory.base_reg; // specifically the base addr reg
        // pi->args[1].reg_size = -1; // size is already computed so we can skip this
        assemble_base_abm(store, pi);
        return;
    }
    // reg <- simple MEM: load
    if (KIND(0).reg_class == GPR && SIMPLE_MEM(1)) {
        struct etca_opc_info *load = str_hash_find(opcode_hash_control, "load");
        pi->params.kinds.rr = 1;
        pi->args[1].kind = (struct etca_arg_kind){0}; // erase kind info
        pi->args[1].kind.reg_class = GPR; // instead we have a GPR
        pi->args[1].reg.gpr_reg_num = pi->args[1].memory.base_reg; // the base addr reg
        // pi->args[1].memory = (?){0}; // no need, assemble_base_abm won't look at this
        // pi->args[1].reg_size = -1; // size is already computed so no need for this
        assemble_base_abm(load, pi);
        return;
    }
    // two (GP) registers, or GPR and (any) MEM, or (any) MEM and GPR: it's just movs.
    if ((KIND(0).reg_class == GPR && KIND(1).reg_class == GPR)
        || (KIND(0).reg_class == GPR && KIND(1).memory)
        || (KIND(0).memory && KIND(1).reg_class == GPR)) {
        struct etca_opc_info *movs = str_hash_find(opcode_hash_control, "movs");
        pi->params.kinds.rr = 1;
        assemble_base_abm(movs, pi);
        return;
    }
    // GP register <- CTRL register: readcr
    if (KIND(0).reg_class == GPR && KIND(1).reg_class == CTRL) {
        struct etca_opc_info *readcr = str_hash_find(opcode_hash_control, "readcr");
        pi->params.kinds.rc = 1;
        assemble_base_abm(readcr, pi);
        return;
    }
    // CTRL register <- GP register: writecr
    // remember writecr needs the ctrl reg on the right, so we have to swap them!
    if (KIND(0).reg_class == CTRL && KIND(1).reg_class == GPR) {
        struct etca_opc_info *writecr = str_hash_find(opcode_hash_control, "writecr");
        struct etca_arg tmp = pi->args[0];
        pi->args[0] = pi->args[1];
        pi->args[1] = tmp;
        pi->params.kinds.rc = 1;
        assemble_base_abm(writecr, pi);
        return;
    }
    // GP register <- IMM
    // This is the large-immediate mov pseudo. It's mainly handled in elf32-etca.c,
    // but we need to construct the correct fixup if the immediate isn't concrete.
    if (KIND(0).reg_class == GPR && KIND(1).immAny) {
	char *output;

	size_t byte_count = etca_calc_mov_ri_byte_count(
		&settings.current_cpuid,
		pi->opcode_size,
		pi->args[0].reg.gpr_reg_num,
		KIND(1).immConc ? (&pi->args[1].imm_expr.X_add_number) : NULL);
	output = frag_more(byte_count);
	enum elf_etca_reloc_type reloc_kind = etca_build_mov_ri(
		&settings.current_cpuid,
		pi->opcode_size,
		pi->args[0].reg.gpr_reg_num,
		KIND(1).immConc ? (&pi->args[1].imm_expr.X_add_number) : NULL,
		output);
	if (!KIND(1).immConc) {
	    fix_new_exp(frag_now,
		(output - frag_now->fr_literal),
		byte_count,
		&pi->args[1].imm_expr,
		false,
		(bfd_reloc_code_real_type) (BFD_RELOC_ETCA_BASE_JMP - 1 + reloc_kind));
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
        struct etca_opc_info *push = str_hash_find(opcode_hash_control, "push");
        pi->params.kinds.rr = KIND(1).reg_class == GPR;
        pi->params.kinds.ri = KIND(1).immAny;
        // replace the predec arg with just a GPR of the same regnum.
        pi->args[0].kind = (struct etca_arg_kind){0};
        pi->args[0].kind.reg_class = GPR;
        // pi->args[0].reg.gpr_reg_num is already set correctly!
        assemble_base_abm(push, pi);
        return;
    }
    // reg <- predec/postinc: ASP pop
    // Once again, if we parsed this, we know we have ASP (and therefore SAF).
    // Enforce that the right arg is postinc.
    if (KIND(0).reg_class == GPR && (KIND(1).predec || KIND(1).postinc)) {
        if (KIND(1).predec) {
            as_bad("ptr predec can only be the first operand of `mov'");
        }
        struct etca_opc_info *pop = str_hash_find(opcode_hash_control, "pop");
        pi->params.kinds.rr = 1;
        // replace postinc arg with GPR of the same regnum.
        pi->args[1].kind = (struct etca_arg_kind){0};
        pi->args[1].kind.reg_class = GPR;
        assemble_base_abm(pop, pi);
        return;
    }

    as_bad("bad operands for `mov'");

#undef KIND
}

enum abm_mode {
    invalid,
    ri_byte,
    abm_00,
};

// Not declared above since it's a local implementation detail that depends on the above enum.
static enum abm_mode find_abm_mode(const struct etca_opc_info *opcode, struct parse_info *pi);

static void assemble_abm(const struct etca_opc_info *, struct parse_info *, enum abm_mode);

/* Analyze the parse_info and the opcode to determine what needs to be done to
 * emit the ABM byte before assemble_abm takes over
 * (i.e. what assemble_base_abm and assemble_exop_abm need to do)
 * This includes:
 * - Correctly indicate format between RI and ABM (when return value == ri_byte)
 * - Emit an REX prefix (not implemented)
 * The returned int is to be passed to assemble_abm which uses it to shortcut
 * instead of reanalyzing everything. If the return value is 'invalid', `as_bad`
 * has been called and we should stop assembling.
 *
 * Will modify *pi to make small adjustments as needed
 * */
static enum abm_mode find_abm_mode(const struct etca_opc_info *opcode, struct parse_info *pi) {
#define IS_VALID_REG(idx) (pi->args[idx].reg.gpr_reg_num >= 0 && pi->args[idx].reg.gpr_reg_num <= 15)
#define IS_REX_REG(idx) (pi->args[idx].reg.gpr_reg_num > 7)
    if (pi->params.kinds.rr) {
	if (!IS_VALID_REG(0)) {
	    as_bad("Invalid register number");
	    return invalid;
	}
	if (!IS_VALID_REG(1)) {
	    as_bad("Invalid register number");
	    return invalid;
	}
	if (IS_REX_REG(0)) {
	    as_bad("REX extension not implemented");
	    return invalid;
	}
	if (IS_REX_REG(1)) {
	    as_bad("REX extension not implemented");
	    return invalid;
	}
	return abm_00;
    } else if (pi->params.kinds.ri) {
        bool signed_imm = true;
	if (!IS_VALID_REG(0)) {
	    as_bad("Invalid register number");
	    return invalid;
	}
	if (IS_REX_REG(0)) {
	    as_bad("REX extension not implemented");
	    return invalid;
	}

        // is the immediate well-sized? We have no support for FI right now.
        if (opcode->format == ETCA_IF_BASE_ABM && ETCA_BASE_ABM_IMM_UNSIGNED(opcode->opcode)) {
            signed_imm = false;
        }

        if (signed_imm) {
            if (!pi->args[1].kind.imm5s)
                as_bad("bad immediate for `%s'", opcode->name);
        } else {
            if (!pi->args[1].kind.imm5z)
                as_bad("bad immediate for `%s'", opcode->name);
        }

	return ri_byte;
    } else if (pi->params.kinds.rc) {
        // readcr or writecr
        // can't encode a control register number more than 31;
        // we don't have any such yet, but ensure we get an error
        // if or when that happens.
        gas_assert(pi->args[1].reg.ctrl_reg_num < 32);
        // set the immediate value to the control reg number
        pi->args[1].imm_expr.X_add_number = pi->args[1].reg.ctrl_reg_num;
        // and encode an ri_byte.
        return ri_byte;
    } else {
	as_bad("Unknown params kind for assemble_abm");
	return invalid;
    }
#undef IS_VALID_REG
#undef IS_REX_REG
}

/* Assembles just an abm or ri byte, for use by assemble_base_abm and assemble_exop_abm
 * find_abm_mode needs to be called first and the mode passed in here. find_abm_mode
 * potentially does further setup that is required for this function to work.
 */
void assemble_abm(const struct etca_opc_info *opcode ATTRIBUTE_UNUSED, struct parse_info *pi, enum abm_mode mode) {
    char *output;
    size_t idx = 0;

    switch (mode) {
	case invalid: /* We shouldn't be called in this case */
	    abort();
	case ri_byte: /* We trust that find_abm_mode verified everything and set known_imm correctly */
	    output = frag_more(1);
	    output[idx++] = (pi->args[0].reg.gpr_reg_num << 5) | ((pi->args[1].imm_expr.X_add_number) & 0x1F);
	    return;
	case abm_00:
	    output = frag_more(1);
	    output[idx++] = (pi->args[0].reg.gpr_reg_num << 5) | (pi->args[1].reg.gpr_reg_num << 2) | 0b00;
	    return;
	default:
	    abort();
    }
}

/* Assemble a base-isa style instruction with arbitrary RI/ABM (as long as the current extensions support it)
 */
void assemble_base_abm(const struct etca_opc_info *opcode, struct parse_info *pi) {
    char *output;
    size_t idx = 0;
    // this is not at all correct, obviously, but useful for testing for now.
    int8_t size_attr = pi->opcode_size >= 0 ? pi->opcode_size : 0b01;
    enum abm_mode mode = find_abm_mode(opcode, pi);

    if (mode == invalid) { return; }

    // FIXME: This should probably be handled in slo's size_info field.
    if (opcode->name && !strcmp(opcode->name, "slo") && !pi->args[1].kind.imm5z) {
        as_bad("slo operand 2 must be a concrete unsigned 5-bit value");
    }

    if (mode == ri_byte) {
	output = frag_more(1);
	output[idx++] = (0b01000000 | size_attr << 4 | opcode->opcode);
    } else {
	output = frag_more(1);
	output[idx++] = (0b00000000 | size_attr << 4 | opcode->opcode);
    }
    assemble_abm(opcode, pi, mode);
}

/* Assemble a base-isa style jump instruction.
 */
void assemble_base_jmp(const struct etca_opc_info *opcode, struct parse_info *pi) {
    char *output;
    size_t idx = 0;

    output = frag_more(2);
    fixS *fixp = fix_new_exp(frag_now,
			     (output - frag_now->fr_literal),
			     2,
			     &pi->args[0].imm_expr,
			     true,
			     BFD_RELOC_ETCA_BASE_JMP);
    fixp->fx_signed = true;
    output[idx++] = (0b10000000 | opcode->opcode);
    output[idx++] = 0;
}

/* Assemble an SAF conditional register jump/call instruction. */
void assemble_saf_jmp(const struct etca_opc_info *opcode, struct parse_info *pi) {
    char *output;
    size_t idx = 0;
    gas_assert(pi->argc == 1 && pi->args[0].kind.reg_class == GPR);

    output = frag_more(2);
    output[idx++] = 0b10101111;
    // we put the opcodes in the table including the "call" bit.
    output[idx++] = (pi->args[0].reg.gpr_reg_num << 5) | opcode->opcode;
}

/* Assemble a SAF push or pop instruction. */
void assemble_saf_stk(const struct etca_opc_info *opcode, struct parse_info *pi) {
    // 12 => pop;  stack pointer belongs in the B operand
    // 13 => push; stack pointer belongs in the A operand
    gas_assert(opcode->opcode == 12 || opcode->opcode == 13);
    gas_assert(pi->argc == 1);

    // Kind r => rr. Kind i => ri. Kind m needs depends on which opcode we have.
    pi->params.kinds.rr = pi->params.kinds.r;
    pi->params.kinds.ri = pi->params.kinds.i;
    pi->params.kinds.r  = pi->params.kinds.i = 0;
    gas_assert(pi->params.kinds.rr || pi->params.kinds.ri || pi->params.kinds.m);

    if (opcode->opcode == 12) {
        // parsed operand is already in the A operand. Just pull in stack pointer...
        pi->argc = 2;
        pi->args[1].kind.reg_class = GPR;
        pi->args[1].reg.gpr_reg_num = 6; // #define this somewhere? or maybe an enum?
        assemble_base_abm(opcode, pi);
        return;
    } else if (opcode->opcode == 13) {
        // parsed operand is in the A operand, but must be moved to B.
        pi->argc = 2;
        pi->args[1] = pi->args[0];
        pi->args[0].kind.reg_class = GPR;
        pi->args[0].reg.gpr_reg_num = 6;
        assemble_base_abm(opcode, pi);
        return;
    }
}
