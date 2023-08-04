
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
     */
    struct expressionS imm_expr;

    /* See imm_expr, but for displacements. */
    struct expressionS disp_expr;

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
    int8_t opcode_size; /* The size marker attached to the opcode, one of -1 (none),0 (h),1 (x),2 (d),3 (q)*/
    union etca_opc_params_field params;
    size_t argc;
    struct etca_arg args[MAX_OPERANDS];
    // struct etca_prefix prefixes[MAX_PREFIXES]; // (or would it be better to hace the indvidual prefixes seperated?
};

/* An opcode-assembler function.
Takes the opc_info being assembled, and should confirm that it actually handles that opcode.
Similarly, should confirm that the params_kind it got is expected. */
typedef void(*assembler)(const struct etca_opc_info *, struct parse_info *);

static int parse_extension_list(const char *extensions, struct etca_cpuid *out);

static int8_t parse_size_attr(char value);

static char *parse_register_name(char *str, struct etca_arg *result);

static char *parse_immediate(char *str, struct etca_arg *result);

static char *parse_memory_location(char *str, struct etca_arg *result);

static char *parse_memory_upper(char *str, struct etca_arg *result);

static char *parse_operand(char *str, struct etca_arg *result);

static bool compute_params(struct parse_info *pi);

static void assemble_base_abm(const struct etca_opc_info *, struct parse_info *);
static void assemble_base_jmp(const struct etca_opc_info *, struct parse_info *);

#define TRY_PARSE_SIZE_ATTR(lval, c) (((lval) = parse_size_attr(c)) >= 0)

/* The known predefined archs. Needs to be kept in sync with gcc manually */
struct etca_known_archs {
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
} settings = {
	.current_cpuid = ETCA_CPI_BASE,
	.march = "",
	.march_cpuid = ETCA_CPI_BASE,
	.mextensions = ETCA_CPI_BASE,
	.arch_name = 0,
	.custom_name = 0,
	.manual_cpuid = 0,
};


static assembler pseudo_functions[1] = {
	0, /* mov */
};
static assembler format_assemblers[ETCA_IFORMAT_COUNT] = {
	0, /* ILLEGAL */
	0, /* SPECIAL (handled via pseudo_functions) */
	0, /* PSEUDO (handled via pseudo_functions) */
	assemble_base_abm, /* BASE_ABM */
	0, /* EXOP_ABM */
	assemble_base_jmp, /* BASE_JMP */
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

/* Parse a register (numeric, SaF or Control, REX) name into it's numeric value and puts it into result,
 * setting the kind to one of GPR or CTRL and storing the correct register index
 * Will parse a size attr and also set that in result.
 * If it fails to parse a register, it will *not* call as_bad and return NULL
 * // TODO: We should be calling as_bad
 */
static char *parse_register_name(char *str, struct etca_arg *result) {
    if (*str == 'r') { /* Numeric register reference */
	str++;
	if (TRY_PARSE_SIZE_ATTR(result->reg_size, *str)) {
	    str++;
	} else {
	    /* TODO: pedantic check */
	}
	/* Probably should be rewritten to use something like strtol and provide a good error message */
	if (*str == '1' && '0' <= *(str + 1) && *(str + 1) <= '5') {
	    result->reg.gpr_reg_num = 10 + (*(str + 1) - '0');
	    str += 2;
	} else if ('0' <= *str && *str <= '9') {
	    result->reg.gpr_reg_num = *str - '0';
	    str++;
	} else {
	    return NULL;
	}
	result->kind.reg_class = GPR;
	return str;
    } else {
	const char (*reg_name)[3];
	for (reg_name = &etca_register_saf_names[0],
		     result->reg.gpr_reg_num = 0;
	     result->reg.gpr_reg_num < 16;
	     result->reg.gpr_reg_num++, reg_name++) {
	    if ((*reg_name)[0] == *str && (*reg_name)[1] == *(str + 1)) {
		str += 2;
		if (TRY_PARSE_SIZE_ATTR(result->reg_size, *str)) {
		    str++;
		} else {
		    /* TODO: pedantic check */
		}
		result->kind.reg_class = GPR;
		return str;
	    }
	}
	return NULL;
    }
}

/* Parse a potentially complex immediate expression and analyze it as far as possible.
 */
static char *parse_immediate(char *str, struct etca_arg *result) {
    char *save = input_line_pointer;
    input_line_pointer = str;
    expression(&result->imm_expr);
    str = input_line_pointer;
    input_line_pointer = save;
    offsetT value;

    switch (result->imm_expr.X_op) {
	case O_constant:
	    value = result->imm_expr.X_add_number;
	    result->kind.immAny = 1;
	    result->kind.immZ = (value >= 0); // This isn't necessarily correct...
	    result->kind.immS = 1; // Neither is this
	    result->kind.imm8 = (-128 <= value && value <= 255);
	    result->kind.imm5 = (-16 <= value && value <= 32);
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

    return str;
}

/* Parse a non-nested memory location, setting the fields in result correctly.
 */
static char *parse_memory_location(char *str ATTRIBUTE_UNUSED, struct etca_arg *result ATTRIBUTE_UNUSED) {
    as_fatal("Memory location syntax not implemented");
    return NULL;
}

/* Parse a potentially nested-or-ASP memory location reference.
 */
static char *parse_memory_upper(char *str, struct etca_arg *result) {
    parse_memory_location(str, result);
    return NULL;
}

/* Parse an arbitrary component, deferring to the correct parse_* function.
 */
char *parse_operand(char *str, struct etca_arg *result) {
    while (ISSPACE(*str)) str++;
    switch (*str) {
	case '%':
	    str++;
	    return parse_register_name(str, result);
	case '[':
	    str++;
	    return parse_memory_upper(str, result);
	default: {
	    return parse_immediate(str, result);
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
    opcode_hash_control = str_htab_create();

    /* Insert names into hash table.  */
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
}

/* Based on the list of parsed arguments, correctly set pi->params.
 */
bool compute_params(struct parse_info *pi) {
#define IS_REG(arg) ((arg).kind.reg_class == GPR)
#define IS_IMM(arg) ((arg).kind.immAny || (arg).kind.imm5 || (arg.kind.imm8))
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
    char *op_start;
    char *op_end;

    const struct etca_opc_info *opcode;
    struct parse_info pi = {
	    .opcode_size = -1,
	    .params = {.uint = 0},
	    .argc = 0,
	    .args = {}
    };
    // char *output;
    // int idx = 0;
    char pend;

    int nlen = 0;

    /* Drop leading whitespace.  */
    while (ISSPACE(*str)) str++;

    /* Find the op code end.  */
    op_start = str;
    op_end = str;
    while ((*op_end) && !is_end_of_line[(*op_end) & 0xff] && !ISSPACE(*op_end)) {
	op_end++;
	nlen++;
    }

    if (nlen == 0) {
	as_bad(_("can't find opcode "));
	return;
    }
    /* Check for a size marker before looking up the opcode*/
    if (nlen > 1) {
	if ((pi.opcode_size = parse_size_attr(*(op_end - 1))) > 0) {
	    op_end--;
	    *op_end = ' '; /* Replace the size marker with a space: We dealt with it, it's no longer needed*/
	}
    }

    pend = *op_end;
    *op_end = 0;

    opcode = (struct etca_opc_info *) str_hash_find(opcode_hash_control, op_start);
    *op_end = pend;

    if (opcode == NULL) {
	as_bad(_("unknown opcode %s"), op_start);
	return;
    }
    str = op_end;
    if (opcode->format == ETCA_IF_ILLEGAL) {
	as_bad("Illegal opcode %s", op_start);
	return;
    }

    while (ISSPACE(*str)) str++;
    while (*str != 0 && pi.argc < MAX_OPERANDS) {
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
	    as_bad("Unsupported argument pairing for this opcode and cpuid");
	    return;
	}
    }
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
 *  -march=extensions(.ABBR)+    (name defaults to `base`)
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
};

struct option md_longopts[] =
	{
		{"march",       required_argument, NULL, OPTION_MARCH},
		{"mextensions", required_argument, NULL, OPTION_MEXTENSIONS},
		{"mcpuid",      required_argument, NULL, OPTION_MCPUID},
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
	    /* We only actually analyze the name in md_after*/
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
	    return parse_hex_cpuid((char *) arg, &settings.march_cpuid);;
	default:
	    return 0;
    }
}

void
md_show_usage(FILE *stream) {
    fprintf (stream, " ETCa-specific assembler options:\n");
    fprintf (stream, "\t-march=name[+ABBR(.ABBR)*]\t");
    fprintf (stream, "\t\t\tSpecify an architecture name as well as optionally a list of extensions implemented on top of it");
}

/* Check that our arguments, especially the given -march and -mcpuid make sense*/
void etca_after_parse_args(void) {
    settings.current_cpuid.cpuid1 |= settings.mextensions.cpuid1 | settings.march_cpuid.cpuid1;
    settings.current_cpuid.cpuid2 |= settings.mextensions.cpuid2 | settings.march_cpuid.cpuid2;
    settings.current_cpuid.feat |= settings.mextensions.feat | settings.march_cpuid.feat;
    /* TODO: Checks */
}

/* Apply a fixup to the object file.  */

void
md_apply_fix(fixS *fixP ATTRIBUTE_UNUSED, valueT *valP ATTRIBUTE_UNUSED, segT seg ATTRIBUTE_UNUSED) {
    printf("md_apply_fix\n");
}

/* Translate internal representation of relocation info to BFD target
   format.  */

arelent *
tc_gen_reloc(asection *section ATTRIBUTE_UNUSED, fixS *fixp) {
    printf("tc_gen_reloc\n");
    arelent *rel;
    bfd_reloc_code_real_type r_type;

    rel = xmalloc(sizeof(arelent));
    rel->sym_ptr_ptr = xmalloc(sizeof(asymbol * ));
    *rel->sym_ptr_ptr = symbol_get_bfdsym(fixp->fx_addsy);
    rel->address = fixp->fx_frag->fr_address + fixp->fx_where;

    r_type = fixp->fx_r_type;
    rel->addend = fixp->fx_addnumber;
    rel->howto = bfd_reloc_type_lookup(stdoutput, r_type);

    if (rel->howto == NULL) {
	as_bad_where(fixp->fx_file, fixp->fx_line,
		     _("Cannot represent relocation type %s"),
		     bfd_get_reloc_code_name(r_type));
	/* Set howto to a garbage value so that we can keep going.  */
	rel->howto = bfd_reloc_type_lookup(stdoutput, BFD_RELOC_32);
	assert(rel->howto != NULL);
    }

    return rel;
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
static enum abm_mode find_abm_mode(const struct etca_opc_info *opcode ATTRIBUTE_UNUSED, struct parse_info *pi) {
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
	if (!IS_VALID_REG(0)) {
	    as_bad("Invalid register number");
	    return invalid;
	}
	if (IS_REX_REG(0)) {
	    as_bad("REX extension not implemented");
	    return invalid;
	}
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
	    output[idx++] = (pi->args[0].reg.gpr_reg_num << 5) | ((pi->args[0].imm_expr.X_add_number) & 0x1F);
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
    enum abm_mode mode = find_abm_mode(opcode, pi);
    if (mode == invalid) { return; }

    if (mode == ri_byte) {
	output = frag_more(1);
	output[idx++] = (0b01000000 | (((pi->opcode_size > 0) ? pi->opcode_size : 0b01) << 4) | opcode->opcode);
    } else {
	output = frag_more(1);
	output[idx++] = (0b00000000 | (((pi->opcode_size > 0) ? pi->opcode_size : 0b01) << 4) | opcode->opcode);
    }
    assemble_abm(opcode, pi, mode);
}

/* Assemble a base-isa style jump instruction, also supporting the SaF cond calls using the same format.
 */
void assemble_base_jmp(const struct etca_opc_info *opcode, struct parse_info *pi) {
    char *output;
    size_t idx = 0;

    output = frag_more(2);
    fix_new_exp (frag_now,
		 (output - frag_now->fr_literal),
		 2,
		 &pi->args[0].imm_expr,
		 true,
		 BFD_RELOC_ETCA_BASE_JMP);
    output[idx++] = (0b10000000 | opcode->opcode);
    output[idx++] = 0;
}
