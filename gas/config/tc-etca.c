
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

    /* Non-null if we have an expression immediate. If we have an immediate,
        but this is illegal or absent, then the exact value is in known_imm. */
    // TODO: Since this is not a pointer, this behavior probably doesn't make sense
    struct expressionS imm_expr;
    /* The exact value of an immediate if we have one and imm_expr is NULL. */
    uint64_t known_imm;

    /* See imm_expr, but for displacements. */
    struct expressionS disp_expr;
    /* See known_imm, but for displacements. */
    uint64_t known_disp;

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
typedef void(*assembler)(const struct etca_opc_info*, struct parse_info*);

int8_t parse_size_attr(char value);
char *parse_register_name(char *str, struct etca_arg *result);
char *parse_operand(char *str, struct etca_arg *result);
bool compute_params(struct parse_info*pi);
void assemble_base_abm(const struct etca_opc_info*, struct parse_info*);

#define TRY_PARSE_SIZE_ATTR(lval, c) (((lval) = parse_size_attr(c)) >= 0)

struct etca_cpuid current_cpuid = ETCA_CPI_BASE;

static assembler macro_functions[1] = {
        0, /* mov */
};
static assembler format_assemblers[ETCA_IFORMAT_COUNT] = {
        0, /* ILLEGAL */
        0, /* SPECIAL (handled via macro_functions) */
        0, /* MACRO (handled via macro_functions) */
        assemble_base_abm, /* BASE_ABM */
        0, /* EXOP_ABM */
        0, /* BASE_JMP */
};


const char comment_chars[] = ";";
/* Additional characters beyond newline which should be treated as line separators.
  ETCa has none. */
const char line_separator_chars[] = "";
const char line_comment_chars[] = ";";

/* These are extra characters (beyond $ . _ and alphanum) which may appear
   in ETCa operands. % is a register prefix and [ is used for memory operands.
   We only need to give ones that might start operands. This affects the way in
   which GAS removes whitespace before passign the string to `md_assemble`. */
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

int8_t parse_size_attr(char value) {
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

char *parse_register_name(char *str, struct etca_arg *result) {
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

char *parse_operand(char *str, struct etca_arg *result) {
    while (ISSPACE(*str)) str++;
    switch (*str) {
        case '%':
            str++;
            return parse_register_name(str, result);
        default: {
            char *save = input_line_pointer;
            input_line_pointer = str;
            expression(&result->imm_expr);
            str = input_line_pointer;
            input_line_pointer = save;
            result->kind.immAny = 1; // TODO: This needs to actually be set correctlly...
            return str;
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

bool compute_params(struct parse_info*pi){
#define IS_REG(arg) ((arg).kind.reg_class == GPR)
#define IS_IMM(arg) ((arg).kind.immAny || (arg).kind.imm5 || (arg.kind.imm8))
    /* This can probably be solved better... */
    if(pi->argc == 0) {
        pi->params.kinds.e = 1;
        return true;
    } else if (pi->argc == 1) {
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
        if (IS_REG(pi->args[0])) {
            if (IS_IMM(pi->args[1])) {
                pi->params.kinds.ri = 1;
                return true;
            } else if(IS_REG(pi->args[1])) {
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
}

/* This is the guts of the machine-dependent assembler.  STR points to
   a machine dependent instruction.  This function is supposed to emit
   the frags/bytes it assembles to.  */

void
md_assemble(char *str) {
    char *op_start;
    char *op_end;

    const struct etca_opc_info * opcode;
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
        while(ISSPACE(*str)) str++;
        if (*str != ',') break;
        str++;
        while(ISSPACE(*str)) str++;
    }
    assembler assembly_function;
    if(opcode->format != ETCA_IF_SPECIAL) {
        if(!compute_params(&pi)) {
            as_bad("Unknown argument pairing");
            return;
        }
        uint32_t bit_to_test = pi.params.uint;
        while (
                ((opcode->params.uint & bit_to_test) != bit_to_test
                || !etca_match_cpuid_pattern(&opcode->requirements, &current_cpuid))
                &&
                opcode->try_next_assembly) {
            opcode++;
        }
        if ((opcode->params.uint & bit_to_test) != bit_to_test
            || !etca_match_cpuid_pattern(&opcode->requirements, &current_cpuid)) {
            as_bad("Unsupported argument pairing for this opcode and cpuid");
            return;
        }
    }
    if (opcode->format == ETCA_IF_SPECIAL || opcode->format == ETCA_IF_MACRO) {
        assembly_function = macro_functions[opcode->opcode];
    } else {
        assembly_function = format_assemblers[opcode->format];
    }
    if (!assembly_function) {
        fprintf(stderr, "Missing for %s (%d)\n", opcode->name, opcode->format);
        abort();
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

struct option md_longopts[] =
        {
                {NULL, no_argument, NULL, 0}
        };
size_t md_longopts_size = sizeof(md_longopts);

/* We have no target specific options yet, so these next
   two functions are empty.  */
int
md_parse_option(int c ATTRIBUTE_UNUSED, const char *arg ATTRIBUTE_UNUSED) {
    return 0;
}

void
md_show_usage(FILE *stream ATTRIBUTE_UNUSED) {
}

/* Apply a fixup to the object file.  */

void
md_apply_fix(fixS *fixP ATTRIBUTE_UNUSED, valueT *valP ATTRIBUTE_UNUSED, segT seg ATTRIBUTE_UNUSED) {
    /* Empty for now.  */
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

void assemble_base_abm(const struct etca_opc_info *opcode, struct parse_info*pi) {
    char *output;
    size_t idx = 0;

    if(pi->params.kinds.rr) {
        fprintf(stderr, "Calling frag_more(2)\n");
        output = frag_more(2);
        output[idx++] = (0b00000000 | (((pi->opcode_size > 0) ? pi->opcode_size : 0b01) << 4) | opcode->opcode);
        output[idx++] = (pi->args[0].reg.gpr_reg_num << 5) | (pi->args[0].reg.gpr_reg_num << 2) | 0b00;
        fprintf(stderr, "Outputted %hhx %hhx\n", output[0], output[1]);
    } else {
        abort();
    }
}
