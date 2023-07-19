
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

const char comment_chars[] = ";";
const char line_separator_chars[] = ";";
const char line_comment_chars[] = ";";

static int pending_reloc;
static htab_t opcode_hash_control;

const pseudo_typeS md_pseudo_table[] =
	{
		{0, 0, 0}
	};

const char FLT_CHARS[] = "rRsSfFdDxXpP";
const char EXP_CHARS[] = "eE";

struct etca_opcode_set {
    const char *name;
    size_t count;
    size_t potential_iformats;
    const struct etca_opc_info *opcodes[];
};
enum etca_argtype {
    ERROR,
    REG,
    EXPR
};
/* This macro should always be large enough to contain all combinations of etca_argtype*/
#define ARGS(a, b) ((a * 010) + b)

struct etca_argument {
    enum etca_argtype type;
    union {
	struct {
	    uint8_t index;
	    int8_t size;
	} reg;
	expressionS expr;
    };
};

int8_t parse_size_byte(char value);

int8_t parse_size_byte(char value) {
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

char *parse_register_name(char *str, struct etca_argument *result);

char *parse_register_name(char *str, struct etca_argument *result) {
    if (*str == 'r') { /* Numeric register reference */
	str++;
	if ((result->reg.size = parse_size_byte(*str)) > 0) {
	    str++;
	} else {
	    /* TODO: pedantic check */
	}
	/* Probably should be rewritten to use something like strtol and provide a good error message */
	if (*str == '1' && '0' <= *(str + 1) && *(str + 1) <= '5') {
	    result->reg.index = 10 + (*(str + 1) - '0');
	    str += 2;
	} else if ('0' <= *str && *str <= '9') {
	    result->reg.index = *str - '0';
	    str++;
	} else {
	    result->type = ERROR;
	    return NULL;
	}
	return str;
    } else {
	const char (*reg_name)[3];
	for (reg_name = &etca_register_saf_names[0],
		     result->reg.index = 0;
	     result->reg.index < 16;
	     result->reg.index++, reg_name++) {
	    if ((*reg_name)[0] == *str && (*reg_name)[1] == *(str + 1)) {
		str += 2;
		if ((result->reg.size = parse_size_byte(*str)) > 0) {
		    str++;
		} else {
		    /* TODO: pedantic check */
		}
		return str;
	    }
	}
	result->type = ERROR;
	return NULL;
    }
}

char *parse_operand(char *str, struct etca_argument *result);

char *parse_operand(char *str, struct etca_argument *result) {
    while (*str == ' ')
	str++;
    switch (*str) {
	case '%':
	    result->type = REG;
	    str++;
	    return parse_register_name(str, result);
	default: {
	    char *save = input_line_pointer;
	    input_line_pointer = str;
	    expression(&result->expr);
	    str = input_line_pointer;
	    input_line_pointer = save;
	    result->type = EXPR;
	    return str;
	}
    }
}

const struct etca_opc_info *find_opcode(struct etca_opcode_set *opc_set, enum etca_iformat target);

const struct etca_opc_info *find_opcode(struct etca_opcode_set *opc_set, enum etca_iformat target) {
    for (size_t i = 0; i < opc_set->count; ++i) {
	if (opc_set->opcodes[i]->format == target) {
	    return opc_set->opcodes[i];
	}
    }
    return NULL;
}

void
md_operand(expressionS *op __attribute__((unused))) {
    /* Empty for now. */
}

void add_opcode_to_table(const struct etca_opc_info *opcode);

void add_opcode_to_table(const struct etca_opc_info *opcode) {
    if (opcode->name) {
	/* TODO: allocating the arrays here dynamically is inefficient and we can never free them. */
	struct etca_opcode_set *opc_set = str_hash_find(opcode_hash_control, opcode->name);
	if (opc_set) {
	    opc_set = XRESIZEVAR(
	    struct etca_opcode_set, opc_set, sizeof(struct etca_opcode_set) +
					     sizeof(struct etca_opc_info *) * (opc_set->count + 1));
	    opc_set->count = opc_set->count + 1;
	    opc_set->potential_iformats |= opcode->format;
	    opc_set->opcodes[opc_set->count - 1] = opcode;
	} else {
	    opc_set = XNEWVAR(
	    struct etca_opcode_set, sizeof(struct etca_opcode_set) +
				    sizeof(struct etca_opc_info *) * (1));
	    opc_set->name = opcode->name;
	    opc_set->count = 1;
	    opc_set->potential_iformats = opcode->format;
	    opc_set->opcodes[0] = opcode;
	}
	str_hash_insert(opcode_hash_control, opcode->name, opc_set, 1);
    }

}

/* This function is called once, at assembler startup time.  It sets
   up the hash table with all the opcodes in it, and also initializes
   some aliases for compatibility with other assemblers.  */

void
md_begin(void) {
    const struct etca_opc_info *opcode;
    opcode_hash_control = str_htab_create();
    size_t count;

    /* Insert names into hash table.  */
    for (count = 0, opcode = etca_base_rr; count++ < 16; opcode++) {
	add_opcode_to_table(opcode);
    }
    /* Insert names into hash table.  */
    for (count = 0, opcode = etca_base_ri; count++ < 16; opcode++) {
	add_opcode_to_table(opcode);
    }
    /* Insert names into hash table.  */
    for (count = 0, opcode = etca_base_jmp; count++ < 16; opcode++) {
	add_opcode_to_table(opcode);
    }
    bfd_set_arch_mach(stdoutput, TARGET_ARCH, 0);
}

/* This is the guts of the machine-dependent assembler.  STR points to
   a machine dependent instruction.  This function is supposed to emit
   the frags/bytes it assembles to.  */

void
md_assemble(char *str) {
    char *op_start;
    char *op_end;

    const struct etca_opc_info *opcode;
    struct etca_opcode_set *opc_set;
    char *output;
    int idx = 0;
    int size_marker = -1;
    char pend;

    int nlen = 0;
    struct etca_argument a = {ERROR};
    struct etca_argument b = {ERROR};

    /* Drop leading whitespace.  */
    while (*str == ' ')
	str++;

    /* Find the op code end.  */
    op_start = str;
    op_end = str;
    while ((*op_end) && !is_end_of_line[(*op_end) & 0xff] && (*op_end) != ' ') {
	op_end++;
	nlen++;
    }

    if (nlen == 0) {
	as_bad(_("can't find opcode "));
    }
    /* Check for a size marker before looking up the opcode*/
    if (nlen > 1) {
	if ((size_marker = parse_size_byte(*(op_end - 1))) > 0) {
	    op_end--;
	    *op_end = ' '; /* Replace the size marker with a space: We dealt with it, it's no longer needed*/
	}
    }

    pend = *op_end;
    *op_end = 0;

    opc_set = (struct etca_opcode_set *) str_hash_find(opcode_hash_control, op_start);
    *op_end = pend;

    if (opc_set == NULL) {
	as_bad(_("unknown opcode %s"), op_start);
	return;
    }
    str = op_end;
    while (ISSPACE(*str)) str++;

    char *arg_end = parse_operand(str, &a);
    if (!arg_end) {
	as_bad("Expected at least on argument");
	return;
    }
    str = arg_end;
    while (ISSPACE(*str)) str++;

    if (*str == ',') {
	str++;
	while (ISSPACE(*str)) str++;
	arg_end = parse_operand(str, &b);
	if (!arg_end) {
	    as_bad("Expected a second argument after ','");
	    return;
	}
	str = arg_end;
    }
    switch (ARGS(a.type, b.type)) {
	case ARGS(REG, REG):
	    if ((opc_set->potential_iformats & ETCA_IF_BASE_RR) == 0) {
		as_bad("Illegal argument combination reg-reg for opcode %s", opc_set->name);
		return;
	    }
	    if ((a.reg.index > 7) || (b.reg.index > 7)) {
		as_bad("Illegal register index");
		return;
	    }
	    opcode = find_opcode(opc_set, ETCA_IF_BASE_RR);
	    output = frag_more(2);
	    output[idx++] = (0b00000000 | (((size_marker > 0) ? size_marker : 0b01) << 4) | opcode->opcode);
	    output[idx++] = (a.reg.index << 5) | (b.reg.index << 2) | 0b00;
	    break;
	case ARGS(REG, EXPR):
	    if ((opc_set->potential_iformats & ETCA_IF_BASE_RI) == 0) {
		as_bad("Illegal argument combination reg-imm for opcode %s", opc_set->name);
		return;
	    }
	    if ((a.reg.index > 7)) {
		as_bad("Illegal register index");
		return;
	    }
	    opcode = find_opcode(opc_set, ETCA_IF_BASE_RI);
	    output = frag_more(2);  /* TODO: For the general case, we need to use a fixup here */
	    if (b.expr.X_op != O_constant) {
		as_bad("Can't deal with complex expressions right now :-(");
		return;
	    }
	    output[idx++] = (0b01000000 | (((size_marker > 0) ? size_marker : 0b01) << 4) | opcode->opcode);
	    output[idx++] = (a.reg.index << 5) | (b.expr.X_add_number & 0x1F);
	    break;
	case ARGS(EXPR, ERROR):
	    if ((opc_set->potential_iformats & ETCA_IF_BASE_JMP) == 0) {
		as_bad("Illegal argument combination imm for opcode %s", opc_set->name);
		return;
	    }
	    opcode = find_opcode(opc_set, ETCA_IF_BASE_JMP);
	    output = frag_more(2);  /* TODO: For the general case, we need to use a fixup here */
	    if (a.expr.X_op != O_constant) {
		as_bad("Can't deal with complex expressions right now :-(");
		return;
	    }
	    output[idx++] = (0b10000000 | ((a.expr.X_add_number & 0x100) ? 0x10 : 0) | opcode->opcode);
	    output[idx++] = a.expr.X_add_number & 0xFF;
	    break;
	default:
	    as_bad("Illegal argument combination %o", ARGS(a.type, b.type));
	    return;
    }


    while (ISSPACE(*str)) {
	str++;
    }


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

/* Put number into target byte order (little endian).  */

void
md_number_to_chars(char *ptr, valueT use, int nbytes) {
    number_to_chars_littleendian(ptr, use, nbytes);
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