//
// Created by MegaIng on 2023-07-18.
//

/* ETCa support for 32-bit ELF
   Copyright 2023 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/etca.h"
#include "opcode/etca.h"


#define sec_addr(sec) ((sec)->output_section->vma + (sec)->output_offset)

/* Forward declarations.  */
static reloc_howto_type *
etca_elf_rtype_to_howto(bfd *, unsigned int);

static bfd_reloc_status_type
perform_relocation(const reloc_howto_type *, const Elf_Internal_Rela *, bfd_vma, asection *, bfd *, bfd_byte *);


#define MINUS_ONE ((bfd_vma)0 - 1)

static reloc_howto_type etca_elf_howto_table [] =
{
    /* This reloc does nothing.  */
    HOWTO (R_ETCA_NONE,		/* type */
	   0,			/* rightshift */
	   0,			/* size */
	   0,			/* bitsize */
	   false,			/* pc_relative */
	   0,			/* bitpos */
	   complain_overflow_dont, /* complain_on_overflow */
	   bfd_elf_generic_reloc,	/* special_function */
	   "R_ETCA_NONE",		/* name */
	   false,			/* partial_inplace */
	   0,			/* src_mask */
	   0,			/* dst_mask */
	   false),		/* pcrel_offset */

    HOWTO (R_ETCA_BASE_JMP,	/* type */
	   0,			/* rightshift */
	   2,			/* size */
	   9,			/* bitsize */
	   true,		/* pc_relative */
	   0,			/* bitpos */
	   complain_overflow_signed, /* complain_on_overflow */
	   bfd_elf_generic_reloc,	/* special_function */
	   "R_ETCA_BASE_JMP",		/* name */
	   false,			/* partial_inplace */
	   0x00000000,		/* src_mask */
	   0xFF10,		/* dst_mask */
	   true),		/* pcrel_offset */
    HOWTO (R_ETCA_SAF_CALL,	/* type */
	   0,			/* rightshift */
	   2,			/* size */
	   12,			/* bitsize */
	   true,		/* pc_relative */
	   0,			/* bitpos */
	   complain_overflow_signed, /* complain_on_overflow */
	   bfd_elf_generic_reloc,	/* special_function */
	   "R_ETCA_SAF_CALL",		/* name */
	   false,			/* partial_inplace */
	   0x00000000,		/* src_mask */
	   0xFF0F,		/* dst_mask */
	   true),		/* pcrel_offset */
#define HOWTO_RIS(bytes, bits) HOWTO( \
		R_ETCA_ABM_RIS_ ## bits,            \
		0,                                  \
		bytes,                              \
		bits,                               \
		false,                              \
		0,                                  \
		complain_overflow_signed,           \
		bfd_elf_generic_reloc,              \
		"R_ETCA_ABM_RIS_" #bits,            \
		false,                              \
		0, \
		(bits == 64? MINUS_ONE : ((bfd_vma) 1 << bits) - 1), \
		false)
#define HOWTO_RIZ(bytes, bits) HOWTO( \
		R_ETCA_ABM_RIZ_ ## bits,            \
		0,                                  \
		bytes,                              \
		bits,                               \
		false,                              \
		0,                                  \
		complain_overflow_unsigned,           \
		bfd_elf_generic_reloc,              \
		"R_ETCA_ABM_RIZ_" #bits,            \
		false,                              \
		0, \
		(bits == 64? MINUS_ONE : ((bfd_vma) 1 << bits) - 1), \
		false)
    HOWTO_RIS(1, 5),
    HOWTO_RIZ(1, 5),
    HOWTO_RIS(1, 8),
    HOWTO_RIZ(1, 8),
    HOWTO_RIS(2, 16),
    HOWTO_RIZ(2, 16),
    HOWTO_RIS(4, 32),
    HOWTO_RIZ(4, 32),
    HOWTO_RIS(8, 64),
    HOWTO_RIZ(8, 64),
#undef HOWTO_RIZ
#undef HOWTO_RIS
#define HOWTO_MOV(bytes, bits) HOWTO( \
		R_ETCA_MOV_ ## bits,            \
		0,                                  \
		bytes,                              \
		bits,                               \
		false,                              \
		0,                              \
		complain_overflow_unsigned,           \
		bfd_elf_generic_reloc,              \
		"R_ETCA_MOV_" #bits,            \
		false,                              \
		0, \
		(bits == 64? MINUS_ONE : ((bfd_vma) 1 << bits) - 1) & 0x1F001F001F001F00, \
		false)
    HOWTO_MOV(2, 5),
    HOWTO_MOV(4, 10),
    HOWTO_MOV(6, 15),
    HOWTO_MOV(8, 16),
    HOWTO_MOV(8, 20),
    HOWTO_MOV(10, 25),
    HOWTO_MOV(12, 30),
    HOWTO_MOV(14, 32),
#undef HOWTO_MOV

};


static bfd_reloc_status_type
perform_relocation (const reloc_howto_type *howto,
		    const Elf_Internal_Rela *rel,
		    bfd_vma value,
		    asection *input_section,
		    bfd *input_bfd ATTRIBUTE_UNUSED,
		    bfd_byte *contents) {
    if (howto->pc_relative)
	value -= sec_addr (input_section) + rel->r_offset;
    value += rel->r_addend;
    contents += rel->r_offset;
    switch (ELF32_R_TYPE(rel->r_info)) {
	case R_ETCA_BASE_JMP:
	    contents[0] |= (value & 0x100) ? 0x10 : 0;
	    contents[1] = value & 0xFF;
	    return bfd_reloc_ok;
	case R_ETCA_MOV_16:
	    etca_build_mov_ri(NULL, 0b01, (contents[1] >> 5) & 7, (int64_t * ) & value, (char *) contents);
	    return bfd_reloc_ok;
	default:
	    return bfd_reloc_notsupported;
    }
}


/* Relocate an ETCa ELF section. Mostly copied from elfnn-riscv.c

   The RELOCATE_SECTION function is called by the new ELF backend linker
   to handle the relocations for a section.

   The relocs are always passed as Rela structures.

   This function is responsible for adjusting the section contents as
   necessary, and (if generating a relocatable output file) adjusting
   the reloc addend as necessary.

   This function does not have to worry about setting the reloc
   address or the reloc symbol index.

   LOCAL_SYMS is a pointer to the swapped in local symbols.

   LOCAL_SECTIONS is an array giving the section in the input file
   corresponding to the st_shndx field of each local symbol.

   The global hash table entry for the global symbols can be found
   via elf_sym_hashes (input_bfd).

   When generating relocatable output, this function must handle
   STB_LOCAL/STT_SECTION symbols specially.  The output symbol is
   going to be the section symbol corresponding to the output
   section, which means that the addend must be adjusted
   accordingly.  */

static int
etca_elf_relocate_section(bfd *output_bfd,
			  struct bfd_link_info *info,
			  bfd *input_bfd,
			  asection *input_section,
			  bfd_byte *contents,
			  Elf_Internal_Rela *relocs,
			  Elf_Internal_Sym *local_syms,
			  asection **local_sections) {

    Elf_Internal_Rela *rel;
    Elf_Internal_Rela *relend;
    Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr (input_bfd);
    struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (input_bfd);
    bool ret = false;
    relend = relocs + input_section->reloc_count;
    for (rel = relocs; rel < relend; rel++) {
	unsigned long r_symndx;
	struct elf_link_hash_entry *h;
	Elf_Internal_Sym *sym;
	asection *sec;
	bfd_vma relocation;
	bfd_reloc_status_type status = bfd_reloc_ok;
	const char *name = NULL;
	bool unresolved_reloc;
	int r_type = ELF32_R_TYPE(rel->r_info);
	reloc_howto_type *howto = etca_elf_rtype_to_howto(input_bfd, r_type);
	const char *msg = NULL;

	if (howto == NULL)
	    continue;

	/* This is a final link.  */
	r_symndx = ELF32_R_SYM(rel->r_info);
	h = NULL;
	sym = NULL;
	sec = NULL;
	unresolved_reloc = false;
	if (r_symndx < symtab_hdr->sh_info) {
	    sym = local_syms + r_symndx;
	    sec = local_sections[r_symndx];
	    relocation = _bfd_elf_rela_local_sym(output_bfd, sym, &sec, rel);

	    /* Relocate against local STT_GNU_IFUNC symbol.  */
	    if (!bfd_link_relocatable(info)
		&& ELF_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
		BFD_FAIL();
#if 0
		h = etca_elf_get_local_sym_hash(htab, input_bfd, rel, false);
		if (h == NULL)
		    abort ();

		/* Set STT_GNU_IFUNC symbol value.  */
		h->root.u.def.value = sym->st_value;
		h->root.u.def.section = sec;
#endif
	    }
	}
	else {
	    bool warned, ignored;

	    RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				     r_symndx, symtab_hdr, sym_hashes,
				     h, sec, relocation,
				     unresolved_reloc, warned, ignored);
	    if (warned) {
		/* To avoid generating warning messages about truncated
		   relocations, set the relocation's address to be the same as
		   the start of this section.  */
		if (input_section->output_section != NULL)
		    relocation = input_section->output_section->vma;
		else
		    relocation = 0;
	    }
	}

	if (sec != NULL && discarded_section(sec)) RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
										    rel, 1, relend, howto, 0, contents);

	if (bfd_link_relocatable(info))
	    continue;
	switch (r_type) {
	    case R_ETCA_NONE:
		continue;
	    case R_ETCA_MOV_16:
	    case R_ETCA_BASE_JMP:
		/* Nothing special to do*/
		break;
	    default:
		status = bfd_reloc_notsupported;
	}
	if (status == bfd_reloc_ok) {
	    status = perform_relocation(howto, rel, relocation, input_section, input_bfd, contents);
	}

	switch (status) {
	    case bfd_reloc_ok:
		continue;

	    case bfd_reloc_overflow:
		info->callbacks->reloc_overflow
			(info, (h ? &h->root : NULL), name, howto->name,
			 (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
		break;

	    case bfd_reloc_undefined:
		info->callbacks->undefined_symbol
			(info, name, input_bfd, input_section, rel->r_offset,
			 true);
		break;

	    case bfd_reloc_outofrange:
		if (msg == NULL)
		    msg = _("%X%P: internal error: out of range error\n");
		break;

	    case bfd_reloc_notsupported:
		if (msg == NULL)
		    msg = _("%X%P: internal error: unsupported relocation error\n");
		break;

	    case bfd_reloc_dangerous:
		/* The error message should already be set.  */
		if (msg == NULL)
		    msg = _("dangerous relocation error");
		info->callbacks->reloc_dangerous
			(info, msg, input_bfd, input_section, rel->r_offset);
		break;

	    default:
		msg = _("%X%P: internal error: unknown error\n");
		break;
	}
	/* Do not report error message for the dangerous relocation again.  */
	if (msg && status != bfd_reloc_dangerous)
	    info->callbacks->einfo (msg);

	/* We already reported the error via a callback, so don't try to report
	   it again by returning false.  That leads to spurious errors.  */
	ret = true;
	break;
    }
    ret = true;
    return ret;
}

/* Map BFD reloc types to ETCA ELF reloc types.  */

struct etca_reloc_map
{
    bfd_reloc_code_real_type bfd_reloc_val;
    unsigned int etca_reloc_val;
};

static const struct etca_reloc_map etca_reloc_map [] =
	{
#define PAIR(NAME) { BFD_RELOC_ETCA_ ## NAME,       	R_ETCA_ ## NAME }
	{ BFD_RELOC_NONE,	       R_ETCA_NONE },
	PAIR(BASE_JMP),
	PAIR(SAF_CALL),
	PAIR(ABM_RIS_5),
	PAIR(ABM_RIZ_5),
	PAIR(ABM_RIS_8),
	PAIR(ABM_RIZ_8),
	PAIR(ABM_RIS_16),
	PAIR(ABM_RIZ_16),
	PAIR(ABM_RIS_32),
	PAIR(ABM_RIZ_32),
	PAIR(ABM_RIS_64),
	PAIR(ABM_RIZ_64),
	PAIR(MOV_5),
	PAIR(MOV_10),
	PAIR(MOV_15),
	PAIR(MOV_16),
	PAIR(MOV_20),
	PAIR(MOV_25),
	PAIR(MOV_30),
	PAIR(MOV_32),
	PAIR(MOV_35),
	PAIR(MOV_40),
	PAIR(MOV_45),
	PAIR(MOV_50),
	PAIR(MOV_55),
	PAIR(MOV_60),
	PAIR(MOV_64),
#undef PAIR
	};

static reloc_howto_type *
etca_elf_rtype_to_howto(bfd *abfd ATTRIBUTE_UNUSED,
			unsigned int r_type) {
/* In theory r_type could/should be an index into etca_reloc_map.
 * But don't rely on that, at least not now. */
    unsigned int i;

    for (i = sizeof (etca_reloc_map) / sizeof (etca_reloc_map[0]); i--;)
	if (etca_reloc_map [i].etca_reloc_val == r_type)
	    return &etca_elf_howto_table[etca_reloc_map[i].etca_reloc_val];

    return NULL;
}

static reloc_howto_type *
etca_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			 bfd_reloc_code_real_type code)
{
    unsigned int i;

    for (i = sizeof (etca_reloc_map) / sizeof (etca_reloc_map[0]);
	 i--;)
	if (etca_reloc_map [i].bfd_reloc_val == code)
	    return &etca_elf_howto_table[etca_reloc_map[i].etca_reloc_val];

    return NULL;
}

static reloc_howto_type *
etca_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED, const char *r_name)
{
    unsigned int i;

    for (i = 0;
	 i < sizeof (etca_elf_howto_table) / sizeof (etca_elf_howto_table[0]);
	 i++)
	if (etca_elf_howto_table[i].name != NULL
	    && strcasecmp (etca_elf_howto_table[i].name, r_name) == 0)
	    return &etca_elf_howto_table[i];

    return NULL;
}

/* Set the howto pointer for an ETCA ELF reloc.  */

static bool
etca_info_to_howto_rela (bfd *abfd,
			  arelent *cache_ptr,
			  Elf_Internal_Rela *dst)
{
    unsigned int r_type;

    r_type = ELF32_R_TYPE (dst->r_info);
    if (r_type >= (unsigned int) R_ETCA_max)
    {
	/* xgettext:c-format */
	_bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			    abfd, r_type);
	bfd_set_error (bfd_error_bad_value);
	return false;
    }
    cache_ptr->howto = & etca_elf_howto_table [r_type];
    return true;
}


/* Determine what kind of values the object attriubte has. Currently we only have one, which takes a string*/
static int
etca_elf_obj_attrs_arg_type (int tag ATTRIBUTE_UNUSED)
{
    return ATTR_TYPE_FLAG_STR_VAL;
}


/* These functions are also used in the assembler */

size_t etca_calc_mov_ri_byte_count(const struct etca_cpuid *current_cpuid ATTRIBUTE_UNUSED, int8_t size, reg_num reg,
				   int64_t *value_pointer ATTRIBUTE_UNUSED) {
    /* TODO: Actually implement this */
    int factor = (reg < 8) ? 2 : 3;
    switch (size) {
	case 0b00:
	    return 2 * factor;
	case 0b01:
	    return 4 * factor;
	case 0b10:
	    return 7 * factor;
	case 0b11:
	    return 13 * factor;
	default:
	    abort();
    }
}

enum elf_etca_reloc_type etca_build_mov_ri(const struct etca_cpuid *current_cpuid ATTRIBUTE_UNUSED, int8_t size, reg_num reg,
					   int64_t *value_pointer, char *output) {
    const char need_rex = (reg > 8);
    const char rex_a = 0b11000100;
    const char movs = 0b01001001 | (size << 4);
    const char movz = 0b01001000 | (size << 4);
    const char slo = 0b01001100 | (size << 4);
#define ARG(val) ((reg & 7) << 5 | (val & 0x1F))
    /* TODO: Actually implement this */
    uint64_t value = (value_pointer == NULL) ? 0 : (uint64_t) * (value_pointer);
    size_t idx = 0;
    ssize_t bit_offset;
    enum elf_etca_reloc_type ret;
    switch (size) {
	case 0b00:
	    bit_offset = 10;
	    ret = R_ETCA_MOV_10;
	    break;
	case 0b01:
	    bit_offset = 20;
	    ret = R_ETCA_MOV_16;
	    break;
	case 0b10:
	    bit_offset = 35;
	    ret = R_ETCA_MOV_32;
	    break;
	case 0b11:
	default:
	    abort();
    }
    if (need_rex) {
	output[idx++] = rex_a;
    }
    if (value & (1 << bit_offset)) {
	output[idx++] = movs;
    } else {
	output[idx++] = movz;
    }
    output[idx++] = ARG(value >> (bit_offset - 5));
    bit_offset -= 10;
    for (; bit_offset >= 0; bit_offset -= 5) {
	if (need_rex) {
	    output[idx++] = rex_a;
	}
	output[idx++] = slo;
	output[idx++] = ARG(value >> bit_offset);
    }
    return ret;
#undef ARG
}

#define TARGET_LITTLE_SYM	etca_elf32_vec
#define TARGET_LITTLE_NAME	"elf32-etca"
#define ELF_ARCH		bfd_arch_etca
#define ELF_MACHINE_CODE	EM_ETCA
#define ELF_MAXPAGESIZE  	1


#define elf_info_to_howto_rel			NULL
#define elf_info_to_howto			etca_info_to_howto_rela
#define elf_backend_relocate_section		etca_elf_relocate_section
//#define elf_backend_gc_mark_hook		etca_elf_gc_mark_hook
//#define elf_backend_check_relocs		etca_elf_check_relocs
#define bfd_elf32_bfd_reloc_type_lookup		etca_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup		etca_reloc_name_lookup


#define elf_backend_obj_attrs_vendor		"etca"
#define elf_backend_obj_attrs_arg_type		etca_elf_obj_attrs_arg_type
#define elf_backend_obj_attrs_section_type	SHT_ETCA_ATTRIBUTES
#define elf_backend_obj_attrs_section		".etca.attributes"

#include "elf32-target.h"