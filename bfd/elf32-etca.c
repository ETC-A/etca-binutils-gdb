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
    HOWTO_MOV(8, 20),
    HOWTO_MOV(10, 25),
    HOWTO_MOV(12, 30),
    HOWTO_MOV(14, 35),
    HOWTO_MOV(16, 40),
    HOWTO_MOV(18, 45),
    HOWTO_MOV(20, 50),
    HOWTO_MOV(22, 55),
    HOWTO_MOV(24, 60),
    HOWTO_MOV(26, 64),
    HOWTO_MOV(4, 8),
    HOWTO_MOV(8, 16),
    HOWTO_MOV(14, 32),
#undef HOWTO_MOV
#define HOWTO_MOV_REX(bytes, bits) HOWTO( \
		R_ETCA_MOV_ ## bits ## _REX,            \
		0,                                  \
		bytes,                              \
		bits,                               \
		false,                              \
		0,                              \
		complain_overflow_unsigned,           \
		bfd_elf_generic_reloc,              \
		"R_ETCA_MOV_" #bits "_REX",            \
		false,                              \
		0, \
		(bits == 64? MINUS_ONE : ((bfd_vma) 1 << bits) - 1) & 0x1F001F001F001F00, \
		false)
    HOWTO_MOV_REX(3, 5),
    HOWTO_MOV_REX(6, 10),
    HOWTO_MOV_REX(9, 15),
    HOWTO_MOV_REX(12, 20),
    HOWTO_MOV_REX(15, 25),
    HOWTO_MOV_REX(18, 30),
    HOWTO_MOV_REX(21, 35),
    HOWTO_MOV_REX(24, 40),
    HOWTO_MOV_REX(27, 45),
    HOWTO_MOV_REX(30, 50),
    HOWTO_MOV_REX(33, 55),
    HOWTO_MOV_REX(36, 60),
    HOWTO_MOV_REX(39, 64),
    HOWTO_MOV_REX(6, 8),
    HOWTO_MOV_REX(12, 16),
    HOWTO_MOV_REX(21, 32),
#undef HOWTO_MOV_REX

};

#define GET_SIZE(old) ((old >> 4) & 3)
#define GET_A_REG(old) ((old >> 5) & 7)
#define GET_A_REG_REX(old) (0b1000 | ((old >> 5) & 7))

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
	default:
	    if (R_ETCA_IS_MOV(ELF32_R_TYPE(rel->r_info))) {
		etca_build_mov_ri(
			NULL,
			GET_SIZE(contents[0]),
			GET_A_REG(contents[1]),
			(int64_t * ) & value,
			ELF32_R_TYPE(rel->r_info),
			(char *) contents);
		return bfd_reloc_ok;
	    }
	    if (R_ETCA_IS_MOV_REX(ELF32_R_TYPE(rel->r_info))) {
		etca_build_mov_ri(
			NULL,
			GET_SIZE(contents[1]),
			GET_A_REG_REX(contents[2]),
			(int64_t * ) & value,
			ELF32_R_TYPE(rel->r_info),
			(char *) contents);
		return bfd_reloc_ok;
	    }
	    return bfd_reloc_notsupported;
    }
}
#undef GET_SIZE


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
	    case R_ETCA_BASE_JMP:
		/* Nothing special to do*/
		break;
	    default:
		if (R_ETCA_IS_MOV(r_type) || R_ETCA_IS_MOV_REX(r_type)) {
		    break; /* Nothing to do */
		} else {
		    status = bfd_reloc_notsupported;
		}
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


typedef bool (*relax_func_t) (bfd *, asection *, asection *,
			      struct bfd_link_info *,
			      Elf_Internal_Rela *,
			      bfd_vma, bfd_vma, bfd_vma, bool *);

static bool
_bfd_etca_relax_mov (bfd *abfd ATTRIBUTE_UNUSED, asection *sec ATTRIBUTE_UNUSED, asection *sym_sec ATTRIBUTE_UNUSED,
		     struct bfd_link_info *link_info ATTRIBUTE_UNUSED,
		     Elf_Internal_Rela *rel ATTRIBUTE_UNUSED,
		     bfd_vma symval ATTRIBUTE_UNUSED,
		     bfd_vma max_alignment ATTRIBUTE_UNUSED,
		     bfd_vma reserve_size ATTRIBUTE_UNUSED,
		     bool *again ATTRIBUTE_UNUSED) {
	return false;
}

/* Relax a section.
 *
 * Pass 0: Shortens code sequences and deletes the obsolete bytes.
 * Pass 1: Which cannot be disabled, handles code alignment directives.  */

static bool
_bfd_etca_relax_section (bfd *abfd, asection *sec,
			  struct bfd_link_info *info,
			  bool *again) {

    Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr (abfd);
    struct bfd_elf_section_data *data = elf_section_data (sec);
    Elf_Internal_Rela *relocs;
    size_t i;
    *again = false;
    bool ret = true;


    if (bfd_link_relocatable (info)
	|| sec->sec_flg0
	|| sec->reloc_count == 0
	|| (sec->flags & SEC_RELOC) == 0
	|| (sec->flags & SEC_HAS_CONTENTS) == 0
	|| (info->disable_target_specific_optimizations
	    && info->relax_pass == 0))
	return true;

    /* Read this BFD's relocs if we haven't done so already.  */
    if (data->relocs)
	relocs = data->relocs;
    else if (!(relocs = _bfd_elf_link_read_relocs (abfd, sec, NULL, NULL,
						   info->keep_memory)))
	goto fail;

    /* Examine and consider relaxing each reloc.  */
    for (i = 0; i < sec->reloc_count; i++) {
	//asection *sym_sec;
	Elf_Internal_Rela *rel = relocs + i;
	relax_func_t relax_func;
	int type = ELF32_R_TYPE(rel->r_info);
	//bfd_vma symval;
	//char symtype;

	relax_func = NULL;
	if (info->relax_pass == 0) {
	    if (R_ETCA_IS_MOV(type) || R_ETCA_IS_MOV_REX(type)) {
		relax_func = _bfd_etca_relax_mov;
	    }
	}

	data->relocs = relocs;

	/* Read this BFD's contents if we haven't done so already.  */
	if (!data->this_hdr.contents
	    && !bfd_malloc_and_get_section (abfd, sec, &data->this_hdr.contents)) {
	    goto fail;
	}

	/* Read this BFD's symbols if we haven't done so already.  */
	if (symtab_hdr->sh_info != 0
	    && !symtab_hdr->contents
	    && !(symtab_hdr->contents =
			 (unsigned char *) bfd_elf_get_elf_syms (abfd, symtab_hdr,
								 symtab_hdr->sh_info,
								 0, NULL, NULL, NULL))) {
	    goto fail;
	}
	printf("info.relax_pass=%d, type=%d, relax_func=%p\n", info->relax_pass, type, relax_func);
	(void) relax_func;
    }
fail:
    if (relocs != data->relocs)
	free (relocs);

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
	PAIR(MOV_20),
	PAIR(MOV_25),
	PAIR(MOV_30),
	PAIR(MOV_35),
	PAIR(MOV_40),
	PAIR(MOV_45),
	PAIR(MOV_50),
	PAIR(MOV_55),
	PAIR(MOV_60),
	PAIR(MOV_64),
	PAIR(MOV_8),
	PAIR(MOV_16),
	PAIR(MOV_32),
	PAIR(MOV_5_REX),
	PAIR(MOV_10_REX),
	PAIR(MOV_15_REX),
	PAIR(MOV_20_REX),
	PAIR(MOV_25_REX),
	PAIR(MOV_30_REX),
	PAIR(MOV_35_REX),
	PAIR(MOV_40_REX),
	PAIR(MOV_45_REX),
	PAIR(MOV_50_REX),
	PAIR(MOV_55_REX),
	PAIR(MOV_60_REX),
	PAIR(MOV_64_REX),
	PAIR(MOV_8_REX),
	PAIR(MOV_16_REX),
	PAIR(MOV_32_REX),
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

static
uint8_t number_of_needed_bits(int64_t value) {
    return 64 - __builtin_clrsbll(value);
}

static uint8_t size_to_width[4]  = {8,16,32,64};

enum elf_etca_reloc_type
etca_calc_mov_ri(const struct etca_cpuid *current_cpuid ATTRIBUTE_UNUSED, int8_t size, reg_num reg,
			    int64_t *value_pointer ATTRIBUTE_UNUSED) {
    uint8_t bits;
    if (value_pointer == NULL) {
	bits = size_to_width[size];
    } else {
	bits = number_of_needed_bits(*value_pointer);
    }
    if (size < 0 || size > 3) {
	abort();
    }
    enum elf_etca_reloc_type ret = R_ETCA_NONE;
    switch (size) {
	case 0b00:
	    if (bits >= 8) {
		bits = 8;
		ret = R_ETCA_MOV_8;
	    }
	    break;
	case 0b01:
	    if (bits >= 16) {
		bits = 16;
		ret = R_ETCA_MOV_16;
	    }
	    break;
	case 0b10:
	    if (bits >= 32) {
		bits = 32;
		ret = R_ETCA_MOV_32;
	    }
	    break;
	case 0b11:
	    if (bits >= 64) {
		bits = 64;
		ret = R_ETCA_MOV_64;
	    }
	    break;
	default:
	    abort();
    }
    uint8_t insn = (bits + 4) / 5;
    if (ret == R_ETCA_NONE) {
	ret = R_ETCA_MOV_FROM_INSTRUCTION_COUNT(insn);
    }
    if (reg > 8) {
	ret = R_ETCA_MOV_TO_MOV_REX(ret);
    }
    return ret;
}

enum elf_etca_reloc_type
etca_build_mov_ri(const struct etca_cpuid *current_cpuid ATTRIBUTE_UNUSED, int8_t size, reg_num reg,
		  int64_t *value_pointer, enum elf_etca_reloc_type expected, char *output) {
    const char need_rex = (reg > 8);

    const char rex_a = 0b11000100;
    const char movs = 0b01001001 | (size << 4);
    const char movz = 0b01001000 | (size << 4);
    const char slo = 0b01001100 | (size << 4);
#define ARG(val) ((reg & 7) << 5 | (val & 0x1F))

    const enum elf_etca_reloc_type current = etca_calc_mov_ri(current_cpuid, size, reg, value_pointer);
    const unsigned int insn = R_ETCA_MOV_TO_INSTRUCTION_COUNT(current);
    uint64_t value;
    uint8_t bits;
    if (value_pointer == NULL) {
	value = 0;
	bits = size_to_width[size];
    } else {
	value = *value_pointer;
	bits = number_of_needed_bits(value);
    }
    size_t idx = 0;
    if (need_rex) {
	output[idx++] = rex_a;
    }
    if (value & (1 << (bits - 1))) {
	output[idx++] = movs;
    } else {
	output[idx++] = movz;
    }
    output[idx++] = ARG(value >> ((insn - 1) * 5));

    for (int8_t i = insn - 1; i > 0; i--) {
	if (need_rex) {
	    output[idx++] = rex_a;
	}
	output[idx++] = slo;
	output[idx++] = ARG(value >> ((i - 1) * 5));
    }
    if (expected != R_ETCA_NONE && R_ETCA_MOV_TO_INSTRUCTION_COUNT(expected) != insn) {
	etca_build_nop(current_cpuid,
		       (R_ETCA_MOV_TO_INSTRUCTION_COUNT(expected) - insn) * (need_rex ? 3 : 2),
		       output + idx);
    }
    return current;
#undef ARG
}

void etca_build_nop(const struct etca_cpuid * current_cpuid ATTRIBUTE_UNUSED, size_t byte_count, char *output) {
    if (byte_count % 2 == 1) {
	*(output++) = 0b10101110;
	byte_count--;
    }
    while (byte_count > 0) {
	*(output++) = 0b10001111;
	*(output++) = 0;
	byte_count -= 2;
    }
}



#define TARGET_LITTLE_SYM	etca_elf32_vec
#define TARGET_LITTLE_NAME	"elf32-etca"
#define ELF_ARCH		bfd_arch_etca
#define ELF_MACHINE_CODE	EM_ETCA
#define ELF_MAXPAGESIZE  	1


#define elf_info_to_howto_rel			NULL
#define elf_info_to_howto			etca_info_to_howto_rela
#define elf_backend_relocate_section		etca_elf_relocate_section
#define bfd_elf32_bfd_relax_section		_bfd_etca_relax_section
//#define elf_backend_gc_mark_hook		etca_elf_gc_mark_hook
//#define elf_backend_check_relocs		etca_elf_check_relocs
#define bfd_elf32_bfd_reloc_type_lookup		etca_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup		etca_reloc_name_lookup


#define elf_backend_obj_attrs_vendor		"etca"
#define elf_backend_obj_attrs_arg_type		etca_elf_obj_attrs_arg_type
#define elf_backend_obj_attrs_section_type	SHT_ETCA_ATTRIBUTES
#define elf_backend_obj_attrs_section		".etca.attributes"

#include "elf32-target.h"