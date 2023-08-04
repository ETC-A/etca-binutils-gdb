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



/* Forward declarations.  */

bfd_reloc_status_type bfd_etca_reloc_base_jmp (bfd *, arelent *, asymbol *, void *, asection *, bfd *, char **);

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

    /* A 32 bit absolute relocation.  */
    HOWTO (R_ETCA_BASE_JMP,	/* type */
	   0,			/* rightshift */
	   2,			/* size */
	   9,			/* bitsize */
	   true,		/* pc_relative */
	   0,			/* bitpos */
	   complain_overflow_dont, /* complain_on_overflow */
	   bfd_etca_reloc_base_jmp,	/* special_function */
	   "R_ETCA_BASE_JMP",		/* name */
	   false,			/* partial_inplace */
	   0x00000000,		/* src_mask */
	   0xFF10,		/* dst_mask */
	   true),		/* pcrel_offset */

};

bfd_reloc_status_type
bfd_etca_reloc_base_jmp (bfd *abfd,
			 arelent *reloc_entry,
			 asymbol *symbol,
			 void *data,
			 asection *input_section,
			 bfd *output_bfd,
			 char **error_message){
    /* Led the generic ELF code deal with a few of the corner cases*/
    bfd_reloc_status_type status = bfd_elf_generic_reloc(abfd, reloc_entry, symbol, data, input_section, output_bfd, error_message);
    if (status != bfd_reloc_continue) {
	return status;
    }
    BFD_ASSERT(output_bfd == NULL);

    reloc_howto_type * howto = reloc_entry->howto;
    bfd_size_type octets = reloc_entry->address;
    if (!bfd_reloc_offset_in_range (howto, abfd, input_section, octets))
	return bfd_reloc_outofrange;

    /* This code is copied together from parts of perform_relocation in reloc.c*/
    symvalue relocation = symbol->value;
    relocation += reloc_entry->addend;
    if (howto->pc_relative) {
	relocation -= input_section->output_section->vma + input_section->output_offset;

	if (howto->pcrel_offset)
	    relocation -= reloc_entry->address;
    }
    data += octets;

    bfd_vma val = bfd_get_16 (abfd, data);
    relocation = ((relocation << 8) & 0xFF00) | ((relocation >> 8) & 0x10);
    /* We need to swap the order of the relocation here*/
    printf("in_read=%lx, relocation=%lx\n", val, relocation);

    val = ((val & ~howto->dst_mask)
	   | (((val & howto->src_mask) + relocation) & howto->dst_mask));
    printf("out_write=%lx\n", val);

    bfd_put_16 (abfd, val, data);
    return status;
}


/* Map BFD reloc types to ETCA ELF reloc types.  */

struct etca_reloc_map
{
    bfd_reloc_code_real_type bfd_reloc_val;
    unsigned int etca_reloc_val;
};

static const struct etca_reloc_map etca_reloc_map [] =
	{
		{ BFD_RELOC_NONE,	       R_ETCA_NONE },
		{ BFD_RELOC_ETCA_BASE_JMP,  R_ETCA_BASE_JMP },
	};

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

#define TARGET_LITTLE_SYM	etca_elf32_vec
#define TARGET_LITTLE_NAME	"elf32-etca"
#define ELF_ARCH		bfd_arch_etca
#define ELF_MACHINE_CODE	EM_ETCA
#define ELF_MAXPAGESIZE  	1


#define elf_info_to_howto_rel			NULL
#define elf_info_to_howto			etca_info_to_howto_rela
//#define elf_backend_relocate_section		etca_elf_relocate_section
//#define elf_backend_gc_mark_hook		etca_elf_gc_mark_hook
//#define elf_backend_check_relocs		etca_elf_check_relocs
#define bfd_elf32_bfd_reloc_type_lookup		etca_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup		etca_reloc_name_lookup


#define elf_backend_obj_attrs_vendor		"etca"
#define elf_backend_obj_attrs_arg_type		etca_elf_obj_attrs_arg_type
#define elf_backend_obj_attrs_section_type	SHT_ETCA_ATTRIBUTES
#define elf_backend_obj_attrs_section		".etca.attributes"

#include "elf32-target.h"