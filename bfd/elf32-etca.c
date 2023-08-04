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
calculate_relocate_target(bfd *, arelent *, asymbol *, asection *, bfd *, char **, symvalue *, bfd_size_type *);

bfd_reloc_status_type
calculate_relocate_target(bfd *abfd,
			  arelent *reloc_entry,
			  asymbol *symbol,
			  asection *input_section,
			  bfd *output_bfd,
			  char **error_message ATTRIBUTE_UNUSED,
			  symvalue *relocation,
			  bfd_size_type *octets) {

    bfd_reloc_status_type flag = bfd_reloc_ok;
    bfd_vma output_base = 0;
    reloc_howto_type *howto = reloc_entry->howto;
    asection *reloc_target_output_section;

    // This code is mostly copied from perform_relocation in reloc.c

    if (bfd_is_abs_section (symbol->section)
	&& output_bfd != NULL)
    {
	reloc_entry->address += input_section->output_offset;
	return bfd_reloc_ok;
    }

    if (howto == NULL)
	return bfd_reloc_undefined;

    /* Is the address of the relocation really within the section?  */
    *octets = reloc_entry->address;
    if (!bfd_reloc_offset_in_range (howto, abfd, input_section, *octets))
	return bfd_reloc_outofrange;

    /* Work out which section the relocation is targeted at and the
       initial relocation command value.  */

    /* Get symbol value.  (Common symbols are special.)  */
    if (bfd_is_com_section (symbol->section))
	*relocation = 0;
    else
	*relocation = symbol->value;

    reloc_target_output_section = symbol->section->output_section;

    /* Convert input-section-relative symbol value to absolute.  */
    if ((output_bfd && ! howto->partial_inplace)
	|| reloc_target_output_section == NULL)
	output_base = 0;
    else
	output_base = reloc_target_output_section->vma;

    output_base += symbol->section->output_offset;

    *relocation += output_base;

    /* Add in supplied addend.  */
    *relocation += reloc_entry->addend;

    /* Here the variable relocation holds the final address of the
       symbol we are relocating against, plus any addend.  */

    if (howto->pc_relative)
    {
	/* This is a PC relative relocation.  We want to set RELOCATION
	   to the distance between the address of the symbol and the
	   location.  RELOCATION is already the address of the symbol.

	   We start by subtracting the address of the section containing
	   the location.

	   If pcrel_offset is set, we must further subtract the position
	   of the location within the section.  Some targets arrange for
	   the addend to be the negative of the position of the location
	   within the section; for example, i386-aout does this.  For
	   i386-aout, pcrel_offset is FALSE.  Some other targets do not
	   include the position of the location; for example, ELF.
	   For those targets, pcrel_offset is TRUE.

	   If we are producing relocatable output, then we must ensure
	   that this reloc will be correctly computed when the final
	   relocation is done.  If pcrel_offset is FALSE we want to wind
	   up with the negative of the location within the section,
	   which means we must adjust the existing addend by the change
	   in the location within the section.  If pcrel_offset is TRUE
	   we do not want to adjust the existing addend at all.

	   FIXME: This seems logical to me, but for the case of
	   producing relocatable output it is not what the code
	   actually does.  I don't want to change it, because it seems
	   far too likely that something will break.  */

	*relocation -=
		input_section->output_section->vma + input_section->output_offset;

	if (howto->pcrel_offset)
	    *relocation -= reloc_entry->address;
    }

    if (output_bfd != NULL)
    {
	if (! howto->partial_inplace)
	{
	    /* This is a partial relocation, and we want to apply the relocation
	       to the reloc entry rather than the raw data. Modify the reloc
	       inplace to reflect what we now know.  */
	    reloc_entry->addend = *relocation;
	    reloc_entry->address += input_section->output_offset;
	    return flag;
	}
	else
	{
	    /* This is a partial relocation, but inplace, so modify the
	       reloc record a bit.

	       If we've relocated with a symbol with a section, change
	       into a ref to the section belonging to the symbol.  */

	    reloc_entry->address += input_section->output_offset;

	    reloc_entry->addend = *relocation;
	}
    }

    /* FIXME: This overflow checking is incomplete, because the value
       might have overflowed before we get here.  For a correct check we
       need to compute the value in a size larger than bitsize, but we
       can't reasonably do that for a reloc the same size as a host
       machine word.
       FIXME: We should also do overflow checking on the result after
       adding in the value contained in the object file.  */
    if (howto->complain_on_overflow != complain_overflow_dont
	&& flag == bfd_reloc_ok)
	flag = bfd_check_overflow (howto->complain_on_overflow,
				   howto->bitsize,
				   howto->rightshift,
				   bfd_arch_bits_per_address (abfd),
				   *relocation);

    /* Either we are relocating all the way, or we don't want to apply
       the relocation to the reloc entry (probably because there isn't
       any room in the output format to describe addends to relocs).  */

    /* The cast to bfd_vma avoids a bug in the Alpha OSF/1 C compiler
       (OSF version 1.3, compiler version 3.11).  It miscompiles the
       following program:

       struct str
       {
	 unsigned int i0;
       } s = { 0 };

       int
       main ()
       {
	 unsigned long x;

	 x = 0x100000000;
	 x <<= (unsigned long) s.i0;
	 if (x == 0)
	   printf ("failed\n");
	 else
	   printf ("succeeded (%lx)\n", x);
       }
       */

    *relocation >>= (bfd_vma) howto->rightshift;

    /* Shift everything up to where it's going to be used.  */
    *relocation <<= (bfd_vma) howto->bitpos;

    return bfd_reloc_continue;
}

bfd_reloc_status_type
bfd_etca_reloc_base_jmp (bfd *abfd,
			 arelent *reloc_entry,
			 asymbol *symbol,
			 void *data,
			 asection *input_section,
			 bfd *output_bfd,
			 char **error_message) {
    /* Let the generic ELF code deal with a few of the corner cases*/
    bfd_reloc_status_type status = bfd_elf_generic_reloc(abfd, reloc_entry, symbol, data, input_section, output_bfd, error_message);
    if (status != bfd_reloc_continue) {
	return status;
    }
    symvalue relocation;
    bfd_size_type octets;
    /* Offload the work that doesn't depend on the exact instruction format */
    status = calculate_relocate_target(abfd, reloc_entry, symbol, input_section, output_bfd, error_message, &relocation, &octets);
    if (status != bfd_reloc_continue) {
	return status;
    }

    bfd_byte *instruction = data + octets;

    instruction[0] |= (instruction[0] & (~0x10)) | ((relocation >> 8) & 0x10); // Set 'direction' bit in opcode
    instruction[1] = (relocation) & 0xFF; // Set lower bits
    status = bfd_reloc_ok;
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