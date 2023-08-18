
/* tc-etca.h -- Header file for tc-etca.c.

   Copyright 2023 Free Software Foundation, Inc.

   This file is part of GAS, the GNU Assembler.

   GAS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GAS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with GAS; see the file COPYING.  If not, write to the Free Software
   Foundation, 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#define TC_ETCA 1
// ETCa is little endian.
#define TARGET_BYTES_BIG_ENDIAN 0
/* We don't need to handle .word strangely.  */
#define WORKING_DOT_WORD

/* This macro is the BFD target name to use when creating the output
   file.  This will normally depend upon the `OBJ_FMT' macro.  */
#define TARGET_FORMAT "elf32-etca"

/* This macro is the BFD architecture to pass to `bfd_set_arch_mach'.  */
#define TARGET_ARCH bfd_arch_etca

#define md_undefined_symbol(NAME)           0

/* We need to postprocess our arguments a bit */
#define md_after_parse_args()		etca_after_parse_args ()
extern void etca_after_parse_args (void);

// We should deefine this at some point, to produce efficient NOP instructions
// for alignment based on what extensions are available. TODO
// #define md_do_align

// FIXUP=>RELOC configuration

#define GAS_SORT_RELOCS 1 // risc-v does this, not 100% sure what it does
/* Since we're not applying fixups at all right now, we have to suppress GAS's
    burning desire to eliminate symbols from expressions (and hence maybe eliminate relocations)
    if it thinks that we'll be able to write them into the object file and forget about them.
    In fact, relaxation being able to move jumps further or closer from each other makes
    correct relaxation very difficult if we're able to delete the relocations associated
    with local short jump instructions. So if full relaxation is expected, we should
    probably be forcing _all_ fixups into relocations. */
#define TC_FORCE_RELOCATION_LOCAL(FIX) 1
/* As long as we might be doing linker relaxation, we can't allow GAS to replace
    symbol references with section offsets. */
#define tc_fix_adjustable(fixp) 0

/* These macros must be defined, but is will be a fatal assembler
   error if we ever hit them.  */
#define md_estimate_size_before_relax(A, B) (as_fatal (_("estimate size\n")),0)
#define md_convert_frag(B, S, F)            as_fatal (_("convert_frag\n"))

#define md_number_to_chars number_to_chars_littleendian

/* PC relative operands are relative to the start of the entire instruction  (including prefixes), and
   the fixup always covers the entire instruction */
#define md_pcrel_from(FIX) 						\
	((FIX)->fx_where + (FIX)->fx_frag->fr_address)

/* Prevent GAS from folding expressions such as %rh0 + 1 into %rh1. */
#define md_register_arithmetic 0

#define md_section_align(SEGMENT, SIZE)     (SIZE)

// TODO define this to the name of a function etca_address_bytes(void)
// which returns the number of bytes in an address for the current target.
// #define TC_ADDRESS_BYTES etca_address_bytes
