
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
#define TARGET_BYTES_BIG_ENDIAN 1
#define WORKING_DOT_WORD

/* This macro is the BFD target name to use when creating the output
   file.  This will normally depend upon the `OBJ_FMT' macro.  */
#define TARGET_FORMAT "elf32-etca"

/* This macro is the BFD architecture to pass to `bfd_set_arch_mach'.  */
#define TARGET_ARCH bfd_arch_etca

#define md_undefined_symbol(NAME)           0

/* These macros must be defined, but is will be a fatal assembler
   error if we ever hit them.  */
#define md_estimate_size_before_relax(A, B) (as_fatal (_("estimate size\n")),0)
#define md_convert_frag(B, S, F)            as_fatal (_("convert_frag\n"))

/* PC relative operands are relative to the start of the opcode, and
   the operand is always one byte into the opcode.  */
/*#define md_pcrel_from(FIX) 						\
	((FIX)->fx_where + (FIX)->fx_frag->fr_address - 1)
*/
#define md_pcrel_from(FIX) 		(as_fatal (_("md_pcrel_from\n")),0)


#define md_section_align(SEGMENT, SIZE)     (SIZE)