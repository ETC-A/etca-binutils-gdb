//
// Created by MegaIng on 2023-07-18.
//

/* BFD support for the ETCa ISA (family).
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
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"


const bfd_arch_info_type bfd_etca_arch =
        {
                16,               /* 16 bits in a word.  */
                16,               /* 16 bits in an address.  */
                8,                /*  8 bits in a byte.  */
                bfd_arch_etca,    /* enum bfd_architecture arch.  */
                bfd_mach_etca,
                "etca",           /* Arch name.  */
                "ETCa",           /* Printable name.  */
                2,                /* Unsigned int section alignment power.  */
                1,                /* Is Default  */
                bfd_default_compatible,
                bfd_default_scan,
                0,
                0,                /* next */
                0,                /* max_reloc_offset_into_insn */
        };