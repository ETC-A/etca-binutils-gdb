

#ifndef _ELF_ETCA_H
#define _ELF_ETCA_H

#include "elf/reloc-macros.h"

/* Relocation types.  */
START_RELOC_NUMBERS (elf_etca_reloc_type)
  RELOC_NUMBER (R_ETCA_NONE, 0)
  RELOC_NUMBER (R_ETCA_BASE_JMP, 1)
END_RELOC_NUMBERS (R_ETCA_max)

#define SHT_ETCA_ATTRIBUTES 0x70000003

/* Object attributes.  */
enum
{
    /* 0-3 are generic.  */
    Tag_ETCA_cpuid = 4,
};

#endif