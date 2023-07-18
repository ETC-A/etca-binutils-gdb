

#ifndef _ELF_ETCA_H
#define _ELF_ETCA_H

#include "elf/reloc-macros.h"

/* Relocation types.  */
START_RELOC_NUMBERS (elf_etca_reloc_type)
  RELOC_NUMBER (R_ETCA_NONE, 0)
END_RELOC_NUMBERS (R_ETCA_max)

#endif