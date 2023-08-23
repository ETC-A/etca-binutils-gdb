

#ifndef _ELF_ETCA_H
#define _ELF_ETCA_H

#include "elf/reloc-macros.h"

/* Relocation types.  Note: These relocation numbers are part of the ELF files, so changing them is a breaking change */
START_RELOC_NUMBERS (elf_etca_reloc_type)
  RELOC_NUMBER (R_ETCA_NONE, 0)
  RELOC_NUMBER (R_ETCA_BASE_JMP, 1) /* base 9-bit relative jump */
  RELOC_NUMBER (R_ETCA_EXABS_8, 2)  /* exop 8-bit absolute jump */
  RELOC_NUMBER (R_ETCA_EXABS_16, 3) /* `` 16-bit */
  RELOC_NUMBER (R_ETCA_EXABS_32, 4) /* `` 32-bit */
  RELOC_NUMBER (R_ETCA_EXABS_64, 5) /* `` 64-bit */
  RELOC_NUMBER (R_ETCA_SAF_CALL, 6) /* SAF relative call */
  RELOC_NUMBER (R_ETCA_ABM_RIS_5, 7)
  RELOC_NUMBER (R_ETCA_ABM_RIZ_5, 8)
  RELOC_NUMBER (R_ETCA_ABM_RIS_8, 9)
  RELOC_NUMBER (R_ETCA_ABM_RIZ_8, 10)
  RELOC_NUMBER (R_ETCA_ABM_RIS_16, 11)
  RELOC_NUMBER (R_ETCA_ABM_RIZ_16, 12)
  RELOC_NUMBER (R_ETCA_ABM_RIS_32, 13)
  RELOC_NUMBER (R_ETCA_ABM_RIZ_32, 14)
  RELOC_NUMBER (R_ETCA_ABM_RIS_64, 15)
  RELOC_NUMBER (R_ETCA_ABM_RIZ_64, 16)
  RELOC_NUMBER (R_ETCA_MOV_5,  17)
  RELOC_NUMBER (R_ETCA_MOV_10, 18)
  RELOC_NUMBER (R_ETCA_MOV_15, 19)
  RELOC_NUMBER (R_ETCA_MOV_20, 20)
  RELOC_NUMBER (R_ETCA_MOV_25, 21)
  RELOC_NUMBER (R_ETCA_MOV_30, 22)
  RELOC_NUMBER (R_ETCA_MOV_35, 23)
  RELOC_NUMBER (R_ETCA_MOV_40, 24)
  RELOC_NUMBER (R_ETCA_MOV_45, 25)
  RELOC_NUMBER (R_ETCA_MOV_50, 26)
  RELOC_NUMBER (R_ETCA_MOV_55, 27)
  RELOC_NUMBER (R_ETCA_MOV_60, 28)
  RELOC_NUMBER (R_ETCA_MOV_64, 29)
  RELOC_NUMBER (R_ETCA_MOV_8,  30)
  RELOC_NUMBER (R_ETCA_MOV_16, 31)
  RELOC_NUMBER (R_ETCA_MOV_32, 32)
  RELOC_NUMBER (R_ETCA_MOV_5_REX,  33)
  RELOC_NUMBER (R_ETCA_MOV_10_REX, 34)
  RELOC_NUMBER (R_ETCA_MOV_15_REX, 35)
  RELOC_NUMBER (R_ETCA_MOV_20_REX, 36)
  RELOC_NUMBER (R_ETCA_MOV_25_REX, 37)
  RELOC_NUMBER (R_ETCA_MOV_30_REX, 38)
  RELOC_NUMBER (R_ETCA_MOV_35_REX, 39)
  RELOC_NUMBER (R_ETCA_MOV_40_REX, 40)
  RELOC_NUMBER (R_ETCA_MOV_45_REX, 41)
  RELOC_NUMBER (R_ETCA_MOV_50_REX, 42)
  RELOC_NUMBER (R_ETCA_MOV_55_REX, 43)
  RELOC_NUMBER (R_ETCA_MOV_60_REX, 44)
  RELOC_NUMBER (R_ETCA_MOV_64_REX, 45)
  RELOC_NUMBER (R_ETCA_MOV_8_REX,  46)
  RELOC_NUMBER (R_ETCA_MOV_16_REX, 47)
  RELOC_NUMBER (R_ETCA_MOV_32_REX, 48)
  RELOC_NUMBER (R_ETCA_8, 49)
  RELOC_NUMBER (R_ETCA_16, 50)
  RELOC_NUMBER (R_ETCA_32, 51)
  RELOC_NUMBER (R_ETCA_64, 52)
  RELOC_NUMBER (R_ETCA_IPREL_8, 53)
  RELOC_NUMBER (R_ETCA_IPREL_16, 54)
  RELOC_NUMBER (R_ETCA_IPREL_32, 55)
  RELOC_NUMBER (R_ETCA_IPREL_64, 56)
END_RELOC_NUMBERS (R_ETCA_max)
#define _R_ETCA_MOV_DELTA (R_ETCA_MOV_5_REX - R_ETCA_MOV_5)

#define R_ETCA_IS_EXABS(r_type) (R_ETCA_EXABS_8 <= (r_type) && (r_type) <= R_ETCA_EXABS_64)
#define R_ETCA_IS_DISP(r_type)  (R_ETCA_8 <= (r_type) && (r_type) <= R_ETCA_64)
#define R_ETCA_IS_IPREL(r_type) (R_ETCA_IPREL_8 <= (r_type) && (r_type) <= R_ETCA_IPREL_64)
#define R_ETCA_IS_ANY_DISP(r_type) (R_ETCA_IS_EXABS(r_type) || R_ETCA_IS_DISP(r_type) || R_ETCA_IS_IPREL(r_type))

#define R_ETCA_IS_MOV(r_type) (R_ETCA_MOV_5 <= (r_type) && (r_type) <= R_ETCA_MOV_32)
#define R_ETCA_IS_MOV_REX(r_type) (R_ETCA_MOV_5_REX <= (r_type) && (r_type) <= R_ETCA_MOV_32_REX)
#define R_ETCA_MOV_FROM_INSTRUCTION_COUNT(n) (R_ETCA_MOV_5 + (n - 1))
#define R_ETCA_MOV_TO_MOV_REX(r_type) (r_type + _R_ETCA_MOV_DELTA)
#define R_ETCA_MOV_REX_TO_MOV(r_type) (r_type - _R_ETCA_MOV_DELTA)
#define R_ETCA_MOV_NORM(r_type) (R_ETCA_IS_MOV_REX(r_type)? R_ETCA_MOV_REX_TO_MOV(r_type) : r_type )
#define R_ETCA_MOV_TO_INSTRUCTION_COUNT(r_type) (R_ETCA_MOV_NORM(r_type) == R_ETCA_MOV_8 ? 2 : \
                (R_ETCA_MOV_NORM(r_type) == R_ETCA_MOV_16? 4 :                                 \
                (R_ETCA_MOV_NORM(r_type) == R_ETCA_MOV_32? 7 :                                 \
                (R_ETCA_MOV_NORM(r_type) - R_ETCA_MOV_5 + 1))))
#define R_ETCA_MOV_TO_BYTECOUNT(r_type) (R_ETCA_MOV_TO_INSTRUCTION_COUNT(r_type)\
                * (R_ETCA_IS_MOV_REX(r_type)? 3:2))

#define SHT_ETCA_ATTRIBUTES 0x70000003

/* Object attributes.  */
enum
{
    /* 0-3 are generic.  */
    Tag_ETCA_cpuid = 4,
};

#endif