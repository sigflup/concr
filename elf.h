/* I don't want to include a whole new library (libelf) for just
 * these headers. Elf standard is in control of libelf. If elf changes then
 * I change, not when libelf does. This is stolen from libelf, orignal 
 * copyright:
 *
 * elf_repl.h - public header file for systems that lack it.
 * Copyright (C) 1995 - 2006 Michael Riepe
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 * 
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef IS64BIT 
 #define ELF_Ehdr	Elf64_Ehdr
 #define ELF_Shdr	Elf64_Shdr
 #define ELF_Sym        Elf64_Sym
 #define ELF_Off        Elf64_Off
 #define ELF_Word	Elf64_Word
 #define ELF_Addr	Elf64_Addr
#else
 #define ELF_Ehdr	Elf32_Ehdr
 #define ELF_Shdr	Elf32_Shdr
 #define ELF_Sym        Elf32_Sym
 #define ELF_Off        Elf32_Off
 #define ELF_Word	Elf32_Word
 #define ELF_Addr	Elf32_Addr
#endif

typedef uint32_t Elf32_Addr;
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Off;
typedef int32_t  Elf32_Sword;
typedef uint32_t Elf32_Word;

typedef uint64_t Elf64_Addr;
typedef uint16_t Elf64_Half;
typedef uint64_t Elf64_Off;
typedef int32_t  El64_Sword;
typedef uint32_t Elf64_Word;
typedef int64_t  Elf64_Sxword;
typedef uint64_t Elf64_Xword;


#define EI_NIDENT	16

typedef struct {
 unsigned char e_ident[EI_NIDENT];
 Elf32_Half    e_type;
 Elf32_Word    e_version;
 Elf32_Addr    e_entry;
 Elf32_Off     e_phoff;
 Elf32_Off     e_shoff;
 Elf32_Word    e_flags;
 Elf32_Half    e_ehsize;
 Elf32_Half    e_phentsize;
 Elf32_Half    e_phnum;
 Elf32_Half    e_shentsize;
 Elf32_Half    e_shnum;
 Elf32_Half    e_shstrndx;
} Elf32_Ehdr;

typedef struct {
 unsigned char e_ident[EI_NIDENT];
 Elf64_Half    e_type;
 Elf64_Word    e_version;
 Elf64_Addr    e_entry;
 Elf64_Off     e_phoff;
 Elf64_Off     e_shoff;
 Elf64_Word    e_flags;
 Elf64_Half    e_ehsize;
 Elf64_Half    e_phentsize;
 Elf64_Half    e_phnum;
 Elf64_Half    e_shentsize;
 Elf64_Half    e_shnum;
 Elf64_Half    e_shstrndx;
} Elf64_Ehdr;

#define ELFMAG0	0x7f
#define	ELFMAG1	'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

typedef struct {
 Elf32_Word sh_name;
 Elf32_Word sh_type;
 Elf32_Word sh_flags;
 Elf32_Addr sh_addr;
 Elf32_Off  sh_offset;
 Elf32_Word sh_size;
 Elf32_Word sh_link;
 Elf32_Word sh_info;
 Elf32_Word sh_addralign;
 Elf32_Word sh_entsize;
} Elf32_Shdr;

typedef struct {
 Elf64_Word sh_name;
 Elf64_Word sh_type;
 Elf64_Xword sh_flags;
 Elf64_Addr sh_addr;
 Elf64_Off  sh_offset;
 Elf64_Xword sh_size;
 Elf64_Word sh_link;
 Elf64_Word sh_info;
 Elf64_Xword sh_addralign;
 Elf64_Xword sh_entsize;
} Elf64_Shdr;

/*
 * Special section indices
 */
#define SHN_UNDEF	0
#define SHN_LORESERVE	0xff00
#define SHN_LOPROC	0xff00
#define SHN_HIPROC	0xff1f
#define SHN_LOOS	0xff20
#define SHN_HIOS	0xff3f
#define SHN_ABS		0xfff1
#define SHN_COMMON	0xfff2
#define SHN_XINDEX	0xffff
#define SHN_HIRESERVE	0xffff



#define SHT_NULL		0
#define SHT_PROGBITS		1
#define SHT_SYMTAB		2
#define SHT_STRTAB		3
#define SHT_RELA		4
#define SHT_HASH		5
#define SHT_DYNAMIC		6
#define SHT_NOTE		7
#define SHT_NOBITS		8
#define SHT_REL			9
#define SHT_SHLIB		10
#define SHT_DYNSYM		11
#define SHT_INIT_ARRAY		14
#define SHT_FINI_ARRAY		15
#define SHT_PREINIT_ARRAY	16
#define SHT_GROUP		17
#define SHT_SYMTAB_SHNDX	18
#define SHT_NUM			19
#define SHT_LOOS		0x60000000
#define SHT_HIOS		0x6fffffff
#define SHT_LOPROC		0x70000000
#define SHT_HIPROC		0x7fffffff
#define SHT_LOUSER		0x80000000
#define SHT_HIUSER		0xffffffff

/*
 * Solaris extensions
 */
#define SHT_LOSUNW		0x6ffffff4
#define SHT_SUNW_dof		0x6ffffff4
#define SHT_SUNW_cap		0x6ffffff5
#define SHT_SUNW_SIGNATURE	0x6ffffff6
#define SHT_SUNW_ANNOTATE	0x6ffffff7
#define SHT_SUNW_DEBUGSTR	0x6ffffff8
#define SHT_SUNW_DEBUG		0x6ffffff9
#define SHT_SUNW_move		0x6ffffffa
#define SHT_SUNW_COMDAT		0x6ffffffb
#define SHT_SUNW_syminfo	0x6ffffffc
#define SHT_SUNW_verdef		0x6ffffffd
#define SHT_SUNW_verneed	0x6ffffffe
#define SHT_SUNW_versym		0x6fffffff
#define SHT_HISUNW		0x6fffffff

#define SHT_SPARC_GOTDATA	0x70000000
#define SHT_AMD64_UNWIND	0x70000001 

/*
 * GNU extensions
 */
#define SHT_GNU_verdef		0x6ffffffd
#define SHT_GNU_verneed		0x6ffffffe
#define SHT_GNU_versym		0x6fffffff

/*
 * sh_flags
 */
#define SHF_WRITE		0x1
#define SHF_ALLOC		0x2
#define SHF_EXECINSTR		0x4
#define SHF_MERGE		0x10
#define SHF_STRINGS		0x20
#define SHF_INFO_LINK		0x40
#define SHF_LINK_ORDER		0x80
#define SHF_OS_NONCONFORMING	0x100
#define SHF_GROUP		0x200
#define SHF_TLS			0x400
#define SHF_MASKOS		0x0ff00000
#define SHF_MASKPROC		0xf0000000

/*
 * Solaris extensions
 */
#define SHF_AMD64_LARGE		0x10000000
#define SHF_ORDERED		0x40000000
#define SHF_EXCLUDE		0x80000000

/*
 * Section group flags
 */
#define GRP_COMDAT		0x1
#define GRP_MASKOS		0x0ff00000
#define GRP_MASKPROC		0xf0000000

typedef struct {
 Elf32_Word st_name;
 Elf32_Addr st_value;
 Elf32_Word st_size;
 unsigned char st_info;
 unsigned char st_other;
 Elf32_Half st_shndx;
} Elf32_Sym;

typedef struct {
 Elf64_Word st_name;
 unsigned char st_info;
 unsigned char st_other;
 Elf64_Half st_shndx;
 Elf64_Addr st_value;
 Elf64_Xword st_size;
} Elf64_Sym;

#define STN_UNDEF	0

/*
 * Macros for manipulating st_info
 */
#define ELF32_ST_BIND(i)	((i)>>4)
#define ELF32_ST_TYPE(i)	((i)&0xf)
#define ELF32_ST_INFO(b,t)	(((b)<<4)+((t)&0xf))

#define ELF64_ST_BIND(i)	((i)>>4)
#define ELF64_ST_TYPE(i)	((i)&0xf)
#define ELF64_ST_INFO(b,t)	(((b)<<4)+((t)&0xf))

/*
 * Symbol binding
 */
#define STB_LOCAL	0
#define STB_GLOBAL	1
#define STB_WEAK	2
#define STB_NUM		3
#define STB_LOOS	10
#define STB_HIOS	12
#define STB_LOPROC	13
#define STB_HIPROC	15

/*
 * Symbol types
 */
#define STT_NOTYPE	0
#define STT_OBJECT	1
#define STT_FUNC	2
#define STT_SECTION	3
#define STT_FILE	4
#define STT_COMMON	5
#define STT_TLS		6
#define STT_NUM		7
#define STT_LOOS	10
#define STT_HIOS	12
#define STT_LOPROC	13
#define STT_HIPROC	15

/*
 * Macros for manipulating st_other
 */
#define ELF32_ST_VISIBILITY(o)	((o)&0x3)
#define ELF64_ST_VISIBILITY(o)	((o)&0x3)

/*
 * Symbol visibility
 */
#define STV_DEFAULT	0
#define STV_INTERNAL	1
#define STV_HIDDEN	2
#define STV_PROTECTED	3

/*sdfsdfsdf*/
