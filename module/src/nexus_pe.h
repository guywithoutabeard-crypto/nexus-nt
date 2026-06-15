/*
 * nexus_pe.h — PE (Portable Executable) format definitions
 * For loading Windows .sys kernel drivers on Linux
 *
 * Based on NDISwrapper (GPL-2.0) and Windows PE specification
 */

#ifndef _NEXUS_PE_H_
#define _NEXUS_PE_H_

#include "nexus_nt.h"

/* PE Signature */
#define IMAGE_NT_SIGNATURE       0x00004550  /* "PE\0\0" */
#define IMAGE_DOS_SIGNATURE      0x5A4D      /* "MZ" */

/* Machine types */
#define IMAGE_FILE_MACHINE_I386  0x014c
#define IMAGE_FILE_MACHINE_AMD64 0x8664

/* Characteristics */
#define IMAGE_FILE_EXECUTABLE_IMAGE  0x0002
#define IMAGE_FILE_32BIT_MACHINE     0x0100
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020
#define IMAGE_FILE_DLL               0x2000
#define IMAGE_FILE_RELOCS_STRIPPED   0x0001

/* Optional header magic */
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b

/* Data directory indices */
#define IMAGE_DIRECTORY_ENTRY_EXPORT    0
#define IMAGE_DIRECTORY_ENTRY_IMPORT    1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE  2
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_IAT      12

/* Relocation types */
#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGHLOW  3
#define IMAGE_REL_BASED_DIR64   10

/* Import ordinal flag */
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL
#define IMAGE_ORDINAL_FLAG32 0x80000000UL

#ifdef CONFIG_X86_64
#define IMAGE_ORDINAL_FLAG IMAGE_ORDINAL_FLAG64
#define IMAGE_SNAP_BY_ORDINAL(o) ((o) & IMAGE_ORDINAL_FLAG64)
#define IMAGE_NT_OPTIONAL_HDR_MAGIC IMAGE_NT_OPTIONAL_HDR64_MAGIC
#else
#define IMAGE_ORDINAL_FLAG IMAGE_ORDINAL_FLAG32
#define IMAGE_SNAP_BY_ORDINAL(o) ((o) & IMAGE_ORDINAL_FLAG32)
#define IMAGE_NT_OPTIONAL_HDR_MAGIC IMAGE_NT_OPTIONAL_HDR32_MAGIC
#endif

/* ===== PE Structures ===== */

typedef struct _IMAGE_DOS_HEADER {
	WORD  e_magic;
	WORD  e_cblp;
	WORD  e_cp;
	WORD  e_crlc;
	WORD  e_cparhdr;
	WORD  e_minalloc;
	WORD  e_maxalloc;
	WORD  e_ss;
	WORD  e_sp;
	WORD  e_csum;
	WORD  e_ip;
	WORD  e_cs;
	WORD  e_lfarlc;
	WORD  e_ovno;
	WORD  e_res[4];
	WORD  e_oemid;
	WORD  e_oeminfo;
	WORD  e_res2[10];
	LONG  e_lfanew;  /* Offset to PE header */
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG VirtualAddress;
	ULONG Size;
} IMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_FILE_HEADER {
	WORD  Machine;
	WORD  NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	WORD  SizeOfOptionalHeader;
	WORD  Characteristics;
} IMAGE_FILE_HEADER;

/* 64-bit optional header */
typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD   Magic;
	BYTE   MajorLinkerVersion;
	BYTE   MinorLinkerVersion;
	ULONG  SizeOfCode;
	ULONG  SizeOfInitializedData;
	ULONG  SizeOfUninitializedData;
	ULONG  AddressOfEntryPoint;
	ULONG  BaseOfCode;
	ULONGLONG ImageBase;
	ULONG  SectionAlignment;
	ULONG  FileAlignment;
	WORD   MajorOperatingSystemVersion;
	WORD   MinorOperatingSystemVersion;
	WORD   MajorImageVersion;
	WORD   MinorImageVersion;
	WORD   MajorSubsystemVersion;
	WORD   MinorSubsystemVersion;
	ULONG  Win32VersionValue;
	ULONG  SizeOfImage;
	ULONG  SizeOfHeaders;
	ULONG  CheckSum;
	WORD   Subsystem;
	WORD   DllCharacteristics;
	ULONGLONG SizeOfStackReserve;
	ULONGLONG SizeOfStackCommit;
	ULONGLONG SizeOfHeapReserve;
	ULONGLONG SizeOfHeapCommit;
	ULONG  LoaderFlags;
	ULONG  NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

/* 32-bit optional header */
typedef struct _IMAGE_OPTIONAL_HEADER32 {
	WORD   Magic;
	BYTE   MajorLinkerVersion;
	BYTE   MinorLinkerVersion;
	ULONG  SizeOfCode;
	ULONG  SizeOfInitializedData;
	ULONG  SizeOfUninitializedData;
	ULONG  AddressOfEntryPoint;
	ULONG  BaseOfCode;
	ULONG  BaseOfData;
	ULONG  ImageBase;
	ULONG  SectionAlignment;
	ULONG  FileAlignment;
	WORD   MajorOperatingSystemVersion;
	WORD   MinorOperatingSystemVersion;
	WORD   MajorImageVersion;
	WORD   MinorImageVersion;
	WORD   MajorSubsystemVersion;
	WORD   MinorSubsystemVersion;
	ULONG  Win32VersionValue;
	ULONG  SizeOfImage;
	ULONG  SizeOfHeaders;
	ULONG  CheckSum;
	WORD   Subsystem;
	WORD   DllCharacteristics;
	ULONG  SizeOfStackReserve;
	ULONG  SizeOfStackCommit;
	ULONG  SizeOfHeapReserve;
	ULONG  SizeOfHeapCommit;
	ULONG  LoaderFlags;
	ULONG  NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;

#ifdef CONFIG_X86_64
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
#else
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
#endif

typedef struct _IMAGE_NT_HEADERS {
	ULONG Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS;

#define IMAGE_SIZEOF_SECTION_HEADER 40
#define IMAGE_SIZEOF_SHORT_NAME    8

typedef struct _IMAGE_SECTION_HEADER {
	BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	} Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	WORD  NumberOfRelocations;
	WORD  NumberOfLinenumbers;
	ULONG Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	union {
		ULONG Characteristics;
		ULONG OriginalFirstThunk;
	} u;
	ULONG TimeDateStamp;
	ULONG ForwarderChain;
	ULONG Name;
	ULONG FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	ULONG Characteristics;
	ULONG TimeDateStamp;
	WORD  MajorVersion;
	WORD  MinorVersion;
	ULONG Name;
	ULONG Base;
	ULONG NumberOfFunctions;
	ULONG NumberOfNames;
	ULONG AddressOfFunctions;
	ULONG AddressOfNames;
	ULONG AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_BASE_RELOCATION {
	ULONG VirtualAddress;
	ULONG SizeOfBlock;
	WORD  TypeOffset[1];  /* Variable length */
} IMAGE_BASE_RELOCATION;

/* Get first section header from NT headers */
#define IMAGE_FIRST_SECTION(nthdr) \
	((IMAGE_SECTION_HEADER *)((ULONG_PTR)(nthdr) + \
	 offsetof(IMAGE_NT_HEADERS, OptionalHeader) + \
	 (nthdr)->FileHeader.SizeOfOptionalHeader))

/* RVA to VA helper */
#define RVA2VA(image, rva, type) ((type)((void *)(image) + (rva)))

/* ===== NT Export Table Entry ===== */
struct nt_export {
	const char *name;
	void *func;
};

/* ===== Loaded Driver Info ===== */
struct nexus_driver {
	char name[64];
	void *image;               /* Mapped PE image */
	size_t image_size;
	IMAGE_NT_HEADERS *nt_hdr;
	IMAGE_OPTIONAL_HEADER *opt_hdr;
	void *entry_point;         /* DriverEntry function */
	struct list_head list;
};

/* ===== PE Loader Functions ===== */
int nexus_pe_load(const void *file_data, size_t file_size,
                  const char *name, struct nexus_driver **out_driver);
void nexus_pe_unload(struct nexus_driver *driver);
int nexus_pe_call_entry(struct nexus_driver *driver);
int nexus_pe_call_entry_v2(struct nexus_driver *driver,
                            void *driver_object, void *registry_path);

/* ===== NT Export Resolution ===== */
int nexus_resolve_import(const char *name, void **func);
void nexus_register_exports(void);

#endif /* _NEXUS_PE_H_ */
