/*
 * nexus_pe.c — PE Loader for Windows .sys drivers
 *
 * Loads a Windows kernel driver (.sys PE file) into Linux kernel memory,
 * resolves its imports against our NT API shim, applies relocations,
 * and calls DriverEntry.
 *
 * Based on NDISwrapper pe_linker.c (GPL-2.0)
 * License: GPL-2.0
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/kprobes.h>

#include "nexus_nt.h"
#include "nexus_pe.h"

/* ===== NT API Export Table ===== */
/* These are the functions we provide to loaded Windows drivers */

static PVOID stub_return_null(void) { return NULL; }
static NTSTATUS stub_return_success(void) { return STATUS_SUCCESS; }
static NTSTATUS stub_return_not_impl(void) { return STATUS_NOT_IMPLEMENTED; }
static void stub_void(void) { }

/* Master export table — maps NT function names to our implementations */
static struct nt_export nexus_exports[] = {
	/* Process/Thread */
	{ "PsGetCurrentProcess", NxPsGetCurrentProcess },
	{ "PsGetCurrentProcessId", (void *)NxPsGetCurrentProcessId },
	{ "PsLookupProcessByProcessId", (void *)NxPsLookupProcessByProcessId },
	{ "PsSetCreateProcessNotifyRoutine", (void *)NxPsSetCreateProcessNotifyRoutine },
	{ "PsGetProcessImageFileName", (void *)NxPsGetProcessImageFileName },
	{ "KeServiceDescriptorTable", (void *)NxKeServiceDescriptorTable },

	/* Memory - stubs for now */
	{ "ExAllocatePoolWithTag", (void *)stub_return_null },
	{ "ExAllocatePool", (void *)stub_return_null },
	{ "ExFreePoolWithTag", (void *)stub_void },
	{ "ExFreePool", (void *)stub_void },
	{ "MmGetSystemRoutineAddress", (void *)stub_return_null },
	{ "MmIsAddressValid", (void *)stub_return_null },

	/* Object Manager - stubs */
	{ "ObReferenceObjectByHandle", (void *)stub_return_success },
	{ "ObfDereferenceObject", (void *)stub_void },
	{ "ObfReferenceObject", (void *)stub_void },
	{ "ObRegisterCallbacks", (void *)stub_return_success },
	{ "ObUnRegisterCallbacks", (void *)stub_void },

	/* I/O */
	{ "IoCreateDevice", (void *)stub_return_success },
	{ "IoDeleteDevice", (void *)stub_void },
	{ "IoCreateSymbolicLink", (void *)stub_return_success },
	{ "IoDeleteSymbolicLink", (void *)stub_return_success },
	{ "IofCompleteRequest", (void *)stub_void },
	{ "IofCallDriver", (void *)stub_return_success },

	/* Sync */
	{ "KeInitializeSpinLock", (void *)stub_void },
	{ "KeAcquireSpinLock", (void *)stub_void },
	{ "KeReleaseSpinLock", (void *)stub_void },
	{ "KeInitializeEvent", (void *)stub_void },
	{ "KeSetEvent", (void *)stub_void },
	{ "KeWaitForSingleObject", (void *)stub_return_success },
	{ "KeGetCurrentIrql", (void *)stub_return_null },

	/* Registry */
	{ "ZwOpenKey", (void *)stub_return_success },
	{ "ZwQueryValueKey", (void *)stub_return_success },
	{ "ZwClose", (void *)stub_return_success },
	{ "ZwCreateKey", (void *)stub_return_success },

	/* System Info */
	{ "ZwQuerySystemInformation", (void *)NxZwQuerySystemInformation },

	/* Strings */
	{ "RtlInitUnicodeString", (void *)stub_void },
	{ "RtlCopyUnicodeString", (void *)stub_void },
	{ "RtlCompareUnicodeString", (void *)stub_return_null },
	{ "RtlEqualUnicodeString", (void *)stub_return_null },

	/* Misc */
	{ "DbgPrint", (void *)stub_void },
	{ "DbgPrintEx", (void *)stub_void },
	{ "KeBugCheck", (void *)stub_void },
	{ "KeBugCheckEx", (void *)stub_void },
	{ "_snwprintf", (void *)stub_return_null },
	{ "wcslen", (void *)stub_return_null },
	{ "wcscpy", (void *)stub_return_null },
	{ "memset", (void *)memset },
	{ "memcpy", (void *)memcpy },
	{ "memmove", (void *)memmove },
	{ "strlen", (void *)strlen },
	{ "strcpy", (void *)strcpy },

	/* End marker */
	{ NULL, NULL }
};

/*
 * Resolve an imported function name to our implementation
 */
int nexus_resolve_import(const char *name, void **func)
{
	int i;
	for (i = 0; nexus_exports[i].name != NULL; i++) {
		if (strcmp(nexus_exports[i].name, name) == 0) {
			*func = nexus_exports[i].func;
			return 0;
		}
	}

	pr_warn("nexus_nt: unresolved import: %s (stubbing)\n", name);
	*func = (void *)stub_return_not_impl;
	return -1;
}

/*
 * Validate PE headers
 */
static int validate_pe(const void *data, size_t size)
{
	IMAGE_DOS_HEADER *dos;
	IMAGE_NT_HEADERS *nt;

	if (size < sizeof(IMAGE_DOS_HEADER))
		return -EINVAL;

	dos = (IMAGE_DOS_HEADER *)data;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		pr_err("nexus_nt: not a PE file (bad MZ signature)\n");
		return -EINVAL;
	}

	if (dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size) {
		pr_err("nexus_nt: PE header extends past file\n");
		return -EINVAL;
	}

	nt = (IMAGE_NT_HEADERS *)((void *)data + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		pr_err("nexus_nt: bad PE signature: 0x%x\n", nt->Signature);
		return -EINVAL;
	}

#ifdef CONFIG_X86_64
	if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		pr_err("nexus_nt: not a 64-bit driver (machine: 0x%x)\n",
		       nt->FileHeader.Machine);
		return -EINVAL;
	}
	if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		pr_err("nexus_nt: not PE64 (magic: 0x%x)\n",
		       nt->OptionalHeader.Magic);
		return -EINVAL;
	}
#else
	if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
		pr_err("nexus_nt: not a 32-bit driver\n");
		return -EINVAL;
	}
#endif

	if (nt->FileHeader.NumberOfSections == 0) {
		pr_err("nexus_nt: PE has no sections\n");
		return -EINVAL;
	}

	return 0;
}

/*
 * Map PE sections into memory with proper alignment
 */
static void *map_pe_image(const void *file_data, size_t file_size,
                          IMAGE_NT_HEADERS *nt_hdr, size_t *out_size)
{
	void *image;
	IMAGE_SECTION_HEADER *sect;
	int i, num_sections;
	size_t image_size;

	image_size = nt_hdr->OptionalHeader.SizeOfImage;
	*out_size = image_size;

	/* Align to page size for set_memory_x */
	image_size = PAGE_ALIGN(image_size);
	*out_size = image_size;

	image = __vmalloc(image_size, GFP_KERNEL);
	if (!image)
		return NULL;

	memset(image, 0, image_size);

	/* Memory needs to be executable for driver code.
	 * Using kprobes trick to find set_memory_x */
	{
		typedef int (*set_mem_x_t)(unsigned long, int);
		struct kprobe kp = { .symbol_name = "set_memory_x" };
		if (register_kprobe(&kp) == 0) {
			set_mem_x_t fn = (set_mem_x_t)kp.addr;
			unregister_kprobe(&kp);
			fn((unsigned long)image, image_size >> PAGE_SHIFT);
			pr_info("nexus_nt: set PE memory executable\n");
		} else {
			pr_warn("nexus_nt: can't make memory executable\n");
		}
	}

	/* Copy headers */
	sect = IMAGE_FIRST_SECTION(nt_hdr);
	memcpy(image, file_data, sect->PointerToRawData);

	/* Copy sections */
	num_sections = nt_hdr->FileHeader.NumberOfSections;
	for (i = 0; i < num_sections; i++) {
		if (sect->VirtualAddress + sect->SizeOfRawData > image_size) {
			pr_err("nexus_nt: section %.*s exceeds image size\n",
			       IMAGE_SIZEOF_SHORT_NAME, sect->Name);
			vfree(image);
			return NULL;
		}
		if (sect->PointerToRawData + sect->SizeOfRawData > file_size) {
			pr_err("nexus_nt: section %.*s exceeds file size\n",
			       IMAGE_SIZEOF_SHORT_NAME, sect->Name);
			vfree(image);
			return NULL;
		}

		pr_info("nexus_nt: mapping section %.*s: file 0x%x -> rva 0x%x (%u bytes)\n",
			IMAGE_SIZEOF_SHORT_NAME, sect->Name,
			sect->PointerToRawData, sect->VirtualAddress,
			sect->SizeOfRawData);

		memcpy(image + sect->VirtualAddress,
		       file_data + sect->PointerToRawData,
		       sect->SizeOfRawData);
		sect++;
	}

	return image;
}

/*
 * Apply base relocations
 */
static int apply_relocations(void *image, IMAGE_NT_HEADERS *nt_hdr)
{
	IMAGE_DATA_DIRECTORY *reloc_dir;
	IMAGE_BASE_RELOCATION *block;
	ULONG_PTR base, delta;
	size_t total_size;

	reloc_dir = &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (reloc_dir->Size == 0)
		return 0;

	base = nt_hdr->OptionalHeader.ImageBase;
	delta = (ULONG_PTR)image - base;

	block = RVA2VA(image, reloc_dir->VirtualAddress, IMAGE_BASE_RELOCATION *);
	total_size = reloc_dir->Size;

	while (block->SizeOfBlock) {
		int i;
		int num_entries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (i = 0; i < num_entries; i++) {
			WORD fixup = block->TypeOffset[i];
			WORD type = (fixup >> 12) & 0x0f;
			WORD offset = fixup & 0xfff;
			void *loc = image + block->VirtualAddress + offset;

			switch (type) {
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			case IMAGE_REL_BASED_HIGHLOW: {
				uint32_t *p = (uint32_t *)loc;
				*p += (uint32_t)delta;
				break;
			}
			case IMAGE_REL_BASED_DIR64: {
				uint64_t *p = (uint64_t *)loc;
				*p += delta;
				break;
			}
			default:
				pr_warn("nexus_nt: unknown reloc type %d\n", type);
				break;
			}
		}

		block = (IMAGE_BASE_RELOCATION *)((void *)block + block->SizeOfBlock);
	}

	pr_info("nexus_nt: relocations applied (delta: 0x%llx)\n", (uint64_t)delta);
	return 0;
}

/*
 * Resolve imported functions
 */
static int resolve_imports(void *image, IMAGE_NT_HEADERS *nt_hdr)
{
	IMAGE_DATA_DIRECTORY *import_dir;
	IMAGE_IMPORT_DESCRIPTOR *desc;
	int unresolved = 0;

	import_dir = &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (import_dir->Size == 0)
		return 0;

	desc = RVA2VA(image, import_dir->VirtualAddress, IMAGE_IMPORT_DESCRIPTOR *);

	while (desc->Name) {
		char *dll_name = RVA2VA(image, desc->Name, char *);
		ULONG_PTR *lookup = RVA2VA(image, desc->u.OriginalFirstThunk, ULONG_PTR *);
		ULONG_PTR *address = RVA2VA(image, desc->FirstThunk, ULONG_PTR *);
		int i;

		pr_info("nexus_nt: resolving imports from %s\n", dll_name);

		for (i = 0; lookup[i]; i++) {
			if (IMAGE_SNAP_BY_ORDINAL(lookup[i])) {
				pr_warn("nexus_nt: ordinal import not supported\n");
				unresolved++;
				continue;
			}

			char *func_name = RVA2VA(image,
				(lookup[i] & ~IMAGE_ORDINAL_FLAG) + 2, char *);
			void *func_addr;

			if (nexus_resolve_import(func_name, &func_addr) < 0)
				unresolved++;

			address[i] = (ULONG_PTR)func_addr;
		}

		desc++;
	}

	if (unresolved > 0)
		pr_warn("nexus_nt: %d imports were stubbed\n", unresolved);

	return 0;
}

/*
 * Load a Windows .sys driver from a buffer
 */
int nexus_pe_load(const void *file_data, size_t file_size,
                  const char *name, struct nexus_driver **out_driver)
{
	struct nexus_driver *driver;
	IMAGE_DOS_HEADER *dos;
	IMAGE_NT_HEADERS *nt;
	void *image;
	size_t image_size;
	int ret;

	pr_info("nexus_nt: loading driver '%s' (%zu bytes)\n", name, file_size);

	ret = validate_pe(file_data, file_size);
	if (ret)
		return ret;

	dos = (IMAGE_DOS_HEADER *)file_data;
	nt = (IMAGE_NT_HEADERS *)((void *)file_data + dos->e_lfanew);

	/* Map PE into memory */
	image = map_pe_image(file_data, file_size, nt, &image_size);
	if (!image)
		return -ENOMEM;

	/* Update NT headers pointer to mapped image */
	nt = (IMAGE_NT_HEADERS *)(image + dos->e_lfanew);

	/* Apply relocations */
	ret = apply_relocations(image, nt);
	if (ret) {
		vfree(image);
		return ret;
	}

	/* Resolve imports */
	ret = resolve_imports(image, nt);
	if (ret) {
		vfree(image);
		return ret;
	}

	/* Create driver structure */
	driver = kzalloc(sizeof(*driver), GFP_KERNEL);
	if (!driver) {
		vfree(image);
		return -ENOMEM;
	}

	strncpy(driver->name, name, sizeof(driver->name) - 1);
	driver->image = image;
	driver->image_size = image_size;
	driver->nt_hdr = nt;
	driver->opt_hdr = &nt->OptionalHeader;
	driver->entry_point = RVA2VA(image,
		nt->OptionalHeader.AddressOfEntryPoint, void *);

	pr_info("nexus_nt: driver '%s' loaded at %p, entry at %p\n",
		name, image, driver->entry_point);
	pr_info("nexus_nt: image size: 0x%zx, sections: %d\n",
		image_size, nt->FileHeader.NumberOfSections);

	*out_driver = driver;
	return 0;
}

/*
 * Unload a driver
 */
void nexus_pe_unload(struct nexus_driver *driver)
{
	if (!driver)
		return;

	pr_info("nexus_nt: unloading driver '%s'\n", driver->name);

	if (driver->image)
		vfree(driver->image);

	kfree(driver);
}

/*
 * Call DriverEntry
 * WARNING: This calls Windows driver code in kernel space.
 * The driver must have all its imports resolved or it will crash.
 */
int nexus_pe_call_entry(struct nexus_driver *driver)
{
	typedef NTSTATUS (*driver_entry_fn)(void *driver_object, void *registry_path);
	driver_entry_fn entry;
	NTSTATUS status;

	if (!driver || !driver->entry_point) {
		pr_err("nexus_nt: no entry point\n");
		return -EINVAL;
	}

	pr_info("nexus_nt: calling DriverEntry at %p for '%s'\n",
		driver->entry_point, driver->name);

	entry = (driver_entry_fn)driver->entry_point;

	/* Call DriverEntry(NULL, NULL) — we pass NULL for both
	 * DriverObject and RegistryPath for now.
	 * A real implementation would create fake DRIVER_OBJECT. */
	status = entry(NULL, NULL);

	pr_info("nexus_nt: DriverEntry returned 0x%x (%s)\n",
		status, NT_SUCCESS(status) ? "SUCCESS" : "FAILED");

	return NT_SUCCESS(status) ? 0 : -EIO;
}
