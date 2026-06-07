/*
 * nexus_main.c — NexusOS NT Kernel Compatibility Layer
 *
 * Main kernel module entry point. Initializes fake NT kernel
 * structures and provides the environment Windows .sys drivers expect.
 *
 * License: GPL-2.0
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#include "nexus_nt.h"
#include "nexus_pe.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NexusOS Project");
MODULE_DESCRIPTION("NT Kernel Compatibility Layer for Windows Driver Loading");
MODULE_VERSION("0.1.0");

struct nexus_nt_state nexus_state;

/*
 * Build fake EPROCESS list from real Linux processes.
 * Anti-cheat walks ActiveProcessLinks and reads ImageFileName,
 * UniqueProcessId, etc. We mirror Linux's task list.
 */
int nexus_build_process_list(void)
{
	struct task_struct *task;
	struct nexus_eprocess *nep;
	PLIST_ENTRY active_links;

	spin_lock_init(&nexus_state.process_lock);
	INIT_LIST_HEAD(&nexus_state.process_list);
	InitializeListHead(&nexus_state.eprocess_list_head);

	rcu_read_lock();
	for_each_process(task) {
		nep = kzalloc(sizeof(*nep), GFP_ATOMIC);
		if (!nep)
			continue;

		nep->task = task;
		nep->pid = task->pid;

		/* Write UniqueProcessId at correct offset */
		*(ULONG_PTR *)(nep->data + EPROCESS_UNIQUEPROCESSID_OFFSET) =
			(ULONG_PTR)task->pid;

		/* Write ImageFileName at correct offset (15 chars max in Windows) */
		strncpy((char *)(nep->data + EPROCESS_IMAGEFILENAME_OFFSET),
			task->comm, 15);

		/* Set up ActiveProcessLinks at correct offset */
		active_links = (PLIST_ENTRY)(nep->data + EPROCESS_ACTIVEPROCESSLINKS_OFFSET);
		InsertTailList(&nexus_state.eprocess_list_head, active_links);

		/* Add to our internal tracking list */
		list_add_tail(&nep->list, &nexus_state.process_list);
	}
	rcu_read_unlock();

	pr_info("nexus_nt: built EPROCESS list with entries from /proc\n");
	return 0;
}

/*
 * Build fake kernel module list.
 * Anti-cheat expects to see ntoskrnl.exe, hal.dll, CI.dll, etc.
 * in the loaded modules list.
 */
int nexus_build_fake_modules(void)
{
	struct {
		const char *name;
		const char *path;
		ULONG size;
	} fake_mods[] = {
		{ "ntoskrnl.exe", "\\SystemRoot\\system32\\ntoskrnl.exe", 0x00A00000 },
		{ "hal.dll",      "\\SystemRoot\\system32\\hal.dll",      0x00080000 },
		{ "CI.dll",       "\\SystemRoot\\system32\\CI.dll",       0x00200000 },
		{ "clfs.sys",     "\\SystemRoot\\system32\\drivers\\clfs.sys", 0x00070000 },
		{ "tm.sys",       "\\SystemRoot\\system32\\drivers\\tm.sys",   0x00030000 },
		{ "PSHED.dll",    "\\SystemRoot\\system32\\PSHED.dll",    0x00040000 },
		{ "BOOTVID.dll",  "\\SystemRoot\\system32\\BOOTVID.dll",  0x00010000 },
		{ "FLTMGR.SYS",  "\\SystemRoot\\system32\\drivers\\FLTMGR.SYS", 0x00080000 },
		{ "msrpc.sys",    "\\SystemRoot\\system32\\drivers\\msrpc.sys",   0x000A0000 },
		{ "ksecdd.sys",   "\\SystemRoot\\system32\\drivers\\ksecdd.sys",  0x00050000 },
		{ "tcpip.sys",    "\\SystemRoot\\system32\\drivers\\tcpip.sys",   0x00400000 },
		{ "ndis.sys",     "\\SystemRoot\\system32\\drivers\\ndis.sys",    0x00200000 },
		{ NULL, NULL, 0 }
	};

	struct nexus_fake_module *mod;
	int i;
	ULONG_PTR base_addr = 0xFFFFF80000000000ULL; /* Typical Windows kernel base */

	INIT_LIST_HEAD(&nexus_state.module_list);
	InitializeListHead(&nexus_state.module_list_head);

	for (i = 0; fake_mods[i].name != NULL; i++) {
		mod = kzalloc(sizeof(*mod), GFP_KERNEL);
		if (!mod)
			continue;

		mod->DllBase = (PVOID)(base_addr + i * 0x01000000);
		mod->SizeOfImage = fake_mods[i].size;
		mod->EntryPoint = mod->DllBase + 0x1000;

		/* TODO: populate FullDllName and BaseDllName as UNICODE_STRING */

		InsertTailList(&nexus_state.module_list_head, &mod->InLoadOrderLinks);
		list_add_tail(&mod->list, &nexus_state.module_list);
	}

	pr_info("nexus_nt: built fake module list (%d modules)\n", i);
	return 0;
}

/*
 * Build fake SSDT.
 * Anti-cheat reads KeServiceDescriptorTable and checks:
 * - Number of entries matches expected Windows version
 * - Entries point to valid memory (not hooked)
 * We create a table with valid-looking function pointers.
 */
int nexus_build_ssdt(void)
{
	int i;
	/* Allocate a block of memory to serve as "syscall handlers" */
	void *fake_code = kzalloc(SSDT_NUM_ENTRIES * 16, GFP_KERNEL);
	if (!fake_code)
		return -ENOMEM;

	/* Fill with RET instructions (0xC3) so any accidental call returns safely */
	memset(fake_code, 0xC3, SSDT_NUM_ENTRIES * 16);

	nexus_state.ssdt.NumberOfServices = SSDT_NUM_ENTRIES;
	nexus_state.ssdt.ServiceTable = nexus_state.ssdt_entries;
	nexus_state.ssdt.CounterTable = NULL;
	nexus_state.ssdt.ArgumentTable = NULL;

	for (i = 0; i < SSDT_NUM_ENTRIES; i++)
		nexus_state.ssdt_entries[i] = fake_code + (i * 16);

	pr_info("nexus_nt: built fake SSDT (%d entries)\n", SSDT_NUM_ENTRIES);
	return 0;
}

/*
 * Build fake object directory tree.
 * Anti-cheat may walk \Device, \Driver, \ObjectTypes.
 */
int nexus_build_object_directory(void)
{
	struct nexus_object_directory *dev, *drv, *types;

	strncpy(nexus_state.root_directory.name, "\\", sizeof(nexus_state.root_directory.name));
	INIT_LIST_HEAD(&nexus_state.root_directory.children);
	INIT_LIST_HEAD(&nexus_state.root_directory.objects);

	/* \Device */
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (dev) {
		strncpy(dev->name, "Device", sizeof(dev->name));
		INIT_LIST_HEAD(&dev->children);
		INIT_LIST_HEAD(&dev->objects);
		list_add_tail(&dev->sibling, &nexus_state.root_directory.children);
	}

	/* \Driver */
	drv = kzalloc(sizeof(*drv), GFP_KERNEL);
	if (drv) {
		strncpy(drv->name, "Driver", sizeof(drv->name));
		INIT_LIST_HEAD(&drv->children);
		INIT_LIST_HEAD(&drv->objects);
		list_add_tail(&drv->sibling, &nexus_state.root_directory.children);
	}

	/* \ObjectTypes */
	types = kzalloc(sizeof(*types), GFP_KERNEL);
	if (types) {
		strncpy(types->name, "ObjectTypes", sizeof(types->name));
		INIT_LIST_HEAD(&types->children);
		INIT_LIST_HEAD(&types->objects);
		list_add_tail(&types->sibling, &nexus_state.root_directory.children);
	}

	pr_info("nexus_nt: built object directory tree\n");
	return 0;
}

/* ===== NT API Implementations ===== */

PVOID NxPsGetCurrentProcess(void)
{
	struct nexus_eprocess *nep;
	pid_t pid = current->pid;

	list_for_each_entry(nep, &nexus_state.process_list, list) {
		if (nep->pid == pid)
			return (PVOID)nep->data;
	}
	return NULL;
}

ULONG_PTR NxPsGetCurrentProcessId(void)
{
	return (ULONG_PTR)current->pid;
}

NTSTATUS NxPsLookupProcessByProcessId(ULONG_PTR pid, PVOID *process)
{
	struct nexus_eprocess *nep;

	list_for_each_entry(nep, &nexus_state.process_list, list) {
		if (nep->pid == (pid_t)pid) {
			*process = (PVOID)nep->data;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS NxPsSetCreateProcessNotifyRoutine(
	PCREATE_PROCESS_NOTIFY_ROUTINE callback, BOOLEAN remove)
{
	if (remove) {
		int i;
		for (i = 0; i < nexus_state.num_process_notify; i++) {
			if (nexus_state.process_notify[i] == callback) {
				nexus_state.process_notify[i] = NULL;
				return STATUS_SUCCESS;
			}
		}
		return STATUS_UNSUCCESSFUL;
	}

	if (nexus_state.num_process_notify >= MAX_PROCESS_NOTIFY_CALLBACKS)
		return STATUS_UNSUCCESSFUL;

	nexus_state.process_notify[nexus_state.num_process_notify++] = callback;
	pr_info("nexus_nt: driver registered process notify callback\n");
	return STATUS_SUCCESS;
}

UCHAR *NxPsGetProcessImageFileName(PVOID process)
{
	return (UCHAR *)((uint8_t *)process + EPROCESS_IMAGEFILENAME_OFFSET);
}

struct service_descriptor_table *NxKeServiceDescriptorTable(void)
{
	return &nexus_state.ssdt;
}

NTSTATUS NxZwQuerySystemInformation(ULONG info_class, PVOID buffer,
                                     ULONG length, PULONG ret_length)
{
	pr_info("nexus_nt: ZwQuerySystemInformation called (class %u)\n", info_class);
	if (ret_length)
		*ret_length = 0;
	return STATUS_NOT_IMPLEMENTED;
}

/* ===== Proc Interface for Debugging ===== */
static int nexus_proc_show(struct seq_file *m, void *v)
{
	struct nexus_eprocess *nep;
	struct nexus_fake_module *mod;

	seq_printf(m, "=== NexusOS NT Compatibility Layer v0.1 ===\n\n");

	seq_printf(m, "EPROCESS List:\n");
	list_for_each_entry(nep, &nexus_state.process_list, list) {
		seq_printf(m, "  PID %5d  %s\n", nep->pid,
			   (char *)(nep->data + EPROCESS_IMAGEFILENAME_OFFSET));
	}

	seq_printf(m, "\nFake Kernel Modules:\n");
	list_for_each_entry(mod, &nexus_state.module_list, list) {
		seq_printf(m, "  Base: %p  Size: 0x%X\n",
			   mod->DllBase, mod->SizeOfImage);
	}

	seq_printf(m, "\nSSDT: %d entries\n", nexus_state.ssdt.NumberOfServices);
	seq_printf(m, "Process notify callbacks: %d\n", nexus_state.num_process_notify);

	return 0;
}

static int nexus_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, nexus_proc_show, NULL);
}

static const struct proc_ops nexus_proc_ops = {
	.proc_open    = nexus_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ===== Module Init/Exit ===== */

static int __init nexus_nt_module_init(void)
{
	pr_info("nexus_nt: initializing NT kernel compatibility layer\n");

	memset(&nexus_state, 0, sizeof(nexus_state));
	nexus_state.owner = THIS_MODULE;

	nexus_build_process_list();
	nexus_build_fake_modules();
	nexus_build_ssdt();
	nexus_build_object_directory();

	proc_create("nexus_nt", 0444, NULL, &nexus_proc_ops);

	pr_info("nexus_nt: ready. cat /proc/nexus_nt for status.\n");
	return 0;
}

static void __exit nexus_nt_module_exit(void)
{
	struct nexus_eprocess *nep, *nep_tmp;
	struct nexus_fake_module *mod, *mod_tmp;

	remove_proc_entry("nexus_nt", NULL);

	list_for_each_entry_safe(nep, nep_tmp, &nexus_state.process_list, list) {
		list_del(&nep->list);
		kfree(nep);
	}

	list_for_each_entry_safe(mod, mod_tmp, &nexus_state.module_list, list) {
		list_del(&mod->list);
		kfree(mod);
	}

	/* Free SSDT fake code block */
	if (nexus_state.ssdt_entries[0])
		kfree(nexus_state.ssdt_entries[0]);

	pr_info("nexus_nt: unloaded\n");
}

module_init(nexus_nt_module_init);
module_exit(nexus_nt_module_exit);
