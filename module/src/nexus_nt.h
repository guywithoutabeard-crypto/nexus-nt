/*
 * nexus_nt.h — NexusOS NT Kernel Compatibility Layer
 *
 * Provides NT kernel structures and APIs so Windows .sys drivers
 * (particularly anti-cheat) can load and run on Linux.
 *
 * Based on NDISwrapper PE loader (GPL-2.0)
 * NT structure definitions from ReactOS (GPL-2.0)
 *
 * License: GPL-2.0
 */

#ifndef _NEXUS_NT_H_
#define _NEXUS_NT_H_

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/module.h>

/* ===== Windows Base Types ===== */
typedef uint8_t   UCHAR, BOOLEAN, BYTE;
typedef int8_t    CHAR;
typedef uint16_t  USHORT, WORD, WCHAR;
typedef int16_t   SHORT;
typedef uint32_t  ULONG, DWORD;
typedef int32_t   LONG, NTSTATUS;
typedef uint64_t  ULONGLONG, ULONG_PTR;
typedef int64_t   LONGLONG, LONG_PTR;
typedef void      VOID, *PVOID;
typedef ULONG_PTR SIZE_T;
typedef UCHAR     KIRQL;

#define STATUS_SUCCESS            ((NTSTATUS)0x00000000)
#define STATUS_UNSUCCESSFUL       ((NTSTATUS)0xC0000001)
#define STATUS_NOT_IMPLEMENTED    ((NTSTATUS)0xC0000002)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define STATUS_ACCESS_DENIED      ((NTSTATUS)0xC0000022)
#define STATUS_BUFFER_TOO_SMALL   ((NTSTATUS)0xC0000023)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034)

#define NT_SUCCESS(status) ((NTSTATUS)(status) >= 0)

#define PASSIVE_LEVEL  0
#define APC_LEVEL      1
#define DISPATCH_LEVEL 2

/* ===== NT Doubly-Linked List (used everywhere in NT kernel) ===== */
typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY *Flink;
	struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

static inline void InitializeListHead(PLIST_ENTRY head) {
	head->Flink = head;
	head->Blink = head;
}

static inline void InsertTailList(PLIST_ENTRY head, PLIST_ENTRY entry) {
	entry->Blink = head->Blink;
	entry->Flink = head;
	head->Blink->Flink = entry;
	head->Blink = entry;
}

static inline BOOLEAN IsListEmpty(PLIST_ENTRY head) {
	return head->Flink == head;
}

/* ===== UNICODE_STRING ===== */
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	WCHAR  *Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _ANSI_STRING {
	USHORT Length;
	USHORT MaximumLength;
	CHAR   *Buffer;
} ANSI_STRING, *PANSI_STRING;

/* ===== EPROCESS — Fake Windows Process Structure ===== */
/*
 * Anti-cheat walks the ActiveProcessLinks list and reads fields
 * at specific offsets. We must match the Windows layout.
 * Offsets below are for Windows 10 22H2 x64.
 */

#define EPROCESS_IMAGEFILENAME_OFFSET   0x5A8
#define EPROCESS_UNIQUEPROCESSID_OFFSET 0x440
#define EPROCESS_ACTIVEPROCESSLINKS_OFFSET 0x448
#define EPROCESS_PEB_OFFSET             0x550
#define EPROCESS_TOKEN_OFFSET           0x4B8
#define EPROCESS_VADROOT_OFFSET         0x7D8

struct nexus_eprocess {
	/* We allocate a buffer large enough to hold the full "EPROCESS"
	 * and write fields at the correct offsets */
	uint8_t data[0x1000];

	/* Our internal bookkeeping (after the fake struct) */
	struct list_head list;         /* Linux list for our tracking */
	struct task_struct *task;      /* Real Linux process */
	pid_t pid;
};

/* ===== ETHREAD — Fake Windows Thread Structure ===== */
struct nexus_ethread {
	uint8_t data[0x800];
	struct list_head list;
	struct task_struct *task;
};

/* ===== SSDT — System Service Descriptor Table ===== */
/*
 * Anti-cheat reads the SSDT to check for hooks.
 * We build a fake one with the right number of entries.
 */
#define SSDT_NUM_ENTRIES 462  /* Windows 10 22H2 */

struct service_descriptor_table {
	void **ServiceTable;           /* Array of function pointers */
	ULONG *CounterTable;           /* Usage counters (can be NULL) */
	ULONG NumberOfServices;        /* Number of entries */
	UCHAR *ArgumentTable;          /* Argument byte counts */
};

/* ===== Kernel Module Entry (for fake loaded modules list) ===== */
struct nexus_fake_module {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;

	struct list_head list;  /* internal tracking */
};

/* ===== Object Manager ===== */
struct nexus_object_directory {
	char name[64];
	struct list_head children;     /* child directories */
	struct list_head objects;      /* objects in this directory */
	struct list_head sibling;      /* sibling in parent's children list */
};

struct nexus_object {
	char name[64];
	char type[32];                 /* "Device", "Driver", "Event", etc. */
	PVOID body;                    /* pointer to actual object body */
	struct list_head sibling;      /* sibling in directory's objects list */
};

/* ===== Process Notify Callbacks ===== */
#define MAX_PROCESS_NOTIFY_CALLBACKS 64

typedef void (*PCREATE_PROCESS_NOTIFY_ROUTINE)(
	PVOID ParentId, PVOID ProcessId, BOOLEAN Create);

typedef void (*PCREATE_PROCESS_NOTIFY_ROUTINE_EX)(
	PVOID Process, PVOID CreateInfo, BOOLEAN Create);

/* ===== ObRegisterCallbacks ===== */
typedef NTSTATUS (*POB_PRE_OPERATION_CALLBACK)(
	PVOID RegistrationContext, PVOID OperationInformation);

typedef void (*POB_POST_OPERATION_CALLBACK)(
	PVOID RegistrationContext, PVOID OperationInformation);

struct ob_callback_registration {
	USHORT Version;
	USHORT OperationRegistrationCount;
	UNICODE_STRING Altitude;
	PVOID RegistrationContext;
};

/* ===== PE Image Structure (from NDISwrapper) ===== */
struct pe_image {
	char name[64];
	void *image;
	int size;
	void *entry;
	void *nt_hdr;
	void *opt_hdr;
	int type;
};

/* ===== Global State ===== */
struct nexus_nt_state {
	/* Process tracking */
	struct list_head process_list;
	spinlock_t process_lock;
	LIST_ENTRY eprocess_list_head;  /* Fake ActiveProcessLinks head */

	/* SSDT */
	struct service_descriptor_table ssdt;
	void *ssdt_entries[SSDT_NUM_ENTRIES];

	/* Fake kernel modules */
	struct list_head module_list;
	LIST_ENTRY module_list_head;    /* Fake InLoadOrderLinks head */

	/* Object manager */
	struct nexus_object_directory root_directory;

	/* Process notify callbacks */
	PCREATE_PROCESS_NOTIFY_ROUTINE process_notify[MAX_PROCESS_NOTIFY_CALLBACKS];
	int num_process_notify;

	/* Loaded Windows drivers */
	struct pe_image loaded_drivers[16];
	int num_loaded_drivers;

	/* Module reference */
	struct module *owner;
};

extern struct nexus_nt_state nexus_state;

/* ===== API Functions We Export to Windows Drivers ===== */

/* Process/Thread */
PVOID NxPsGetCurrentProcess(void);
ULONG_PTR NxPsGetCurrentProcessId(void);
NTSTATUS NxPsLookupProcessByProcessId(ULONG_PTR pid, PVOID *process);
NTSTATUS NxPsSetCreateProcessNotifyRoutine(PCREATE_PROCESS_NOTIFY_ROUTINE callback, BOOLEAN remove);
NTSTATUS NxPsSetCreateProcessNotifyRoutineEx(PCREATE_PROCESS_NOTIFY_ROUTINE_EX callback, BOOLEAN remove);
UCHAR *NxPsGetProcessImageFileName(PVOID process);

/* Object Manager */
NTSTATUS NxObRegisterCallbacks(struct ob_callback_registration *reg, PVOID *handle);
void NxObUnRegisterCallbacks(PVOID handle);

/* System Information */
NTSTATUS NxZwQuerySystemInformation(ULONG class, PVOID buffer, ULONG length, PULONG ret_length);

/* Memory */
NTSTATUS NxMmCopyVirtualMemory(PVOID src_process, PVOID src_addr,
                                PVOID dst_process, PVOID dst_addr,
                                SIZE_T size, KIRQL prev_mode, PSIZE_T bytes_copied);

/* SSDT */
struct service_descriptor_table *NxKeServiceDescriptorTable(void);

/* Internal */
int nexus_nt_init(void);
void nexus_nt_exit(void);
int nexus_build_process_list(void);
int nexus_build_fake_modules(void);
int nexus_build_ssdt(void);
int nexus_build_object_directory(void);
int nexus_load_sys_driver(const char *path);

#endif /* _NEXUS_NT_H_ */
