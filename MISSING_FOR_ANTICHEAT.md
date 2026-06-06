# What NDISwrapper Has vs What Anti-Cheat Needs

## Already Implemented (389 functions) ✅
- ExAllocatePoolWithTag / ExFreePool (memory)
- IoCreateDevice / IoDeleteDevice (driver devices)
- KeInitializeSpinLock / KeAcquireSpinLock (sync)
- MmGetSystemRoutineAddress (dynamic function resolution)
- ObReferenceObjectByHandle (object manager)
- ZwCreateFile / ZwReadFile / ZwClose (file I/O)
- ZwOpenKey / ZwQueryValueKey (registry)
- PsCreateSystemThread (threading)
- All interlocked operations
- Timer, DPC, event, mutex, semaphore
- MDL (Memory Descriptor List) management
- Port I/O operations

## MISSING — Must Build for Anti-Cheat ❌

### Process/Thread Inspection (CRITICAL)
- PsGetCurrentProcess — get current EPROCESS
- PsGetCurrentProcessId — get PID
- PsLookupProcessByProcessId — find process by PID
- PsSetCreateProcessNotifyRoutine — watch process creation
- PsSetCreateProcessNotifyRoutineEx — extended version
- PsSetCreateThreadNotifyRoutine — watch thread creation
- PsSetLoadImageNotifyRoutine — watch DLL loads
- PsGetProcessImageFileName — get process name
- PsGetProcessPeb — get Process Environment Block

### Object Manager (CRITICAL)
- ObRegisterCallbacks — monitor handle operations
- ObUnRegisterCallbacks
- ObOpenObjectByName — open named objects
- ObQueryNameString — get object name

### System Information (CRITICAL)
- ZwQuerySystemInformation — THE BIG ONE
  - SystemProcessInformation (class 5)
  - SystemModuleInformation (class 11)
  - SystemHandleInformation (class 16)
  - SystemKernelDebuggerInformation (class 35)

### Memory Scanning
- MmCopyVirtualMemory — read other process memory
- ZwQueryVirtualMemory — query memory regions
- KeStackAttachProcess — attach to another process's address space
- KeUnstackDetachProcess

### Kernel Module Info
- ZwQuerySystemInformation(SystemModuleInformation) — list loaded modules
- Fake module list showing ntoskrnl.exe, hal.dll, CI.dll, etc.

### SSDT
- KeServiceDescriptorTable — must exist and look valid
- Correct number of entries
- Entries point to valid memory

### Fake Structures Needed
- EPROCESS chain (ActiveProcessLinks doubly-linked list)
- ETHREAD chain
- PEB (Process Environment Block) per process
- KUSER_SHARED_DATA at correct address
- Kernel module list (LDR_DATA_TABLE_ENTRY)
- Object directory tree (\Device, \Driver, \ObjectTypes)
