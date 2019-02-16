#pragma once
/// See: MEMORY-MANAGEMENT REGISTERS
#include <pshpack1.h>
struct Idtr {
	unsigned short limit;
	ULONG_PTR base;
};

struct Idtr32 {
	unsigned short limit;
	ULONG32 base;
};
static_assert(sizeof(Idtr32) == 6, "Size check");

/// @copydoc Idtr
using Gdtr = Idtr;
#if defined(_AMD64_)
static_assert(sizeof(Idtr) == 10, "Size check");
static_assert(sizeof(Gdtr) == 10, "Size check");
#else
static_assert(sizeof(Idtr) == 6, "Size check");
static_assert(sizeof(Gdtr) == 6, "Size check");
#endif
#include <poppack.h>

/// See: Segment Selectors
#include <pshpack1.h>
union SegmentSelector {
	unsigned short all;
	struct {
		unsigned short rpl : 2;  //!< Requested Privilege Level
		unsigned short ti : 1;   //!< Table Indicator
		unsigned short index : 13;
	} fields;
};
static_assert(sizeof(SegmentSelector) == 2, "Size check");
#include <poppack.h>

/// See: Segment Descriptor
union SegmentDescriptor {
	ULONG64 all;
	struct {
		ULONG64 limit_low : 16;
		ULONG64 base_low : 16;
		ULONG64 base_mid : 8;
		ULONG64 type : 4;
		ULONG64 system : 1;
		ULONG64 dpl : 2;
		ULONG64 present : 1;
		ULONG64 limit_high : 4;
		ULONG64 avl : 1;
		ULONG64 l : 1;  //!< 64-bit code segment (IA-32e mode only)
		ULONG64 db : 1;
		ULONG64 gran : 1;
		ULONG64 base_high : 8;
	} fields;
};
static_assert(sizeof(SegmentDescriptor) == 8, "Size check");

/// @copydoc SegmentDescriptor
struct SegmentDesctiptorX64 {
	SegmentDescriptor descriptor;
	ULONG32 base_upper32;
	ULONG32 reserved;
};
static_assert(sizeof(SegmentDesctiptorX64) == 16, "Size check");

/// See: MODEL-SPECIFIC REGISTERS (MSRS)
enum class Msr : unsigned int {
	kIa32ApicBase = 0x01B,

	kIa32FeatureControl = 0x03A,

	kIa32SysenterCs = 0x174,
	kIa32SysenterEsp = 0x175,
	kIa32SysenterEip = 0x176,

	kIa32Debugctl = 0x1D9,

	kIa32MtrrCap = 0xFE,
	kIa32MtrrDefType = 0x2FF,
	kIa32MtrrPhysBaseN = 0x200,
	kIa32MtrrPhysMaskN = 0x201,
	kIa32MtrrFix64k00000 = 0x250,
	kIa32MtrrFix16k80000 = 0x258,
	kIa32MtrrFix16kA0000 = 0x259,
	kIa32MtrrFix4kC0000 = 0x268,
	kIa32MtrrFix4kC8000 = 0x269,
	kIa32MtrrFix4kD0000 = 0x26A,
	kIa32MtrrFix4kD8000 = 0x26B,
	kIa32MtrrFix4kE0000 = 0x26C,
	kIa32MtrrFix4kE8000 = 0x26D,
	kIa32MtrrFix4kF0000 = 0x26E,
	kIa32MtrrFix4kF8000 = 0x26F,

	kIa32VmxBasic = 0x480,
	kIa32VmxPinbasedCtls = 0x481,
	kIa32VmxProcBasedCtls = 0x482,
	kIa32VmxExitCtls = 0x483,
	kIa32VmxEntryCtls = 0x484,
	kIa32VmxMisc = 0x485,
	kIa32VmxCr0Fixed0 = 0x486,
	kIa32VmxCr0Fixed1 = 0x487,
	kIa32VmxCr4Fixed0 = 0x488,
	kIa32VmxCr4Fixed1 = 0x489,
	kIa32VmxVmcsEnum = 0x48A,
	kIa32VmxProcBasedCtls2 = 0x48B,
	kIa32VmxEptVpidCap = 0x48C,
	kIa32VmxTruePinbasedCtls = 0x48D,
	kIa32VmxTrueProcBasedCtls = 0x48E,
	kIa32VmxTrueExitCtls = 0x48F,
	kIa32VmxTrueEntryCtls = 0x490,
	kIa32VmxVmfunc = 0x491,

	kIa32Efer = 0xC0000080,
	kIa32Star = 0xC0000081,
	kIa32Lstar = 0xC0000082,

	kIa32Fmask = 0xC0000084,

	kIa32FsBase = 0xC0000100,
	kIa32GsBase = 0xC0000101,
	kIa32KernelGsBase = 0xC0000102,
	kIa32TscAux = 0xC0000103,
};

union FlagRegister {
	ULONG_PTR all;
	struct {
		ULONG_PTR cf : 1;          //!< [0] Carry flag
		ULONG_PTR reserved1 : 1;   //!< [1] Always 1
		ULONG_PTR pf : 1;          //!< [2] Parity flag
		ULONG_PTR reserved2 : 1;   //!< [3] Always 0
		ULONG_PTR af : 1;          //!< [4] Borrow flag
		ULONG_PTR reserved3 : 1;   //!< [5] Always 0
		ULONG_PTR zf : 1;          //!< [6] Zero flag
		ULONG_PTR sf : 1;          //!< [7] Sign flag
		ULONG_PTR tf : 1;          //!< [8] Trap flag
		ULONG_PTR intf : 1;        //!< [9] Interrupt flag
		ULONG_PTR df : 1;          //!< [10] Direction flag
		ULONG_PTR of : 1;          //!< [11] Overflow flag
		ULONG_PTR iopl : 2;        //!< [12:13] I/O privilege level
		ULONG_PTR nt : 1;          //!< [14] Nested task flag
		ULONG_PTR reserved4 : 1;   //!< [15] Always 0
		ULONG_PTR rf : 1;          //!< [16] Resume flag
		ULONG_PTR vm : 1;          //!< [17] Virtual 8086 mode
		ULONG_PTR ac : 1;          //!< [18] Alignment check
		ULONG_PTR vif : 1;         //!< [19] Virtual interrupt flag
		ULONG_PTR vip : 1;         //!< [20] Virtual interrupt pending
		ULONG_PTR id : 1;          //!< [21] Identification flag
		ULONG_PTR reserved5 : 10;  //!< [22:31] Always 0
	} fields;
};
static_assert(sizeof(FlagRegister) == sizeof(void*), "Size check");

#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_QUERY_EA                 0x07
#define IRP_MJ_SET_EA                   0x08
#define IRP_MJ_FLUSH_BUFFERS            0x09
#define IRP_MJ_QUERY_VOLUME_INFORMATION 0x0a
#define IRP_MJ_SET_VOLUME_INFORMATION   0x0b
#define IRP_MJ_DIRECTORY_CONTROL        0x0c
#define IRP_MJ_FILE_SYSTEM_CONTROL      0x0d
#define IRP_MJ_DEVICE_CONTROL           0x0e
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0f
#define IRP_MJ_SHUTDOWN                 0x10
#define IRP_MJ_LOCK_CONTROL             0x11
#define IRP_MJ_CLEANUP                  0x12
#define IRP_MJ_CREATE_MAILSLOT          0x13
#define IRP_MJ_QUERY_SECURITY           0x14
#define IRP_MJ_SET_SECURITY             0x15
#define IRP_MJ_POWER                    0x16
#define IRP_MJ_SYSTEM_CONTROL           0x17
#define IRP_MJ_DEVICE_CHANGE            0x18
#define IRP_MJ_QUERY_QUOTA              0x19
#define IRP_MJ_SET_QUOTA                0x1a
#define IRP_MJ_PNP                      0x1b
#define IRP_MJ_PNP_POWER                IRP_MJ_PNP      // Obsolete....
#define IRP_MJ_MAXIMUM_FUNCTION         0x1b

typedef struct _DRIVER_OBJECT {
	SHORT Type;
	SHORT Size;

	//
	// The following links all of the devices created by a single driver
	// together on a list, and the Flags word provides an extensible flag
	// location for driver objects.
	//

	PVOID DeviceObject;
	ULONG Flags;

	//
	// The following section describes where the driver is loaded.  The count
	// field is used to count the number of times the driver has had its
	// registered reinitialization routine invoked.
	//

	PVOID DriverStart;
	ULONG DriverSize;
	PVOID DriverSection;
	PVOID DriverExtension;

	//
	// The driver name field is used by the error log thread
	// determine the name of the driver that an I/O request is/was bound.
	//

	UNICODE_STRING DriverName;

	//
	// The following section is for registry support.  This is a pointer
	// to the path to the hardware information in the registry
	//

	PUNICODE_STRING HardwareDatabase;

	//
	// The following section contains the optional pointer to an array of
	// alternate entry points to a driver for "fast I/O" support.  Fast I/O
	// is performed by invoking the driver routine directly with separate
	// parameters, rather than using the standard IRP call mechanism.  Note
	// that these functions may only be used for synchronous I/O, and when
	// the file is cached.
	//

	PVOID FastIoDispatch;

	//
	// The following section describes the entry points to this particular
	// driver.  Note that the major function dispatch table must be the last
	// field in the object so that it remains extensible.
	//

	PVOID DriverInit;
	PVOID DriverStartIo;
	PVOID DriverUnload;
	PVOID MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];

} DRIVER_OBJECT;
typedef struct _DRIVER_OBJECT *PDRIVER_OBJECT;

typedef enum _SYSTEM_INFORMATION_CLASS_EX
{
	SystemProcessorInformation = 0x1,
	SystemPathInformation = 0x4,
	SystemCallCountInformation = 0x6,
	SystemDeviceInformation = 0x7,
	SystemFlagsInformation = 0x9,
	SystemCallTimeInformation = 0xa,
	SystemModuleInformation = 0xb,
	SystemLocksInformation = 0xc,
	SystemStackTraceInformation = 0xd,
	SystemPagedPoolInformation = 0xe,
	SystemNonPagedPoolInformation = 0xf,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1a,
	SystemUnloadGdiDriverInformation = 0x1b,
	SystemTimeAdjustmentInformation = 0x1c,
	SystemSummaryMemoryInformation = 0x1d,
	SystemMirrorMemoryInformation = 0x1e,
	SystemPerformanceTraceInformation = 0x1f,
	SystemObsolete0 = 0x20,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2a,
	SystemLegacyDriverInformation = 0x2b,
	SystemCurrentTimeZoneInformation = 0x2c,
	SystemTimeSlipNotification = 0x2e,
	SystemSessionCreate = 0x2f,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3a,
	SystemComPlusPackage = 0x3b,
	SystemNumaAvailableMemory = 0x3c,
	SystemProcessorPowerInformation = 0x3d,
	SystemEmulationBasicInformation = 0x3e,
	SystemEmulationProcessorInformation = 0x3f,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4a,
	SystemRegisterFirmwareTableInformationHandler = 0x4b,
	SystemFirmwareTableInformation = 0x4c,
	SystemModuleInformationEx = 0x4d,
	SystemVerifierTriageInformation = 0x4e,
	SystemSuperfetchInformation = 0x4f,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5a,
	SystemHypervisorInformation = 0x5b,
	SystemVerifierInformationEx = 0x5c,
	SystemTimeZoneInformation = 0x5d,
	SystemImageFileExecutionOptionsInformation = 0x5e,
	SystemCoverageInformation = 0x5f,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6a,
	SystemLogicalProcessorAndGroupInformation = 0x6b,
	SystemProcessorCycleTimeInformation = 0x6c,
	SystemStoreInformation = 0x6d,
	SystemRegistryAppendString = 0x6e,
	SystemAitSamplingValue = 0x6f,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7a,
	SystemBasicPerformanceInformation = 0x7b,
	SystemQueryPerformanceCounterInformation = 0x7c,
	SystemSessionBigPoolInformation = 0x7d,
	SystemBootGraphicsInformation = 0x7e,
	SystemScrubPhysicalMemoryInformation = 0x7f,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemThrottleNotificationInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8a,
	SystemMemoryChannelInformation = 0x8b,
	SystemBootLogoInformation = 0x8c,
	SystemProcessorPerformanceInformationEx = 0x8d,
	SystemSpare0 = 0x8e,
	SystemSecureBootPolicyInformation = 0x8f,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9a,
	SystemRegistryReconciliationInformation = 0x9b,

	SystemKernelVaShadowInformation = 196,
	MaxSystemInfoClass = 0x9c,
} SYSTEM_INFORMATION_CLASS_EX;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;         // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_USER_PROCESS_PARAMETERS_EX {
	ULONG                   MaximumLength;//+0
	ULONG                   Length;//+4
	ULONG                   Flags;//+8
	ULONG                   DebugFlags;//+12
	PVOID                   ConsoleHandle;//+16
	ULONG                   ConsoleFlags;//+24
	HANDLE                  StdInputHandle;//+32
	HANDLE                  StdOutputHandle;//+40
	HANDLE                  StdErrorHandle;//+48
	UNICODE_STRING          CurrentDirectoryPath;//+56
	HANDLE                  CurrentDirectoryHandle;//+72
	UNICODE_STRING          DllPath;//+80
	UNICODE_STRING ImagePathName;//Offset=96 in x64
	UNICODE_STRING CommandLine;
	//MORE
} RTL_USER_PROCESS_PARAMETERS_EX, *PRTL_USER_PROCESS_PARAMETERS_EX;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _RTL_CRITICAL_SECTION_64 {
	uint64_t DebugInfo;
	uint32_t LockCount;
	uint32_t RecursionCount;
	uint64_t OwningThread;
	uint64_t LockSemaphore;
	uint64_t SpinCount;
} RTL_CRITICAL_SECTION_64, *PRTL_CRITICAL_SECTION_64;

typedef struct _MDL {
	struct _MDL *Next;
	SHORT Size;
	SHORT MdlFlags;

	PVOID Process;
	PVOID MappedSystemVa;   /* see creators for field size annotations. */
	PVOID StartVa;   /* see creators for validity; could be address 0.  */
	ULONG ByteCount;
	ULONG ByteOffset;
} MDL, *PMDL;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
	BOOLEAN DebuggerEnabled;
	BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	PVOID NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

#define MAXIMUM_INVERTED_FUNCTION_TABLE_SIZE 160

typedef struct _INVERTED_FUNCTION_TABLE_ENTRY {
	PRUNTIME_FUNCTION FunctionTable;
	PVOID ImageBase;
	ULONG SizeOfImage;
	ULONG SizeOfTable;
} INVERTED_FUNCTION_TABLE_ENTRY, *PINVERTED_FUNCTION_TABLE_ENTRY;

typedef struct _INVERTED_FUNCTION_TABLE {
	ULONG CurrentSize;
	ULONG MaximumSize;
	BOOLEAN Overflow;
	INVERTED_FUNCTION_TABLE_ENTRY TableEntry[MAXIMUM_INVERTED_FUNCTION_TABLE_SIZE];
} INVERTED_FUNCTION_TABLE, *PINVERTED_FUNCTION_TABLE;

typedef enum _UNWIND_OP_CODES {
	UWOP_PUSH_NONVOL = 0,
	UWOP_ALLOC_LARGE,
	UWOP_ALLOC_SMALL,
	UWOP_SET_FPREG,
	UWOP_SAVE_NONVOL,
	UWOP_SAVE_NONVOL_FAR,
	UWOP_SPARE_CODE1,
	UWOP_SPARE_CODE2,
	UWOP_SAVE_XMM128,
	UWOP_SAVE_XMM128_FAR,
	UWOP_PUSH_MACHFRAME
} UNWIND_OP_CODES, *PUNWIND_OP_CODES;

//
// Define unwind code structure.
//

typedef union _UNWIND_CODE {
	struct {
		UCHAR CodeOffset;
		UCHAR UnwindOp : 4;
		UCHAR OpInfo : 4;
	};

	USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

//
// Define unwind information flags.
//

#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2
#define UNW_FLAG_CHAININFO 0x4

//
// Define unwind information structure.
//

typedef struct _UNWIND_INFO {
	UCHAR Version : 3;
	UCHAR Flags : 5;
	UCHAR SizeOfProlog;
	UCHAR CountOfCodes;
	UCHAR FrameRegister : 4;
	UCHAR FrameOffset : 4;
	UNWIND_CODE UnwindCode[1];

	//
	// The unwind codes are followed by an optional DWORD aligned field that
	// contains the exception handler address or a function table entry if
	// chained unwind information is specified. If an exception handler address
	// is specified, then it is followed by the language specified exception
	// handler data.
	//
	//  union {
	//      struct {
	//          ULONG ExceptionHandler;
	//          ULONG ExceptionData[];
	//      };
	//
	//      RUNTIME_FUNCTION FunctionEntry;
	//  };
	//

} UNWIND_INFO, *PUNWIND_INFO;