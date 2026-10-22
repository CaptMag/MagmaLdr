#pragma once
#include <Windows.h>

// bullshit
#pragma warning(push)
#pragma warning(disable : 4201)
#pragma warning(disable : 4214)

// FileDispositionInformationEx definitions
#ifndef FILE_DISPOSITION_INFORMATION_EX
#define FILE_DISPOSITION_INFORMATION_EX struct _FILE_DISPOSITION_INFORMATION_EX
#define FileDispositionInformationEx ((INT)64)
#define FILE_DISPOSITION_DELETE 0x00000001
#define FILE_DISPOSITION_POSIX_SEMANTICS 0x00000002
FILE_DISPOSITION_INFORMATION_EX{
    ULONG Flags;
};
#endif

typedef struct _USTRING {
    DWORD  Length;
    DWORD  MaximumLength;
    PUCHAR Buffer;
} USTRING, * PUSTRING;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING;
typedef STRING* PSTRING;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1, // The mapped view of the section will be mapped into any child processes created by the process.
    ViewUnmap = 2  // The mapped view of the section will not be mapped into any child processes created by the process.
} SECTION_INHERIT;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef LONG KPRIORITY, * PKPRIORITY;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;                                // +0x00
    UCHAR Initialized;                           // +0x04
    PVOID SsHandle;                              // +0x08
    LIST_ENTRY InLoadOrderModuleList;            // +0x10
    LIST_ENTRY InMemoryOrderModuleList;          // +0x20
    LIST_ENTRY InInitializationOrderModuleList;  // +0x30
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;               // +0x00
    LIST_ENTRY InMemoryOrderLinks;             // +0x10
    LIST_ENTRY InInitializationOrderLinks;     // +0x20
    PVOID DllBase;                             // +0x30
    PVOID EntryPoint;                          // +0x38
    ULONG SizeOfImage;                         // +0x40
    UNICODE_STRING FullDllName;                // +0x48
    UNICODE_STRING BaseDllName;                // +0x58
    ULONG Flags;                               // +0x68
    USHORT LoadCount;                          // +0x6C
    USHORT TlsIndex;                           // +0x6E
    LIST_ENTRY HashLinks;                      // +0x70
    ULONG TimeDateStamp;                       // +0x80
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _LDR_RESLOADER_RET
{
    PVOID Module;
    IMAGE_RESOURCE_DATA_ENTRY* DataEntry;
    PVOID TargetModule;
} LDR_RESLOADER_RET, * PLDR_RESLOADER_RET;

typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    PVOID                         Reserved4[3];
    PVOID                         AtlThunkSListPtr;
    PVOID                         Reserved5;
    ULONG                         Reserved6;
    PVOID                         Reserved7;
    ULONG                         Reserved8;
    ULONG                         AtlThunkSListPtr32;
    PVOID                         Reserved9[45];
    BYTE                          Reserved10[96];
    BYTE                          Reserved11[128];
    PVOID                         Reserved12[1];
    ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _ACTIVATION_CONTEXT_DATA
{
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG TotalSize;
    ULONG DefaultTocOffset;     // to ACTIVATION_CONTEXT_DATA_TOC_HEADER
    ULONG ExtendedTocOffset;    // to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER
    ULONG AssemblyRosterOffset; // to ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
    ULONG Flags;                // ACTIVATION_CONTEXT_FLAG_*
} ACTIVATION_CONTEXT_DATA, * PACTIVATION_CONTEXT_DATA;

typedef struct _ACTIVATION_CONTEXT ACTIVATION_CONTEXT, * PACTIVATION_CONTEXT;

typedef _Function_class_(ACTIVATION_CONTEXT_NOTIFY_ROUTINE)
VOID NTAPI ACTIVATION_CONTEXT_NOTIFY_ROUTINE(
    _In_ ULONG NotificationType, // ACTIVATION_CONTEXT_NOTIFICATION_*
    _In_ PACTIVATION_CONTEXT ActivationContext,
    _In_ PACTIVATION_CONTEXT_DATA ActivationContextData,
    _In_opt_ PVOID NotificationContext,
    _In_opt_ PVOID NotificationData,
    _Inout_ PBOOLEAN DisableThisNotification
);

typedef ACTIVATION_CONTEXT_NOTIFY_ROUTINE* PACTIVATION_CONTEXT_NOTIFY_ROUTINE;

typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY
{
    ULONG Flags;
    UNICODE_STRING DosPath;
    HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, * PASSEMBLY_STORAGE_MAP_ENTRY;

typedef struct _ASSEMBLY_STORAGE_MAP
{
    ULONG Flags;
    ULONG AssemblyCount;
    PASSEMBLY_STORAGE_MAP_ENTRY* AssemblyArray;
} ASSEMBLY_STORAGE_MAP, * PASSEMBLY_STORAGE_MAP;

// Full definition (typedef names already introduced by the forward declaration)
struct _ACTIVATION_CONTEXT
{
    LONG RefCount;
    ULONG Flags;
    PACTIVATION_CONTEXT_DATA ActivationContextData;
    PACTIVATION_CONTEXT_NOTIFY_ROUTINE NotificationRoutine;
    PVOID NotificationContext;
    ULONG SentNotifications[8];
    ULONG DisabledNotifications[8];
    ASSEMBLY_STORAGE_MAP StorageMap;
    PASSEMBLY_STORAGE_MAP_ENTRY InlineStorageMapEntries[32];
};

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG Flags; // RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_*
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK
{
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags; // ACTIVATION_CONTEXT_STACK_FLAG_*
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG Flags;
    PCSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH
{
    ULONG Offset : 30;
    ULONG InProcessing : 1;
    ULONG HasRenderingCommand : 1;
    ULONG_PTR HDC;
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

#define WIN32_CLIENT_INFO_LENGTH 62
#define STATIC_UNICODE_BUFFER_LENGTH 261

typedef struct tagSOleTlsData
{
    PVOID ThreadBase;
    PVOID SmAllocator;
    ULONG ApartmentID;
    ULONG Flags; // OLETLSFLAGS
    LONG TlsMapIndex;
    PVOID* TlsSlot;
    ULONG ComInits;
    ULONG OleInits;
    ULONG Calls;
    PVOID ServerCall;      // previously CallInfo (before TH1)
    PVOID CallObjectCache; // previously FreeAsyncCall (before TH1)
    PVOID ContextStack;    // previously FreeClientCall (before TH1)
    PVOID ObjServer;
    ULONG TIDCaller;
    // ... (other fields are version-dependant)
} SOleTlsData, * PSOleTlsData;

typedef struct _TPP_CALLBACK_RECORD
{
    PVOID Callback;         // Function pointer recorded at callback entry
    PVOID Parameter;        // First argument passed to Callback
    PVOID SubProcessTag;    // TEB SubProcessTag active at callback entry
    ULONGLONG Timestamp;    // InterruptTime snapshot at callback entry
} TPP_CALLBACK_RECORD, * PTPP_CALLBACK_RECORD;

typedef struct _TPP_CALLER_RECORD
{
    PVOID ReturnAddress;    // Return address captured by TpCaptureCaller
    ULONG Type;             // Capture type (1 or 2, caller-supplied)
    ULONG Reserved;
} TPP_CALLER_RECORD, * PTPP_CALLER_RECORD;

typedef struct _TPP_THREAD_DATA
{
    PVOID ActiveCallbackObject;             // Pointer to the TP object (TP_WORK/TP_TIMER/TP_IO/TP_WAIT) currently executing on this thread; NULL between callbacks
    ULONG Flags;                            // Lifecycle flags: 0x3 = allocated, 0x4 = freeing
    ULONG CallbackRecordIndex;              // Ring index (0 or 1) selecting which CallbackRecords slot to write next
    ULONGLONG CallbackCount;                // Total callbacks dispatched on this thread
    ULONGLONG ThreadStartTimestamp;         // InterruptTime at TppAllocThreadData
    TPP_CALLBACK_RECORD CallbackRecords[2]; // Last two callback invocations (ring buffer keyed by CallbackRecordIndex)
    TPP_CALLER_RECORD CallerRecords[2];     // Last two TpCaptureCaller snapshots (ring buffer keyed by CallerRecordIndex)
    ULONG CallerRecordIndex;                // Ring index (0 or 1) selecting which CallerRecords slot to write next
    ULONG Reserved;
} TPP_THREAD_DATA, * PTPP_THREAD_DATA;

typedef struct _TEB
{
    //
    // Thread Information Block (TIB) contains the thread's stack, base and limit addresses, the current stack pointer, and the exception list.
    //
    NT_TIB NtTib;

    //
    // Reserved.
    //
    PVOID EnvironmentPointer;

    //
    // Client ID for this thread.
    //
    CLIENT_ID ClientId;

    //
    // A handle to an active Remote Procedure Call (RPC) if the thread is currently involved in an RPC operation.
    //
    PVOID ActiveRpcHandle;

    //
    // Pointer to the per-thread TLS data vector (PVOID[LdrpTlsBitmap] heap block, or self-pointer when no TLS is active).
    //
    PVOID* ThreadLocalStoragePointer;

    //
    // A pointer to the Process Environment Block (PEB), which contains information about the process.
    //
    PPEB ProcessEnvironmentBlock;

    //
    // The previous Win32 error value for this thread.
    //
    ULONG LastErrorValue;

    //
    // The number of critical sections currently owned by this thread.
    //
    ULONG CountOfOwnedCriticalSections;

    //
    // Reserved.
    //
    PVOID CsrClientThread;

    //
    // Reserved for win32k.sys
    //
    PVOID Win32ThreadInfo;

    //
    // Reserved for user32.dll
    //
    ULONG User32Reserved[26];

    //
    // Reserved for winsrv.dll
    //
    ULONG UserReserved[5];

    //
    // Reserved.
    //
    PVOID WOW32Reserved;

    //
    // The LCID of the current thread. (Kernel32!GetThreadLocale)
    //
    LCID CurrentLocale;

    //
    // Reserved.
    //
    ULONG FpSoftwareStatusRegister;

    //
    // Reserved.
    //
    PVOID ReservedForDebuggerInstrumentation[16];

#ifdef _WIN64
    //
    // Reserved for floating-point emulation.
    //
    PVOID SystemReserved1[25];

    //
    // Per-thread fiber local storage. (Teb->HasFiberData)
    //
    PVOID HeapFlsData;

    //
    // Reserved.
    //
    ULONG_PTR RngState[4];
#else
    //
    // Reserved.
    //
    PVOID SystemReserved1[26];
#endif

    //
    // Placeholder compatibility mode. (ProjFs and Cloud Files)
    //
    CHAR PlaceholderCompatibilityMode;

    //
    // Indicates whether placeholder hydration is always explicit.
    //
    BOOLEAN PlaceholderHydrationAlwaysExplicit;

    //
    // ProjFs and Cloud Files (reparse point) file virtualization.
    //
    CHAR PlaceholderReserved[10];

    //
    // The process ID (PID) that the current COM server thread is acting on behalf of.
    //
    ULONG ProxiedProcessId;

    //
    // Pointer to the activation context stack for the current thread.
    //
    ACTIVATION_CONTEXT_STACK ActivationStack;

    //
    // Scheduler ticket attributing this thread's CPU usage to another thread. Set/cleared via NtSetInformationThread(ThreadWorkOnBehalfTicket).
    //
    UCHAR WorkingOnBehalfTicket[8]; // ALPC_WORK_ON_BEHALF_TICKET

    //
    // The last exception status for the current thread.
    //
    NTSTATUS ExceptionCode;

    //
    // Pointer to the activation context stack for the current thread.
    //
    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;

    //
    // The stack pointer (SP) of the current system call or exception during instrumentation.
    //
    ULONG_PTR InstrumentationCallbackSp;

    //
    // The program counter (PC) of the previous system call or exception during instrumentation.
    //
    ULONG_PTR InstrumentationCallbackPreviousPc;

    //
    // The stack pointer (SP) of the previous system call or exception during instrumentation.
    //
    ULONG_PTR InstrumentationCallbackPreviousSp;

#ifdef _WIN64
    //
    // The miniversion ID of the current transacted file operation.
    //
    ULONG TxFsContext;
#endif

    //
    // Indicates the state of the system call or exception instrumentation callback.
    //
    BOOLEAN InstrumentationCallbackDisabled;

#ifdef _WIN64
    //
    // Indicates the state of alignment exceptions for unaligned load/store operations.
    //
    BOOLEAN UnalignedLoadStoreExceptions;
#endif

#ifndef _WIN64
    //
    // SpareBytes.
    //
    UCHAR SpareBytes[23];

    //
    // The miniversion ID of the current transacted file operation.
    //
    ULONG TxFsContext;
#endif

    //
    // Reserved for GDI (Win32k).
    //
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;

    //
    // User32 (Win32k) thread information.
    // (CLIENTINFO is not a public type, so the raw array is used instead of the
    //  PHNT_MODE-conditional union from the original; the layout is identical.)
    //
    ULONG_PTR Win32ClientInfo[WIN32_CLIENT_INFO_LENGTH];

    //
    // Reserved for opengl32.dll
    //
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    //
    // The previous status value for this thread.
    //
    NTSTATUS LastStatusValue;

    //
    // A static string for use by the application.
    //
    UNICODE_STRING StaticUnicodeString;

    //
    // A static buffer for use by the application.
    //
    WCHAR StaticUnicodeBuffer[STATIC_UNICODE_BUFFER_LENGTH];

    //
    // The maximum stack size and indicates the base of the stack.
    //
    PVOID DeallocationStack;

    //
    // Data for Thread Local Storage. (TlsGetValue)
    //
    PVOID TlsSlots[TLS_MINIMUM_AVAILABLE];

    //
    // Reserved for TLS.
    //
    LIST_ENTRY TlsLinks;

    //
    // Reserved for NTVDM.
    //
    PVOID Vdm;

    //
    // Reserved for RPC. The pointer is XOR'ed with RPC_THREAD_POINTER_KEY.
    //
    PVOID ReservedForNtRpc;

    //
    // Reserved for Debugging (DebugActiveProcess).
    //
    PVOID DbgSsReserved[2];

    //
    // The error mode for the current thread. (GetThreadErrorMode)
    //
    ULONG HardErrorMode;

    //
    // Reserved.
    //
#ifdef _WIN64
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif

    //
    // Reserved.
    //
    GUID ActivityId;

    //
    // The identifier of the service that created the thread. (svchost)
    //
    PVOID SubProcessTag;

    //
    // Reserved.
    //
    PVOID PerflibData;

    //
    // Reserved.
    //
    PVOID EtwTraceData;

    //
    // The address of a socket handle during a blocking socket operation. (WSAStartup)
    //
    HANDLE WinSockData;

    //
    // The number of function calls accumulated in the current GDI batch. (GdiSetBatchLimit)
    //
    ULONG GdiBatchCount;

    //
    // The preferred processor for the current thread. (SetThreadIdealProcessor/SetThreadIdealProcessorEx)
    //
    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    //
    // The minimum size of the stack available during any stack overflow exceptions. (SetThreadStackGuarantee)
    //
    ULONG GuaranteedStackBytes;

    //
    // Reserved.
    //
    PVOID ReservedForPerf;

    //
    // Reserved for Object Linking and Embedding (OLE)
    //
    PSOleTlsData ReservedForOle;

    //
    // Indicates whether the thread is waiting on the loader lock.
    //
    ULONG WaitingOnLoaderLock;

    //
    // The saved priority state for the thread.
    //
    PVOID SavedPriorityState;

    //
    // Reserved.
    //
    ULONG_PTR ReservedForCodeCoverage;

    //
    // Per-thread state for the NT thread pool.
    //
    PTPP_THREAD_DATA ThreadPoolData;

    //
    // Pointer to the TLS (Thread Local Storage) expansion slots for the thread.
    //
    PVOID* TlsExpansionSlots;

#ifdef _WIN64
    PVOID ChpeV2CpuAreaInfo; // CHPEV2_CPUAREA_INFO // previously DeallocationBStore
    PVOID Unused;            // previously BStoreLimit
#endif

    //
    // The generation of the MUI (Multilingual User Interface) data.
    //
    ULONG MuiGeneration;

    //
    // Indicates whether the thread is impersonating another security context.
    //
    ULONG IsImpersonating;

    //
    // Pointer to the NLS (National Language Support) cache.
    //
    PVOID NlsCache;

    //
    // Pointer to the AppCompat/Shim Engine data.
    //
    PVOID pShimData;

    //
    // Reserved.
    //
    ULONG HeapData;

    //
    // Handle to the current transaction associated with the thread.
    //
    HANDLE CurrentTransactionHandle;

    //
    // Pointer to the active frame for the thread.
    //
    PTEB_ACTIVE_FRAME ActiveFrame;

    //
    // Reserved for FLS (RtlProcessFlsData).
    //
    PVOID FlsData;

    //
    // Pointer to the preferred languages for the current thread. (GetThreadPreferredUILanguages)
    //
    PVOID PreferredLanguages;

    //
    // Pointer to the user-preferred languages for the current thread. (GetUserPreferredUILanguages)
    //
    PVOID UserPrefLanguages;

    //
    // Pointer to the merged preferred languages for the current thread. (MUI_MERGE_USER_FALLBACK)
    //
    PVOID MergedPrefLanguages;

    //
    // Indicates whether the thread is impersonating another user's language settings.
    //
    ULONG MuiImpersonation;

    //
    // Reserved.
    //
    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };

    //
    // SameTebFlags modify the state and behavior of the current thread.
    //
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;            // Indicates if the thread is currently in a debug print routine.
            USHORT HasFiberData : 1;            // Indicates if the thread has local fiber-local storage (FLS).
            USHORT SkipThreadAttach : 1;        // Indicates if the thread should suppress DLL_THREAD_ATTACH notifications.
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;          // Indicates if the thread has run process initialization code.
            USHORT ClonedThread : 1;            // Indicates if the thread is a clone of a different thread.
            USHORT SuppressDebugMsg : 1;        // Indicates if the thread should suppress LOAD_DLL_DEBUG_INFO notifications.
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;           // Indicates if the thread is the initial thread of the process.
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;               // Indicates if the thread is the owner of the process loader lock.
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SkipFileAPIBrokering : 1;
        };
    };

    //
    // Pointer to the callback function that is called when a KTM transaction scope is entered.
    //
    PVOID TxnScopeEnterCallback;

    //
    // Pointer to the callback function that is called when a KTM transaction scope is exited.
    //
    PVOID TxnScopeExitCallback;

    //
    // Pointer to optional context data for use by the application when a KTM transaction scope callback is called.
    //
    PVOID TxnScopeContext;

    //
    // The lock count of critical sections for the current thread.
    //
    ULONG LockCount;

    //
    // The offset to the WOW64 (Windows on Windows) TEB for the current thread.
    //
    LONG WowTebOffset;

    //
    // Pointer to the DLL containing the resource (valid after LdrFindResource_U/LdrResFindResource/etc... returns).
    //
    PLDR_RESLOADER_RET ResourceRetValue;

    //
    // Reserved for Windows Driver Framework (WDF).
    //
    PVOID ReservedForWdf;

    //
    // Reserved for the Microsoft C runtime (CRT).
    //
    ULONGLONG ReservedForCrt;

    //
    // The Host Compute Service (HCS) container identifier.
    //
    GUID EffectiveContainerId;

    //
    // Reserved for Kernel32!Sleep (SpinWait).
    //
    ULONGLONG LastSleepCounter; // since Win11

    //
    // Reserved for Kernel32!Sleep (SpinWait).
    //
    ULONG SpinCallCount;

    //
    // Extended feature disable mask (AVX).
    //
    union
    {
        ULONGLONG ExtendedFeatureDisableMask;
        struct
        {
            ULONGLONG LegacyFloatingPointDisabled : 1;
            ULONGLONG LegacySseDisabled : 1;
            ULONGLONG AvxDisabled : 1;
            ULONGLONG MpxBndregsDisabled : 1;
            ULONGLONG MpxBndcsrDisabled : 1;
            ULONGLONG Avx512OpmaskDisabled : 1;
            ULONGLONG Avx512ZmmHi256Disabled : 1;
            ULONGLONG Avx512Zmm16HiDisabled : 1;
            ULONGLONG IptDisabled : 1;
            ULONGLONG PkruDisabled : 1;
            ULONGLONG Reserved0 : 1;
            ULONGLONG CetUserDisabled : 1;
            ULONGLONG CetSupervisorDisabled : 1;
            ULONGLONG Reserved1 : 4;
            ULONGLONG AmxTileDisabled : 1;
            ULONGLONG AmxBf16Disabled : 1;
            ULONGLONG AmxInt8Disabled : 1;
            ULONGLONG Reserved2 : 44;
        };
    };

    //
    // Reserved.
    //
    PVOID SchedulerSharedDataSlot; // since 24H2

    //
    // Reserved.
    //
    PVOID HeapWalkContext;

    //
    // The primary processor group affinity of the thread.
    //
    GROUP_AFFINITY PrimaryGroupAffinity;

    //
    // Read-copy-update (RCU) synchronization context.
    //
    ULONG Rcu[2];
} TEB, * PTEB;

typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation,                         // q: THREAD_BASIC_INFORMATION
    ThreadTimes,                                    // q: KERNEL_USER_TIMES // since VISTA
    ThreadPriority,                                 // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
    ThreadBasePriority,                             // s: KPRIORITY
    ThreadAffinityMask,                             // s: KAFFINITY
    ThreadImpersonationToken,                       // s: HANDLE
    ThreadDescriptorTableEntry,                     // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
    ThreadEnableAlignmentFaultFixup,                // s: BOOLEAN
    ThreadEventPair,                                // q: Obsolete
    ThreadQuerySetWin32StartAddress,                // q: PVOID
    ThreadZeroTlsCell,                              // s: ULONG // TlsIndex // 10
    ThreadPerformanceCount,                         // q: LARGE_INTEGER
    ThreadAmILastThread,                            // q: ULONG
    ThreadIdealProcessor,                           // s: ULONG
    ThreadPriorityBoost,                            // qs: ULONG
    ThreadSetTlsArrayAddress,                       // s: ULONG_PTR
    ThreadIsIoPending,                              // q: ULONG
    ThreadHideFromDebugger,                         // qs: BOOLEAN
    ThreadBreakOnTermination,                       // qs: ULONG
    ThreadSwitchLegacyState,                        // s: void // NtCurrentThread // NPX/FPU
    ThreadIsTerminated,                             // q: ULONG // 20
    ThreadLastSystemCall,                           // q: THREAD_LAST_SYSCALL_INFORMATION
    ThreadIoPriority,                               // qs: IO_PRIORITY_HINT (s: requires SeIncreaseBasePriorityPrivilege)
    ThreadCycleTime,                                // q: THREAD_CYCLE_TIME_INFORMATION (requires THREAD_QUERY_LIMITED_INFORMATION)
    ThreadPagePriority,                             // qs: PAGE_PRIORITY_INFORMATION
    ThreadActualBasePriority,                       // q: LONG
    ThreadTebInformation,                           // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
    ThreadCSwitchMon,                               // q: Obsolete
    ThreadCSwitchPmu,                               // q: Obsolete
    ThreadWow64Context,                             // qs: WOW64_CONTEXT, ARM_NT_CONTEXT since 20H1
    ThreadGroupInformation,                         // qs: GROUP_AFFINITY // 30
    ThreadUmsInformation,                           // q: THREAD_UMS_INFORMATION // Obsolete
    ThreadCounterProfiling,                         // qs: THREAD_PROFILING_INFORMATION
    ThreadIdealProcessorEx,                         // qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
    ThreadCpuAccountingInformation,                 // s: HANDLE // since WIN8
    ThreadSuspendCount,                             // q: ULONG // since WINBLUE
    ThreadHeterogeneousCpuPolicy,                   // qs: KHETERO_CPU_POLICY // since THRESHOLD
    ThreadContainerId,                              // q: GUID
    ThreadNameInformation,                          // qs: THREAD_NAME_INFORMATION (requires THREAD_SET_LIMITED_INFORMATION)
    ThreadSelectedCpuSets,                          // qs: ULONG[]
    ThreadSystemThreadInformation,                  // q: SYSTEM_THREAD_INFORMATION // 40
    ThreadActualGroupAffinity,                      // q: GROUP_AFFINITY // since THRESHOLD2
    ThreadDynamicCodePolicyInfo,                    // qs: ULONG // NtCurrentThread
    ThreadExplicitCaseSensitivity,                  // qs: ULONG; s: 0 disables, otherwise enables // (requires SeDebugPrivilege and PsProtectedSignerAntimalware)
    ThreadWorkOnBehalfTicket,                       // q: RTL_WORK_ON_BEHALF_TICKET_EX; s: ALPC_WORK_ON_BEHALF_TICKET // NtCurrentThread
    ThreadSubsystemInformation,                     // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ThreadDbgkWerReportActive,                      // s: ULONG
    ThreadAttachContainer,                          // s: HANDLE (job object) // NtCurrentThread
    ThreadManageWritesToExecutableMemory,           // s: MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ThreadPowerThrottlingState,                     // qs: POWER_THROTTLING_THREAD_STATE // since REDSTONE3 (set), WIN11 22H2 (query)
    ThreadWorkloadClass,                            // qs: THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
    ThreadCreateStateChange,                        // s: Obsolete // since WIN11
    ThreadApplyStateChange,                         // s: Obsolete
    ThreadStrongerBadHandleChecks,                  // qs: ULONG // NtCurrentThread // since 22H1
    ThreadEffectiveIoPriority,                      // q: IO_PRIORITY_HINT
    ThreadEffectivePagePriority,                    // q: ULONG
    ThreadUpdateLockOwnership,                      // s: THREAD_LOCK_OWNERSHIP // since 24H2
    ThreadSchedulerSharedDataSlot,                  // qs: THREAD_SCHEDULER_SHARED_DATA_SLOT_INFORMATION
    ThreadTebInformationAtomic,                     // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_QUERY_INFORMATION)
    ThreadIndexInformation,                         // q: THREAD_INDEX_INFORMATION
    MaxThreadInfoClass
} THREADINFOCLASS;

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation,                        // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits,                             // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters,                              // q: IO_COUNTERS
    ProcessVmCounters,                              // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes,                                   // q: KERNEL_USER_TIMES // since VISTA
    ProcessBasePriority,                            // s: KPRIORITY
    ProcessRaisePriority,                           // s: PROCESS_RAISE_PRIORITY
    ProcessDebugPort,                               // q: HANDLE
    ProcessExceptionPort,                           // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
    ProcessAccessToken,                             // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation,                          // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize,                                 // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode,                    // qs: PROCESS_DEFAULT_HARD_ERROR_MODE
    ProcessIoPortHandlers,                          // s: PROCESS_IO_PORT_HANDLER_INFORMATION // (kernel-mode only)
    ProcessPooledUsageAndLimits,                    // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch,                         // qs: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL,                            // s: PROCESS_USER_MODE_IOPL (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup,               // s: BOOLEAN
    ProcessPriorityClass,                           // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information,                         // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount,                             // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask,                            // qs: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost,                           // qs: PROCESS_PRIORITY_BOOST
    ProcessDeviceMap,                               // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation,                      // qs: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation,                   // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information,                        // q: ULONG_PTR
    ProcessImageFileName,                           // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled,                   // q: PROCESS_LUID_DEVICE_MAPS_ENABLED
    ProcessBreakOnTermination,                      // qs: ULONG
    ProcessDebugObjectHandle,                       // q: HANDLE // 30
    ProcessDebugFlags,                              // qs: PROCESS_DEBUG_FLAGS
    ProcessHandleTracing,                           // qs: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
    ProcessIoPriority,                              // qs: IO_PRIORITY_HINT (s: requires SeIncreaseBasePriorityPrivilege)
    ProcessExecuteFlags,                            // qs: PROCESS_EXECUTE_FLAGS
    ProcessTlsInformation,                          // s: PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie,                                  // q: ULONG
    ProcessImageInformation,                        // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime,                               // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority,                            // qs: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback,                 // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation,                   // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx,                       // qs: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
    ProcessImageFileNameWin32,                      // q: UNICODE_STRING
    ProcessImageFileMapping,                        // q: HANDLE (input)
    ProcessAffinityUpdateMode,                      // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode,                    // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation,                        // q: PROCESS_GROUP_INFORMATION
    ProcessTokenVirtualizationEnabled,              // s: ULONG
    ProcessConsoleHostProcess,                      // qs: PROCESS_CONSOLE_HOST_PROCESS_INFORMATION
    ProcessWindowInformation,                       // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation,                       // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy,                        // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation,         // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
    ProcessHandleCheckingMode,                      // qs: PROCESS_HANDLE_CHECKING_MODE; s: 0 disables, otherwise enables
    ProcessKeepAliveCount,                          // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles,                       // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl,                       // s: PROCESS_WORKING_SET_CONTROL
    ProcessHandleTable,                             // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode,                   // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation,                  // q: UNICODE_STRING // 60
    ProcessProtectionInformation,                   // q: PS_PROTECTION
    ProcessMemoryExhaustion,                        // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation,                        // s: PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation,                  // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation,                // qs: PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation,               // qs: SYSTEM_CPU_SET_INFORMATION[5] // ProcessReserved1Information
    ProcessAllowedCpuSetsInformation,               // qs: SYSTEM_CPU_SET_INFORMATION[5] // ProcessReserved2Information
    ProcessSubsystemProcess,                        // s: void // EPROCESS->SubsystemProcess
    ProcessJobMemoryInformation,                    // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate,                               // qs: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose,    // qs: PROCESS_RAISE_UM_EXCEPTION_ON_INVALID_HANDLE_CLOSE; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,                    // qs: PROCESS_IUM_CHALLENGE_RESPONSE
    ProcessChildProcessInformation,                 // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation,         // qs: BOOLEAN; s: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation,                    // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues,                            // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES_V1
    ProcessPowerThrottlingState,                    // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessActivityThrottlePolicy,                  // qs: Obsolete // PROCESS_ACTIVITY_THROTTLE_POLICY // ProcessReserved3Information
    ProcessWin32kSyscallFilterInformation,          // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets,             // s: BOOLEAN // 80
    ProcessWakeInformation,                         // q: PROCESS_WAKE_INFORMATION // (kernel-mode only)
    ProcessEnergyTrackingState,                     // qs: PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory,          // s: MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,                 // q: ULONG
    ProcessTelemetryCoverage,                       // qs: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
    ProcessEnclaveInformation,                      // qs: Obsolete
    ProcessEnableReadWriteVmLogging,                // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation,                       // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection,                            // q: HANDLE
    ProcessDebugAuthInformation,                    // s: PROCESS_DEBUG_AUTH_INFORMATION // CiTool.exe -- device-id // PplDebugAuthorization // since RS4 // 90
    ProcessSystemResourceManagement,                // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber,                          // q: ULONGLONG
    ProcessLoaderDetour,                            // qs: Obsolete // since RS5
    ProcessSecurityDomainInformation,               // q: PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation,       // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging,                           // q: PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation,                   // qs: PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation,              // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation,          // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation,                // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
    ProcessDynamicEHContinuationTargets,            // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges,      // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange,                       // qs: Obsolete // since WIN11
    ProcessApplyStateChange,                        // qs: Obsolete
    ProcessEnableOptionalXStateFeatures,            // s: ULONG64 // EnableProcessOptionalXStateFeatures
    ProcessAltPrefetchParam,                        // qs: OVERRIDE_PREFETCH_PARAMETER // App Launch Prefetch (ALPF) // since 22H1
    ProcessAssignCpuPartitions,                     // s: HANDLE[]
    ProcessPriorityClassEx,                         // s: PROCESS_PRIORITY_CLASS_EX
    ProcessMembershipInformation,                   // q: PROCESS_MEMBERSHIP_INFORMATION
    ProcessEffectiveIoPriority,                     // q: IO_PRIORITY_HINT // 110
    ProcessEffectivePagePriority,                   // q: ULONG
    ProcessSchedulerSharedData,                     // s: PROCESS_SCHEDULER_SHARED_DATA_SLOT_INFORMATION // since 24H2
    ProcessSlistRollbackInformation,                // qs: no input buffer, length 0 on set, current process only
    ProcessNetworkIoCounters,                       // q: PROCESS_NETWORK_COUNTERS
    ProcessFindFirstThreadByTebValue,               // q: PROCESS_TEB_VALUE_INFORMATION // NtCurrentProcess
    ProcessEnclaveAddressSpaceRestriction,          // qs: Obsolete // since 25H2
    ProcessAvailableCpus,                           // qs: Obsolete // PROCESS_AVAILABLE_CPUS_INFORMATION
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;        // The exit status of the thread or STATUS_PENDING when the thread has not terminated. (GetExitCodeThread)
    PTEB TebBaseAddress;        // The base address of the memory region containing the TEB structure. (NtCurrentTeb)
    CLIENT_ID ClientId;         // The process and thread identifier of the thread.
    KAFFINITY AffinityMask;     // The affinity mask of the thread. (deprecated) (SetThreadAffinityMask)
    KPRIORITY Priority;         // The current priority of the thread. (GetThreadPriority)
    KPRIORITY BasePriority;     // The current base priority of the thread determined by the thread priority and process priority class.
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

#pragma warning(pop)