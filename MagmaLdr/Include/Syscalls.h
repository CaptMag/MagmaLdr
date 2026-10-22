#pragma once
#include <Windows.h>

#define SEARCH_RANGE 500
#define DOWN 32
#define UP -32

extern VOID InitIndirect(DWORD SystemServiceNumber, PVOID SyscallInstruction);
extern NTSTATUS ExecuteIndirect(...);

typedef struct
{

    BOOLEAN SyscallHook;

    struct
    {

        DWORD SyscallNumber;
        PVOID SyscallInstruction;
        PVOID FunctionAddress;

    } SyscallInfo;

} SyscallInfo, * pSyscallInfo;

BOOLEAN InvokeSyscalls
(
    _In_ pSyscallInfo SyscallConfig,
    _In_ BYTE ModuleId,
    _In_ DWORD ApiHash
);