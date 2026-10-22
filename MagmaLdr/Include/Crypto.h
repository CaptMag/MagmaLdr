#pragma once
#include "Common.h"

typedef NTSTATUS(WINAPI* _SystemFunction033) (
	struct ustring* data,
	struct ustring* key);

typedef NTSTATUS(NTAPI* fnNtQueryInformationThread)(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    );