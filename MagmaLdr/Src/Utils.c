#include "Common.h"

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

PVOID MEMSET
(
	_In_ PVOID	Destination,
	_In_ INT	c,
	_In_ SIZE_T Count
)
{

	INT		i = 0;
	PUCHAR	p = (PUCHAR)Destination;

	while (Count > 0)
	{
		*p++ = (UCHAR)c;
		Count--;
	}

	return Destination;

}

VOID MEMCPY
(
	_In_ PVOID	Destination,
	_In_ PVOID	Source,
	_In_ SIZE_T Size
)
{

	PCHAR D = (PCHAR)Destination;
	PCHAR S = (PCHAR)Source;

	for (SIZE_T i = 0; i < Size; i++)
		D[i] = S[i];

}

SIZE_T STRLEN
(
	_In_ LPCSTR String
)
{

	LPCSTR String2 = NULL;

	for (String2 = String; *String2; ++String2);
	return(String2 - String);

}

SIZE_T WCSLEN
(
	_In_ LPCWSTR String
)
{

	LPCWSTR String2 = NULL;

	for (String2 = String; *String2; ++String2);
	return(String2 - String);

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

DWORD djb2W(const PWSTR str, SIZE_T length)
{
	DWORD	hash = HASH_SEED;
	PUCHAR	Ptr = (PUCHAR)str;

	do
	{
		UCHAR Char = *Ptr;

		if (!length)
		{
			if (!*Ptr)
				break;
		}
		else
		{
			if ((ULONG)(Ptr - (PUCHAR)str) >= length)
				break;

			if (!*Ptr)
				Ptr++;
		}

		if (Char >= 'a')
			Char -= 0x20;

		hash = ((hash << 5) + hash) + Char;
		++Ptr;

	} while (TRUE);

	return hash;
}

DWORD djb2A(const PWSTR str)
{
	DWORD	hash = 5381;
	PUCHAR	Ptr = (PUCHAR)str;

	do
	{

		UCHAR Char = *Ptr;

		if (!*Ptr) break;

		if (!*Ptr)
			Ptr++;

		if (Char >= 'a')
			Char -= 0x20;

		hash = ((hash << 5) + hash) + Char;
		++Ptr;

	} while (TRUE);

	return hash;
}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

PVOID LoadDllModule
(
	_In_ BYTE ModuleId
)
{

	//------------------------------------------------------

	WCHAR AmsiDllStr[]					= { 'A', 'm', 's', 'i', '.', 'd', 'l', 'l', '\0' };
	WCHAR Rpcrt4DllStr[]				= { 'R', 'p', 'c', 'r', 't', '4', '.', 'd', 'l', 'l', '\0' };
	WCHAR CryptspDllStr[]				= { 'C', 'r', 'y', 'p', 't', 's', 'p', '.', 'd', 'l', 'l', '\0' };

	PPEB					pPeb		= (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA			pLdr		= (PPEB_LDR_DATA)pPeb->Ldr;
	PLIST_ENTRY				Head		= &pLdr->InLoadOrderModuleList;
	PLIST_ENTRY				pList		= Head->Flink;
	PLDR_DATA_TABLE_ENTRY	pDataLdr	= NULL;

	DWORD					ModuleHash	= 0;

	//------------------------------------------------------

	switch (ModuleId)
	{

	case KERNEL32_DLL:
		ModuleHash = kernel32_dll_HASH;
		break;
	case NTDLL_DLL:
		ModuleHash = ntdll_dll_HASH;
		break;
	case AMSI_DLL:
		return (PVOID)pLoadLibraryW(AmsiDllStr);
	case RPCRT4_DLL:
		return (PVOID)pLoadLibraryW(Rpcrt4DllStr);
	case CRYPTSP_DLL:
		return (PVOID)pLoadLibraryW(CryptspDllStr);
	default: 
		return NULL;

	}

	//------------------------------------------------------

	for (; pList != Head; pList = pList->Flink)
	{

		pDataLdr = (PLDR_DATA_TABLE_ENTRY)pList;

		if (djb2W(pDataLdr->BaseDllName.Buffer, pDataLdr->BaseDllName.Length) == ModuleHash)
			return pDataLdr->DllBase;

	}

	//------------------------------------------------------

	return NULL;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

PVOID ResolveHashedFunction
(
	_In_ BYTE ModuleId,
	_In_ DWORD ApiHash
)
{

	//------------------------------------------------------

	PIMAGE_NT_HEADERS64		pImageNtHeader			= NULL;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory	= NULL;
	SIZE_T					ExportDirectorySize		= 0;
	PDWORD					AddressOfFunctions		= NULL;
	PDWORD					AddressOfNames			= NULL;
	PWORD					AddressOfNamesOrdinals	= NULL;

	PWCHAR					FunctionName			= NULL;
	PVOID					FunctionAddress			= NULL;
	PVOID					DllModuleBase			= NULL;
	CHAR					ForwarderName[MAX_PATH] = { 0 };
	DWORD					DotOffset				= 0;
	PCHAR					FunctionMod				= NULL;
	PCHAR					ApiName					= NULL;

	//------------------------------------------------------

	if ((DllModuleBase = LoadDllModule(ModuleId)) == NULL)
	{
#ifdef DEBUG
		PRINT_ERROR("LoadDllModule");
#endif
		return NULL;
	}

	//------------------------------------------------------

	pImageNtHeader			= (PIMAGE_NT_HEADERS64)(U_PTR(DllModuleBase) + ((PIMAGE_DOS_HEADER)DllModuleBase)->e_lfanew);
	pImageExportDirectory	= (PIMAGE_EXPORT_DIRECTORY)(U_PTR(DllModuleBase) + pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	ExportDirectorySize		= pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	AddressOfNames			= C_PTR(U_PTR(DllModuleBase) + pImageExportDirectory->AddressOfNames);
	AddressOfFunctions		= C_PTR(U_PTR(DllModuleBase) + pImageExportDirectory->AddressOfFunctions);
	AddressOfNamesOrdinals	= C_PTR(U_PTR(DllModuleBase) + pImageExportDirectory->AddressOfNameOrdinals);

	//------------------------------------------------------

	for (DWORD i = 0; i < pImageExportDirectory->NumberOfNames; i++)
	{

		FunctionName = (PWCHAR)(U_PTR(DllModuleBase) + AddressOfNames[i]);

		if (djb2A(FunctionName) == ApiHash)
		{

			FunctionAddress = C_PTR(U_PTR(DllModuleBase) + AddressOfFunctions[AddressOfNamesOrdinals[i]]);

			if (U_PTR(FunctionAddress) >= U_PTR(pImageExportDirectory) && U_PTR(FunctionAddress) < U_PTR(pImageExportDirectory + ExportDirectorySize))
			{

				//------------------------------------------------------

				__movsb(ForwarderName, FunctionAddress, STRLEN((LPCSTR)FunctionAddress));

				for (SIZE_T i = 0; i < STRLEN((LPCSTR)ForwarderName); i++)
				{

					if (((PCHAR)ForwarderName)[i] == '.')
					{
						DotOffset = i;
						ForwarderName[i] = 0;
						break;
					}

				}

				//------------------------------------------------------

				FunctionMod  = ForwarderName;
				FunctionName = (PWCHAR)ForwarderName + DotOffset + 1;

				if (pLoadLibraryW)
					return ResolveHashedFunction((BYTE)pLoadLibraryW((LPCWSTR)FunctionMod), djb2A((PWSTR)FunctionName));

				//------------------------------------------------------

			}

			return FunctionAddress;

		}

	}

	//------------------------------------------------------

	return NULL;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=