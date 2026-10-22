#include "Common.h"

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

BOOLEAN FetchTextSection
(
	_In_	PVOID	DllModule,
	_Out_	PBYTE*  TextSection,
	_Out_	PBYTE*  TextSectionRVA,
	_Out_	DWORD*  TextSectionSize
)
{

	//------------------------------------------------------

	BOOLEAN					Found				= FALSE;

	PIMAGE_NT_HEADERS64		pImageNtHeader		= NULL;
	PIMAGE_SECTION_HEADER	pImageSectionHeader = NULL;

	PBYTE					ModuleTextSection	= 0;

	//------------------------------------------------------

	pImageNtHeader = (PIMAGE_NT_HEADERS64)(U_PTR(DllModule) + ((PIMAGE_DOS_HEADER)DllModule)->e_lfanew);
	if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
#ifdef DEBUG
		WARN("Nt Signature Does Not Match!");
#endif
		return FALSE;
	}

	pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeader);

	//------------------------------------------------------

	for (DWORD i = 0; i < pImageNtHeader->FileHeader.NumberOfSections; i++)
	{

		if (strcmp(pImageSectionHeader[i].Name, ".text") == 0)
		{

			ModuleTextSection	= (PBYTE)U_PTR(DllModule) + pImageSectionHeader[i].VirtualAddress;
			*TextSection		= ModuleTextSection;
			*TextSectionRVA		= (PBYTE)pImageSectionHeader[i].VirtualAddress;
			*TextSectionSize	= pImageSectionHeader[i].SizeOfRawData;

			Found = TRUE;
			break;

		}

	}

	//------------------------------------------------------

	if (!Found)
		return FALSE;

	return ((ModuleTextSection != NULL)) ? TRUE : FALSE;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

PVOID FetchRXLocation
(
	_In_	PVOID		DllModule,
	_In_	SIZE_T		PayloadSize,
	_Out_	SIZE_T*		SectionSize
)
{

	//------------------------------------------------------

	PIMAGE_NT_HEADERS64		pImageNtHeader		= NULL;
	PIMAGE_SECTION_HEADER	pImageSectionHeader = NULL;

	//------------------------------------------------------

	pImageNtHeader = (PIMAGE_NT_HEADERS64)(U_PTR(DllModule) + ((PIMAGE_DOS_HEADER)DllModule)->e_lfanew);
	if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
#ifdef DEBUG
		WARN("Nt Signature is not valid!");
#endif
		return NULL;
	}

	pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeader);

	//------------------------------------------------------

	for (DWORD i = 0; i < pImageNtHeader->FileHeader.NumberOfSections; i++, pImageSectionHeader++)
	{
		if ((pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) && (pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE))
		{

			if (pImageSectionHeader->Misc.VirtualSize >= PayloadSize)
			{
				*SectionSize = pImageSectionHeader->Misc.VirtualSize;
				return C_PTR(U_PTR(DllModule) + pImageSectionHeader->VirtualAddress);
			}

		}
	}

	//------------------------------------------------------

#ifdef DEBUG
	WARN("Could Not Fetch RX Location!");
#endif
	return NULL;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

// reference: Cave-Finder adamhlt

BOOLEAN FindCodeCave
(
	_In_	PVOID	DllModule,
	_In_	SIZE_T	PayloadSize,
	_Out_	PBYTE*  CodeCaveAddress
)
{

	//------------------------------------------------------

	BOOLEAN		CaveFound		= FALSE;

	PBYTE		TextSectionBase = 0;
	PBYTE		TextSectionRva	= 0;
	DWORD		TextSectionSize = 0;
	DWORD_PTR	Offset			= 0;

	//------------------------------------------------------

	if (!FetchTextSection(DllModule, &TextSectionBase, &TextSectionRva, &TextSectionSize))
	{
#ifdef DEBUG
		PRINT_ERROR("FetchTextSection");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	for (DWORD i = 0; i < TextSectionSize; i++)
	{

		if (TextSectionBase[i] == CODE_CAVE_PATTERN)
		{

			Offset = 0;

			while (TextSectionBase[Offset + i] == 0)
			{

				if ((i + Offset) >= TextSectionSize)
					break;

				Offset++;
			}

			if (Offset >= PayloadSize)
			{

				*CodeCaveAddress = TextSectionBase + i;

				CaveFound = TRUE;

			}

			i += (int)Offset;

		}

	}

	//------------------------------------------------------

	return CaveFound;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=