// used to fill IAT with random APIs
// reference: https://github.com/Maldev-Academy/MaldevAcademyLdr.1/blob/main/Loader/IatCamo.h

#include <Windows.h>
#include "ApiConstants.h"

DWORD Seed(void)
{

	return '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;

}

BOOLEAN RandomBuffer
(
	_Out_ PVOID* Buffer
)
{

	PVOID RandBuf = NULL;

	if ((RandBuf = HeapAlloc(pGetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF)) == NULL)
		return FALSE;

	*(ULONG*)RandBuf = Seed() % 0xFF;

	*Buffer = RandBuf;

	return ((*Buffer != NULL)) ? TRUE : FALSE;

}

VOID BenignFuncs(void)
{

	PVOID Buffer = NULL;
	ULONG_PTR x = 0;

	// add some random functions here

	x = (ULONG_PTR)RandomBuffer(&Buffer);

	if (*x > 350)
	{

		unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
		i = GetLastError();
		i = SetCriticalSectionSpinCount(NULL, NULL);
		i = GetWindowContextHelpId(NULL);
		i = GetWindowLongPtrW(NULL, NULL);
		i = RegisterClassW(NULL);
		i = IsWindowVisible(NULL);
		i = ConvertDefaultLocale(NULL);
		i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
		i = IsDialogMessageW(NULL, NULL);

	}

	pHeapFree(pGetProcessHeap(), 0, Buffer);

}