#include "Common.h"

#ifdef DEBUG

VOID DBG_CONSOLE(void)
{

	BOOLEAN Created = FALSE;

	if (Created)
		return;

	if (!GetConsoleWindow() && AllocConsole())
		Created = TRUE;

}

#endif // DEBUG