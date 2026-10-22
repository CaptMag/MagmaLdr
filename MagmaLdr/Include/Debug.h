#pragma once

#define DEBUG

#ifdef DEBUG

VOID DBG_CONSOLE(void);

#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())
#define NT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%08X""\n", Status)

#endif // DEBUG