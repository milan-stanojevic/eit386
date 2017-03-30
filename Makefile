CC=gcc
CFLAGS= -m32 -I.
DEPS = common.h inject.h elf_protect.h
OBJ = main.o inject.o elf_protect.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

elftool: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)


