prefix=/usr/local
CC=gcc
CFLAGS= -m32 -I.
ASFLAGS= -m32
DEPS = common.h inject.h
OBJ = main.o inject.o protector.o

%.o: %.c $(DEPS)
	$(CC)  -c -o $@ $< $(CFLAGS)
    
%.o: %.S
	$(CC)  -c -o $@ $< $(ASFLAGS)

eit386: $(OBJ)
	gcc  -o $@ $^ $(CFLAGS)

install: eit386
	install -m 0755 eit386 $(prefix)/bin
    
.PHONY: install
