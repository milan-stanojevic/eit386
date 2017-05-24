CC=gcc
CFLAGS= -m32 -I.
DEPS = common.h inject.h
OBJ = main.o inject.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

eit386: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)


