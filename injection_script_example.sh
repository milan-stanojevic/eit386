#!/bin/sh

gcc -m32 -o input_executable input_executable.c
gcc -m32 -c example.S
./eit386 -i example.o input_executable output_executable