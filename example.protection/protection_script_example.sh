#!/bin/sh

gcc -m32 -o input_executable input_executable.c
eit386 -p input_executable output_executable
