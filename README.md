# elftool
elftool is tool for injecting code to existing 32-bit ELF executable, 
it have option for injecting checksum protect code and option for
injecting existing 32-bit ELF relocatable object to our ELF.

# 32-bit ELF checksum protect

Given a 32-bit ELF executable file, elftool inserts into it a
snippet of checksum check code. Every time when you run your executable,
checksum check code will be executed and it will check checksum of 
executable if checksum is valid, executable will execute it's own
code, if checksum is bad (someone was changed executable) checksum
code snippet will write message that executable is infected and it will
exit the program.

# How to inject ELF checksum protect

./elftool -p ./input_elf ./out_elf

./input_elf is our executable that we want to protect.
./out_elf is our new executable that contains checksum protect code.

# How it works

elftool checks if there is padding in memory after PT_LOAD segment, if
padding exists it simply injects our code after segment and changes the
e_entry point to our code. For more details check Silvio Cesare algorithm
for injecting code. http://vxheaven.org/lib/vsc02.html

# Injecting 32-bit ELF relocatable object to existing 32-bit ELF executable

elftool have option that inserts existing 32-bit ELF relocatable object
to ELF executale.

.elftool -i ./object ./input_elf ./out_elf

./object is our 32-bit ELF relocatable object
./input_elf is our executable that we want to insert relocatable object to it.
./out_elf is our new executable that contains our object code, and that code
will be executed first.

# Example code for object

All variables need to be in .text section, and also we need to have one
e_entry label that contains jmp 0xffffffff, this instruction will be replaced
with jump to real e_entry of our executable.

```assembly
.section .text
.globl main
main:
	pusha

	movl $4, %eax
	movl $1, %ebx
	movl $msg, %ecx
	movl $12, %edx
	int $0x80	

	popa
	jmp e_entry

msg:
        	.ascii  "Hello world\n"
e_entry:
	jmp 0xffffffff

```

