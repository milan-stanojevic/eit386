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
