#Milan Stanojevic RA202/2016
#ELF injection

.section .text


.globl main
main:
	pusha
	#otvaramo fajl 
	movl $fname, %ebx
	movl $5, %eax
	movl $0, %ecx

	int $0x80
	
	movl %eax, (fd)
	movl $0, %edi
	#citamo fajl u buffer
	.loop:	
	movl (fd), %ebx
	movl $3, %eax
	movl $byte, %ecx
	movl $1, %edx
	int $0x80
	cmpl (checksum_pos), %edi
	je .next	
	cmpl $0, %eax
	jle .done
	

	movb (checksum), %al  	
	xorb (byte), %al
	movb %al, (checksum)
	
	.next:
	incl %edi
	jmp .loop
	.done:

	movb (checksum), %al
	cmpb (fchecksum), %al
	je execute
	movl $4, %eax
	movl $1, %ebx
	movl $error_msg, %ecx
	movl $21, %edx
	int $0x80	
	#kraj
	jmp end

	execute:
	popa
	jmp e_entry
end:
	popa
	movl $1, %eax
	movl $0, %ebx
	int $0x80
error_msg:
        	.ascii  "Executable infected\n"
	fname:
       .ascii  "TEMPLATE_FNAME" 
               .byte 0
	fchecksum: .byte 0x04
	checksum: .byte 0
    checksum_pos: .long 123456
	byte: .byte 0
	fd: .long 0
e_entry:
	jmp 0xffffffff
