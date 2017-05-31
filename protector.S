.section .text

.globl protector
.globl fchecksum
.globl e_entry
.globl error_msg
.globl file_buf
.globl checksum_int
.globl checksum_pos1
.globl checksum_pos2


protector:
	pusha    
	#otvaramo fajl 
	
    movl 36(%esp), %ebx
	movl $5, %eax
	movl $0, %ecx

	int $0x80
	
	movl %eax, %ebx
	movl $0, %edi
	#citamo fajl u buffer
	.loop:	
    
    movl $0, (file_buf)
	movl $3, %eax
	movl $file_buf, %ecx
	movl $4, %edx
	int $0x80
    
    cmpl (checksum_pos1), %edi
    je .next
    cmpl (checksum_pos2), %edi
    je .next
    
	cmpl $0, %eax
	jle .done

	movl (checksum_int), %eax  	
	xorl (file_buf), %eax
	movl %eax, (checksum_int)
	
	.next:
	incl %edi
	jmp .loop
	.done:

	movl (checksum_int), %eax
	cmpl (fchecksum), %eax
	je execute
    
	movl $4, %eax
	movl $1, %ebx
	movl $error_msg, %ecx
	movl $20, %edx
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
	
error_msg:		.ascii  "Executable infected\n"
fchecksum:		.long 0x04
checksum_int:	.long 0
checksum_pos1:	.long 0
checksum_pos2:	.long 0
file_buf:		.long 0

e_entry:
	jmp 0xffffffff
