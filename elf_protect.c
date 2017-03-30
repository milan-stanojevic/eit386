#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <inject.h>
#include <elf_protect.h>
#include <common.h>

unsigned int injection_code_size = 166;

unsigned char injection_code[] = {
0x60,
0xbb, 0xFF, 0xFF, 0xFF, 0xFF, /* fname addr */
0xb8, 0x05, 0x00, 0x00, 0x00,
0xb9, 0x00, 0x00, 0x00, 0x00,
0xcd, 0x80,
0xa3, 0xFF, 0xFF, 0xFF, 0xFF, /* fd addr  */
0xbf, 0x00, 0x00, 0x00, 0x00,
    
0x8b, 0x1d, 0xFF, 0xFF, 0xFF, 0xFF,  /* fd addr */
0xb8, 0x03, 0x00, 0x00, 0x00,
0xb9, 0xFF, 0xFF, 0xFF, 0xFF, /* byte addr */
0xba, 0x01, 0x00, 0x00, 0x00,
0xcd, 0x80,
0x81, 0xff, 0x00, 0x00, 0x00, 0x00,
0x74, 0x15,
    
0x83, 0xf8, 0x00,
0x7e, 0x13,  /* check sum calc done  */

0xa0, 0xFF, 0xFF, 0xFF, 0xFF,  /* checksum addr */
0x32, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, /* byte addr */
0xa2, 0xFF, 0xFF, 0xFF, 0xFF, /* checksum addr */
0x47,    
0xeb, 0xc9, /* jmp .loop */

0xa0, 0xFF, 0xFF, 0xFF, 0xFF, /* checksum addr */
0x3c, 0x00, /* file checksum */
0x74, 0x18, /* jmp to popa then jump to e_entry  */
0xb8, 0x04, 0x00, 0x00, 0x00,
0xbb, 0x01, 0x00, 0x00, 0x00,
0xb9, 0xFF, 0xFF, 0xFF, 0xFF, /* error msg addr */
0xba, 0x15, 0x00, 0x00, 0x00, /* msg len */
0xcd, 0x80,
0xeb, 0x06,
0x61,
0xe9, 0xFF, 0xFF, 0xFF, 0xFF, /* jmp e_entry */

0xb8, 0x01, 0x00, 0x00, 0x00,
0xbb, 0x00, 0x00, 0x00, 0x00,
0xcd ,0x80,
0x90, 0x90, 0x90, 0x90, 0x90,
0x00, 0x00, 0x00, 0x00, /* fd */
0x00, /* checksum */
0x00, /* byte */
0x45, 0x78, 0x65, 0x63, 0x75, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x69, 0x6e, 0x66, 0x65, 0x63, 0x74, 0x65, 0x64, 0x0a, 0x00 /* error msg */
/* fname */
};


unsigned char calcCheckSum(unsigned char *buf, unsigned int size, int chk_pos)
{
    unsigned char checksum = 0;
    int i;
    for(i=0;i<size;i++){
        if (i == chk_pos)
            continue;
        checksum ^= buf[i];
    }
    return checksum;
}

unsigned int injectElf32Protector(void *buf, unsigned int fsize, char* fname)
{
    void *tbuf;
	int i,pidx,shidx;
    
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)buf;
	
	if (checkELF(ehdr) == 0)
        error("Not an ELF file - it has the wrong magic bytes at the start");
	
	Elf32_Phdr *phdr = (Elf32_Phdr*)(buf+ehdr->e_phoff);
	Elf32_Shdr *shdr = (Elf32_Shdr*)(buf+ehdr->e_shoff);
	pidx = findPhdrForInjection(ehdr,phdr,injection_code_size+strlen(fname)+1);
	if (pidx == -1)
	   error("PT_LOAD segment doesn't have enough space for injection");

    
    
    shidx = findShdr(ehdr,shdr,phdr[pidx].p_offset,phdr[pidx].p_filesz);
	for(i=pidx+1;i<ehdr->e_phnum;i++)
		phdr[i].p_offset+=phdr[pidx].p_align;
	
	for(i=shidx+1;i<ehdr->e_shnum;i++)
		shdr[i].sh_offset+=phdr[pidx].p_align;

    shdr[shidx].sh_size+=(injection_code_size+strlen(fname)+1);

    tbuf = malloc(fsize+injection_code_size+strlen(fname)+1+0x2000);
    
	memcpy(tbuf,buf+phdr[pidx].p_offset+phdr[pidx].p_filesz, fsize-phdr[pidx].p_offset+phdr[pidx].p_filesz);
	memcpy(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+phdr[pidx].p_align,tbuf,fsize-phdr[pidx].p_offset+phdr[pidx].p_filesz);
	fsize+=phdr[pidx].p_align;

    
    memcpy(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz, injection_code, injection_code_size);
	memcpy(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+injection_code_size, fname, strlen(fname)+1); // fname 
	
	unsigned int jmp_rel_addr = ehdr->e_entry - (phdr[pidx].p_vaddr+phdr[pidx].p_filesz+122);
	*(Elf32_Word*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+118) = jmp_rel_addr;



	*(Elf32_Word*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+2) = (phdr[pidx].p_vaddr+phdr[pidx].p_filesz+injection_code_size); // fname addr
	
    *(Elf32_Word*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+19) = (phdr[pidx].p_vaddr+phdr[pidx].p_filesz+139); // fd addr
    
    *(Elf32_Word*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+30) = (phdr[pidx].p_vaddr+phdr[pidx].p_filesz+139); // fd addr
    
    *(Elf32_Word*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+40) = (phdr[pidx].p_vaddr+phdr[pidx].p_filesz+144); // byte addr
    
    *(Elf32_Word*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+65) = (phdr[pidx].p_vaddr+phdr[pidx].p_filesz+143); // checksum addr
    
    *(Elf32_Word*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+71) = (phdr[pidx].p_vaddr+phdr[pidx].p_filesz+144); // byte addr
    
    *(Elf32_Word*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+76) = (phdr[pidx].p_vaddr+phdr[pidx].p_filesz+143); // checksum addr
    
    *(Elf32_Word*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+84) = (phdr[pidx].p_vaddr+phdr[pidx].p_filesz+143); // checksum addr
    
    *(Elf32_Word*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+103) = (phdr[pidx].p_vaddr+phdr[pidx].p_filesz+145); // error msg addr
    
    
    *(Elf32_Word*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+53) = (phdr[pidx].p_offset+phdr[pidx].p_filesz+89); // checksum pos
    
	ehdr->e_entry = phdr[pidx].p_vaddr+phdr[pidx].p_filesz;
	ehdr->e_shoff+=phdr[pidx].p_align;
	phdr[pidx].p_filesz+=(injection_code_size+strlen(fname)+1);
	phdr[pidx].p_memsz=phdr[pidx].p_filesz;
	phdr[pidx].p_flags = (PF_X | PF_W | PF_R);
    
    
    unsigned char checksum = calcCheckSum(buf,fsize,phdr[pidx].p_offset+phdr[pidx].p_filesz-(injection_code_size+strlen(fname)+1)+89);
    *(unsigned char*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz-(injection_code_size+strlen(fname)+1)+89) =  (checksum); // checksum
    
    return fsize;
}
