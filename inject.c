#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <inject.h>
#include <common.h>

int checkELF(Elf32_Ehdr *ehdr)
{
	if (ehdr->e_ident[0] == 0x7F && ehdr->e_ident[1] == 'E' && ehdr->e_ident[2] == 'L' && ehdr->e_ident[3] == 'F')
		return 1;
	else
		return 0;
}

int checkPhdrOverlap(Elf32_Ehdr *ehdr, Elf32_Phdr *phdr, unsigned int pos, unsigned int sz)
{
	int i;
	for(i=0;i<ehdr->e_phnum;i++)
	{
		if ((phdr[i].p_offset >= pos && phdr[i].p_offset < (pos+sz) && phdr[i].p_filesz > 0))
			return 1;
	}
	
	return 0;
}

int findPhdrForInjection(Elf32_Ehdr *ehdr, Elf32_Phdr *phdr, unsigned int target_sz)
{
	int i;
	for(i=0;i<ehdr->e_phnum;i++)
	{
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_filesz == phdr[i].p_memsz && phdr[i].p_filesz > 0)
		{
			if (checkPhdrOverlap(ehdr,phdr,phdr[i].p_offset+phdr[i].p_filesz,target_sz) == 0)
				return i;
		}
		
	}
	
	return -1;
}

int findShdr(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr, Elf32_Off p_offset, Elf32_Word p_filesz)
{
	int i;
	int idx = 0;
	for(i=0;i<ehdr->e_shnum;i++)
	{
		if (shdr[i].sh_offset >= p_offset+p_filesz)
			return idx;
		
		idx = i;
	}
	return idx;
}




Elf32_Addr getElf32SymbolAddr(void *buf, char *symbol)
{
    int i,symidx,strtabidx = -1;
    
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)buf;
	    //printf("e_shoff: %x\ne_shentsize: %x\ne_shstrndx: %d\n",ehdr->e_shoff,ehdr->e_shentsize,ehdr->e_shstrndx);

	if (checkELF(ehdr) == 0)
        error("Not an ELF file - it has the wrong magic bytes at the start");
	
	Elf32_Shdr *shdr = (Elf32_Shdr*)(buf+ehdr->e_shoff);
    
    void *shstr_section = (void*)(buf+ shdr[ehdr->e_shstrndx].sh_offset);
    
    for(i=0;i<ehdr->e_shnum;i++)
    {
        if (shdr[i].sh_type == SHT_SYMTAB)
        {
            char *sh_name = (char*)(shstr_section+shdr[i].sh_name);
            if (strcmp(sh_name, ".symtab") == 0)
                symidx = i;
            
        }else if (shdr[i].sh_type == SHT_STRTAB)
        {
            char *sh_name = (char*)(shstr_section+shdr[i].sh_name);
            if (strcmp(sh_name, ".strtab") == 0)
                strtabidx = i;
            
        }
    }
        
    if (symidx == -1)
        return -1;

    Elf32_Sym *sym = (Elf32_Sym*)(buf+shdr[symidx].sh_offset);
    void *strtab_section = (void*)(buf+ shdr[strtabidx].sh_offset);
    for(i=0;i<shdr[symidx].sh_size/sizeof(Elf32_Sym);i++)
    {
        char *sym_name = (char*)(strtab_section+sym[i].st_name);
        if (strcmp(sym_name,symbol) == 0)
            return sym[i].st_value;
    }
    
    return -1;
}

int getElf32RelObjectCodeSize(void *buf, unsigned int fsize)
{
	int i;
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)buf;

	if (checkELF(ehdr) == 0)
        error("Not an ELF file - it has the wrong magic bytes at the start");
	
	Elf32_Shdr *shdr = (Elf32_Shdr*)(buf+ehdr->e_shoff);
    
    void *shstr_section = (void*)(buf+ shdr[ehdr->e_shstrndx].sh_offset);
    
    for(i=0;i<ehdr->e_shnum;i++)
    {
        if (shdr[i].sh_type == SHT_PROGBITS)
        {
            char *sh_name = (char*)(shstr_section+shdr[i].sh_name);
            if (strcmp(sh_name,".text") == 0)
                return shdr[i].sh_size;
        }
    }
    
	return -1;    
	
}


void* getElf32RelObjectCode(void *buf, unsigned int fsize, unsigned int *code_size, Elf32_Addr e_entry, Elf32_Addr *e_entry_sym)
{
	int i,ridx = -1;
    int tidx = -1;
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)buf;

	if (checkELF(ehdr) == 0)
        error("Not an ELF file - it has the wrong magic bytes at the start");
	
	Elf32_Shdr *shdr = (Elf32_Shdr*)(buf+ehdr->e_shoff);
    
    void *shstr_section = (void*)(buf+ shdr[ehdr->e_shstrndx].sh_offset);
    
    for(i=0;i<ehdr->e_shnum;i++)
    {
        if (shdr[i].sh_type == SHT_REL)
        {
            char *sh_name = (char*)(shstr_section+shdr[i].sh_name);
            if (strcmp(sh_name,".rel.text") == 0)
                ridx = i;
        }else if (shdr[i].sh_type == SHT_PROGBITS)
        {
            char *sh_name = (char*)(shstr_section+shdr[i].sh_name);
            if (strcmp(sh_name,".text") == 0)
                tidx = i;
        }
    }
    
    if (ridx == -1 || tidx == -1)
        return NULL;
    
    *(code_size) = shdr[tidx].sh_size;
    
    printf("[%d] .text section starting at: 0x%x\n\n", tidx, shdr[tidx].sh_offset);
        
    Elf32_Rel *rel = (Elf32_Rel*)(buf+shdr[ridx].sh_offset);
    for(i=0;i<shdr[ridx].sh_size/sizeof(Elf32_Rel);i++)
    {
        //printf("0x%x  %d\n",rel[i].r_offset,ELF32_R_TYPE(rel[i].r_info));
        if (ELF32_R_TYPE(rel[i].r_info) == R_386_32)
        {
            printf("[%d] R_386_32 relocation at: 0x%x\n", i, rel[i].r_offset);
            *(Elf32_Word*)(buf+shdr[tidx].sh_offset+rel[i].r_offset) += e_entry;
        }
    }
    
    if (getElf32SymbolAddr(buf,"e_entry") == -1)
        printf("Warning: e_entry symbol not found in object file!\n");
    else
        printf("\n[e_entry] symbol at: 0x%x\n",getElf32SymbolAddr(buf,"e_entry"));
    
    *(unsigned char*)(buf+shdr[tidx].sh_offset+getElf32SymbolAddr(buf,"e_entry")) = 0xe9; // jmp opcode
        
    *(e_entry_sym) = getElf32SymbolAddr(buf,"e_entry");
    void *code_buf = malloc(shdr[tidx].sh_size);
    memcpy(code_buf, buf+shdr[tidx].sh_offset, shdr[tidx].sh_size);
    return code_buf;
}


unsigned int injectElf32Object(void *buf, unsigned int fsize, void *object_buf, unsigned int object_fsize)
{
    void *tbuf;
	int i,pidx,shidx;
    
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)buf;
	
	if (checkELF(ehdr) == 0)
        error("Not an ELF file - it has the wrong magic bytes at the start");
	
	Elf32_Phdr *phdr = (Elf32_Phdr*)(buf+ehdr->e_phoff);
	Elf32_Shdr *shdr = (Elf32_Shdr*)(buf+ehdr->e_shoff);

	
	unsigned int injection_object_size;
    Elf32_Addr e_entry_sym = 0;

	injection_object_size = getElf32RelObjectCodeSize(object_buf, object_fsize);

	
	
	pidx = findPhdrForInjection(ehdr,phdr,injection_object_size);
	if (pidx == -1)
	   error("PT_LOAD segment doesn't have enough space for injection");


    void* code = getElf32RelObjectCode(object_buf, object_fsize, &injection_object_size, phdr[pidx].p_vaddr+phdr[pidx].p_filesz, &e_entry_sym);

    
    shidx = findShdr(ehdr,shdr,phdr[pidx].p_offset,phdr[pidx].p_filesz);
	for(i=pidx+1;i<ehdr->e_phnum;i++)
		phdr[i].p_offset+=phdr[pidx].p_align;
	
	for(i=shidx+1;i<ehdr->e_shnum;i++)
		shdr[i].sh_offset+=phdr[pidx].p_align;

    shdr[shidx].sh_size+=(injection_object_size);

    tbuf = malloc(fsize+injection_object_size+0x2000);
    
	memcpy(tbuf,buf+phdr[pidx].p_offset+phdr[pidx].p_filesz, fsize-phdr[pidx].p_offset+phdr[pidx].p_filesz);
	memcpy(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+phdr[pidx].p_align,tbuf,fsize-phdr[pidx].p_offset+phdr[pidx].p_filesz);
	fsize+=phdr[pidx].p_align;

    
    memcpy(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz, code, injection_object_size);

    unsigned int jmp_rel_addr = ehdr->e_entry - (phdr[pidx].p_vaddr+phdr[pidx].p_filesz+e_entry_sym+5);
    *(Elf32_Word*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+e_entry_sym+1) = jmp_rel_addr;  
    
    
	ehdr->e_entry = phdr[pidx].p_vaddr+phdr[pidx].p_filesz;
	ehdr->e_shoff+=phdr[pidx].p_align;
	phdr[pidx].p_filesz+=injection_object_size;
	phdr[pidx].p_memsz=phdr[pidx].p_filesz;
	phdr[pidx].p_flags = (PF_X | PF_W | PF_R);
    
    return fsize;
}






void* getElf32RelProtectionObjectCode(void *buf, unsigned int fsize, unsigned int *code_size, Elf32_Addr e_entry, Elf32_Addr *e_entry_sym, Elf32_Addr *fchecksum, Elf32_Addr *checksum_pos)
{
	int i,ridx = -1;
    int tidx = -1;
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)buf;

	if (checkELF(ehdr) == 0)
        error("Not an ELF file - it has the wrong magic bytes at the start");
	
	Elf32_Shdr *shdr = (Elf32_Shdr*)(buf+ehdr->e_shoff);
    
    void *shstr_section = (void*)(buf+ shdr[ehdr->e_shstrndx].sh_offset);
    
    for(i=0;i<ehdr->e_shnum;i++)
    {
        if (shdr[i].sh_type == SHT_REL)
        {
            char *sh_name = (char*)(shstr_section+shdr[i].sh_name);
            if (strcmp(sh_name,".rel.text") == 0)
                ridx = i;
        }else if (shdr[i].sh_type == SHT_PROGBITS)
        {
            char *sh_name = (char*)(shstr_section+shdr[i].sh_name);
            if (strcmp(sh_name,".text") == 0)
                tidx = i;
        }
    }
    
    if (ridx == -1 || tidx == -1)
        return NULL;
    
    *(code_size) = shdr[tidx].sh_size;
    
    printf("[%d] .text section starting at: 0x%x\n\n", tidx, shdr[tidx].sh_offset);
        
    Elf32_Rel *rel = (Elf32_Rel*)(buf+shdr[ridx].sh_offset);
    for(i=0;i<shdr[ridx].sh_size/sizeof(Elf32_Rel);i++)
    {
        //printf("0x%x  %d\n",rel[i].r_offset,ELF32_R_TYPE(rel[i].r_info));
        if (ELF32_R_TYPE(rel[i].r_info) == R_386_32)
        {
            printf("[%d] R_386_32 relocation at: 0x%x\n", i, rel[i].r_offset);
            *(Elf32_Word*)(buf+shdr[tidx].sh_offset+rel[i].r_offset) += e_entry;
        }
    }
    
    if (getElf32SymbolAddr(buf,"e_entry") == -1)
        printf("Warning: e_entry symbol not found in object file!\n");
    else
        printf("\n[e_entry] symbol at: 0x%x\n",getElf32SymbolAddr(buf,"e_entry"));
    
    *(unsigned char*)(buf+shdr[tidx].sh_offset+getElf32SymbolAddr(buf,"e_entry")) = 0xe9; // jmp opcode
        
    *(e_entry_sym) = getElf32SymbolAddr(buf,"e_entry");
	*(fchecksum) = getElf32SymbolAddr(buf,"fchecksum");
    *(checksum_pos) = getElf32SymbolAddr(buf,"checksum_pos");

    void *code_buf = malloc(shdr[tidx].sh_size);
    memcpy(code_buf, buf+shdr[tidx].sh_offset, shdr[tidx].sh_size);
    return code_buf;
}

unsigned char calcCheckSum(unsigned char *buf, unsigned int size, int chk_pos)
{
    unsigned char checksum = 0;
    int i;
    for(i=0;i<size;i++){
        if (i == chk_pos)
            {
                printf(":::%x\n",buf[i]);
            continue;
            }
        checksum ^= buf[i];
    }
    return checksum;
}

unsigned int injectElf32ProtectionObject(void *buf, unsigned int fsize, void *object_buf, unsigned int object_fsize)
{
    void *tbuf;
	int i,pidx,shidx;
    
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)buf;
	
	if (checkELF(ehdr) == 0)
        error("Not an ELF file - it has the wrong magic bytes at the start");
	
	Elf32_Phdr *phdr = (Elf32_Phdr*)(buf+ehdr->e_phoff);
	Elf32_Shdr *shdr = (Elf32_Shdr*)(buf+ehdr->e_shoff);

	
	unsigned int injection_object_size;
    Elf32_Addr e_entry_sym = 0;
	Elf32_Addr fchecksum = 0;
	Elf32_Addr checksum_pos = 0;
	
	injection_object_size = getElf32RelObjectCodeSize(object_buf, object_fsize);


	
	pidx = findPhdrForInjection(ehdr,phdr,injection_object_size);
	if (pidx == -1)
	   error("PT_LOAD segment doesn't have enough space for injection");


    void* code = getElf32RelProtectionObjectCode(object_buf, object_fsize, &injection_object_size, phdr[pidx].p_vaddr+phdr[pidx].p_filesz, &e_entry_sym,&fchecksum,&checksum_pos);

	
    printf("%x %x %x\n",e_entry_sym,fchecksum,checksum_pos);
    shidx = findShdr(ehdr,shdr,phdr[pidx].p_offset,phdr[pidx].p_filesz);
	for(i=pidx+1;i<ehdr->e_phnum;i++)
		phdr[i].p_offset+=phdr[pidx].p_align;
	
	for(i=shidx+1;i<ehdr->e_shnum;i++)
		shdr[i].sh_offset+=phdr[pidx].p_align;

    shdr[shidx].sh_size+=(injection_object_size);

    tbuf = malloc(fsize+injection_object_size+0x2000);
    
	memcpy(tbuf,buf+phdr[pidx].p_offset+phdr[pidx].p_filesz, fsize-phdr[pidx].p_offset+phdr[pidx].p_filesz);
	memcpy(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+phdr[pidx].p_align,tbuf,fsize-phdr[pidx].p_offset+phdr[pidx].p_filesz);
	fsize+=phdr[pidx].p_align;

    
    memcpy(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz, code, injection_object_size);


	
    unsigned int jmp_rel_addr = ehdr->e_entry - (phdr[pidx].p_vaddr+phdr[pidx].p_filesz+e_entry_sym+5);
    *(Elf32_Word*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+e_entry_sym+1) = jmp_rel_addr;  

    
	ehdr->e_entry = phdr[pidx].p_vaddr+phdr[pidx].p_filesz;
	ehdr->e_shoff+=phdr[pidx].p_align;
	phdr[pidx].p_filesz+=injection_object_size;
	phdr[pidx].p_memsz=phdr[pidx].p_filesz;
	phdr[pidx].p_flags = (PF_X | PF_W | PF_R);

		printf("checksum_pos1: %x\n", *(unsigned char*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+fchecksum-injection_object_size));

    *(unsigned int*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+checksum_pos-injection_object_size) = (phdr[pidx].p_offset+phdr[pidx].p_filesz+fchecksum-injection_object_size);
	printf("checksum_pos: %x\n", (phdr[pidx].p_offset+phdr[pidx].p_filesz+fchecksum-injection_object_size));

	unsigned char checksum = calcCheckSum(buf,fsize,phdr[pidx].p_offset+phdr[pidx].p_filesz+fchecksum-injection_object_size);
	
    printf("checksum: %x\n",checksum);
	
    *(unsigned char*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+fchecksum-injection_object_size) =  (checksum); // checksum
printf("checksum: %x\n", *(unsigned char*)(buf+phdr[pidx].p_offset+phdr[pidx].p_filesz+fchecksum-injection_object_size));
	
    
    printf("checksum: %x\n", calcCheckSum(buf,fsize,phdr[pidx].p_offset+phdr[pidx].p_filesz+fchecksum-injection_object_size));

    return fsize;
}