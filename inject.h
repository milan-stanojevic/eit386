#ifndef INJECT_H
#define INJECT_H

int checkELF(Elf32_Ehdr *ehdr);
int checkPhdrOverlap(Elf32_Ehdr *ehdr, Elf32_Phdr *phdr, unsigned int pos, unsigned int sz);
int findPhdrForInjection(Elf32_Ehdr *ehdr, Elf32_Phdr *phdr, unsigned int target_sz);
int findShdr(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr, Elf32_Off p_offset, Elf32_Word p_filesz);
void* getElf32RelObjectCode(void *buf, unsigned int fsize, unsigned int *code_size, Elf32_Addr e_entry, Elf32_Addr *e_entry_sym);
int getElf32RelObjectCodeSize(void *buf, unsigned int fsize);
unsigned int injectElf32Object(void *buf, unsigned int fsize, void *object_buf, unsigned int object_fsize);
unsigned int injectElf32ProtectionObject(void *buf, unsigned int fsize, void *object_buf, unsigned int object_fsize);

#endif