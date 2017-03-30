#ifndef ELF_PROTECT_H
#define ELF_PROTECT_H

unsigned char calcCheckSum(unsigned char *buf, unsigned int size, int chk_pos);
unsigned int injectElf32Protector(void *buf, unsigned int fsize, char* fname);

#endif
