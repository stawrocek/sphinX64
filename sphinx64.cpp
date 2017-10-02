#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>

#include "simple_utils.h"

struct PayloadInfo{
	uint64_t orig_entry;
	uint64_t p_text_vaddr;
	uint64_t s_text_off;
	uint64_t s_text_size;
};

uint8_t* generatePayload(PayloadInfo* pi, long* payload_len, long key_len){
	printf("$ Generating stub\n");
	printf("orig_entry: 0x%x, p_text_vaddr: 0x%x, s_text_off: 0x%x, s_text_size: 0x%x\n", pi->orig_entry, pi->p_text_vaddr, pi->s_text_off, pi->s_text_size);
	long payload_setup_len=-1;
	uint8_t* payload_setup = readFile("stub.asm", "rb", &payload_setup_len);
	uint8_t payload_asm[payload_setup_len+1];
	sprintf((char*)payload_asm, (char*)payload_setup, pi->p_text_vaddr+pi->s_text_off, pi->s_text_size, pi->orig_entry);
	printf("compiling stub_asm:\n%s\n", payload_asm);
	FILE *out_file_ptr = fopen("stub.tmp", "a");
	fprintf(out_file_ptr, "%s\n", payload_asm);
	fclose(out_file_ptr);
	system("nasm -f bin stub.tmp -o stub.o");
	system("rm stub.tmp");
	uint8_t* payload = readFile("stub.o", "rb", payload_len);
	return payload;
}

uint8_t* paddingInfection(uint8_t* buf, long* file_len,
	uint32_t new_align, uint8_t* key, long key_len,
	PayloadInfo* payload_info){
	printf("### Padding Infection ###\n");	
	printf("$ inserting code\n");
	uint64_t e_entry = readULLI(buf+0x18);
	uint64_t e_phoff = readULLI(buf+0x20);
	uint64_t e_shoff = readULLI(buf+0x28);
	uint16_t e_phentsize = readUS(buf+0x36);
	uint16_t e_phnum = readUS(buf+0x38);
	uint16_t e_shentsize = readUS(buf+0x3a);
	uint16_t e_shnum = readUS(buf+0x3c);
	uint16_t e_shstrndx = readUS(buf+0x3e);
	printf("orig_entry_point: 0x%x\n", e_entry);
	uint64_t orig_p_txt_off, orig_p_txt_filesz, orig_p_txt_memsz, orig_p_txt_vaddr;
	uint64_t orig_s_txt_off, orig_s_txt_size;
	printf("$ #%d segments at offset 0x%x, each of 0x%x size\n", e_phnum, e_phoff, e_phentsize);
	printf("$ #%d sections at offset 0x%x, each of 0x%x size\n", e_shnum, e_shoff, e_shentsize);
	for(int i = 0; i < e_phnum; i++){
		//PT_LOAD==1, flags=5 (1 -> executable)
		if(readUI(buf+e_phoff+i*e_phentsize) == 1){
			if(readUI(buf+e_phoff+i*e_phentsize+0x4) & 1){
				orig_p_txt_off = readULLI(buf+e_phoff+i*e_phentsize+0x8);
				orig_p_txt_vaddr = readULLI(buf+e_phoff+i*e_phentsize+0x10);
				orig_p_txt_filesz = readULLI(buf+e_phoff+i*e_phentsize+0x20);
				orig_p_txt_memsz = readULLI(buf+e_phoff+i*e_phentsize+0x28);
				printf("segment #%d is executable, off: 0x%d, memsz: 0x%x, filesz: 0x%x, vaddr: 0x%x\n", 
						i, orig_p_txt_off, orig_p_txt_memsz, orig_p_txt_filesz, orig_p_txt_vaddr);
				printf("chaging it to be writable\n");
				writeULLI(buf+e_phoff+i*e_phentsize+0x4, 7);
				writeULLI(buf+e_phoff+i*e_phentsize+0x20, orig_p_txt_filesz+new_align);
				writeULLI(buf+e_phoff+i*e_phentsize+0x28, orig_p_txt_memsz+new_align);
				printf("extending phdr_text, new_memsz=0x%x, new_filesz=0x%x\n",
					readULLI(buf+e_phoff+i*e_phentsize+0x28), readULLI(buf+e_phoff+i*e_phentsize+0x20));
			}
		}
	}
	writeULLI(buf+0x18, orig_p_txt_vaddr+orig_p_txt_memsz);
	printf("$ changing entry point from 0x%x to 0x%x\n", e_entry, readULLI(buf+0x18));

	printf("txt_off+filesz=0x%x\n", orig_p_txt_off+orig_p_txt_filesz);

	printf("$ moving segments\n");
	for(int i = 0; i < e_phnum; i++){
		uint64_t ph_off = readULLI(buf+e_phoff+i*e_phentsize+0x8);
		printf("offset #%d, ph_off=0x%x\n", i, ph_off);
		if(ph_off > orig_p_txt_off+orig_p_txt_filesz){
			printf("adding 0x%x to offset of #%d segment\n", new_align, i);
			writeULLI(buf+e_phoff+i*e_phentsize+0x8, ph_off+new_align);
		}
	}

	writeULLI(buf+0x28, e_shoff+new_align);
	printf("$ adding 0x%x to e_shoff, old=0x%x, new=0x%x\n", new_align, e_shoff, readULLI(buf+0x28));

	printf("$ localization of .text section\n");	
	for(int i = 0; i < e_shnum; i++){
		uint32_t sh_name = readUI(buf+e_shoff+i*e_shentsize);
        uint64_t sh_flags = readULLI(buf+e_shoff+i*e_shentsize+0x08);
		uint64_t str_off = readULLI(buf+e_shoff+e_shstrndx*e_shentsize+0x18);
		printf("name of #%d section is %s\n", i, buf+str_off+sh_name);
		if(strcmp((char*)(buf+str_off+sh_name), ".text") == 0){
			orig_s_txt_off = readULLI(buf+e_shoff+i*e_shentsize+0x18);
			orig_s_txt_size = readULLI(buf+e_shoff+i*e_shentsize+0x20);
			writeULLI(buf+e_shoff+i*e_shentsize+0x08, sh_flags|1);
			printf("Changing flags from 0x%x to 0x%x (+w)\n", sh_flags,
					readULLI(buf+e_shoff+i*e_shentsize+0x08));
		}
	}
	printf("s_txt_off=0x%x, s_txt_size=0x%x\n", orig_s_txt_off, orig_s_txt_size);
	payload_info->orig_entry=e_entry;
	payload_info->p_text_vaddr = orig_p_txt_vaddr;
	payload_info->s_text_off = orig_s_txt_off;
	payload_info->s_text_size = orig_s_txt_size;
	printf("$ moving sections\n");
	int last_section_in_p_txt_idx=0;
	for(int i = 0; i < e_shnum; i++){
		uint64_t sh_off = readULLI(buf+e_shoff+i*e_shentsize+0x18);
		printf("offset #%d, sh_off=0x%x\n", i, sh_off);
		if(sh_off > orig_p_txt_off+orig_p_txt_filesz){
			printf("adding 0x%x to offset of #%d section\n", new_align, i);
            writeULLI(buf+e_shoff+i*e_shentsize+0x18, sh_off+new_align);
		}
		else{
			last_section_in_p_txt_idx=i;
		}
	}
	uint64_t last_section_in_p_txt_sh_size = readULLI(buf+e_shoff+last_section_in_p_txt_idx*e_shentsize+0x20);
	writeULLI(buf+e_shoff+last_section_in_p_txt_idx*e_shentsize+0x20, last_section_in_p_txt_sh_size+new_align);
	printf("adding 0x%x to last section in phdr_text, change from 0x%x to 0x%x\n", new_align, last_section_in_p_txt_sh_size, 
		readULLI(buf+e_shoff+last_section_in_p_txt_idx*e_shentsize+0x20));

	printf("$ encrypting .text (from 0x%x) with key=%s (length=%d)\n", orig_s_txt_off, key, key_len);
	for(int i = 0; i < orig_s_txt_size; i++){
		buf[orig_s_txt_off+i] ^= key[i%key_len];
	}
	printf("$ extending buffer by 0x%x bytes\n", new_align);
	uint8_t* new_buffer = (uint8_t*)malloc(*file_len + new_align);
	memset(new_buffer, 0, *file_len+new_align);
	uint64_t p_txt_end = orig_p_txt_off+orig_p_txt_filesz;
	long shell_len=-1;
	uint8_t* shell = generatePayload(payload_info, &shell_len, key_len);
	memcpy(new_buffer, buf, p_txt_end);
    memcpy(new_buffer+p_txt_end, shell, shell_len);
    memcpy(new_buffer+p_txt_end+new_align, buf+p_txt_end, *file_len-p_txt_end);

	*file_len += new_align;
	printf("$ done!\n");
	return new_buffer;
}

int main(int argc, char* argv[]){
	if(argc != 3){
		printf("Usage: ./crypter elf_64 password\n");
		return 0;
	}
	long file_len=-1;
	uint8_t* buffer = readFile(argv[1], "rb", &file_len);
	printf("read %s, len=%d\n", argv[1], file_len);
	printBuffer(buffer, 30);
	PayloadInfo payload_info;
	buffer = paddingInfection(buffer, &file_len, 0x1000, (uint8_t*)argv[2], strlen(argv[2]), &payload_info);
	FILE* file_ptr = fopen(argv[1], "wb");
	fwrite(buffer, 1, file_len, file_ptr);
	fclose(file_ptr);			
	free(buffer);
}
