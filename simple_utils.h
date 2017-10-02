uint8_t* readFile(const char* file_name, const char* file_format, long* file_len){
    FILE* file_ptr = fopen(file_name, file_format);
    fseek(file_ptr, 0, SEEK_END);
    *file_len = ftell(file_ptr);
    rewind(file_ptr); 
    uint8_t* buffer = (uint8_t*)malloc(*file_len+1);
    fread(buffer, *file_len, 1, file_ptr);
    fclose(file_ptr);
    return buffer;
}


void printBuffer(uint8_t* buf, uint64_t len){
    for(int i = 0; i < len; i++)
        printf("%02x",(uint8_t)buf[i]);
    printf("\n");
}

uint64_t readULLI(uint8_t* p){
    return (p[0]) | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);  
}

uint32_t readUI(uint8_t* p){
    return (p[0]) | (p[1] << 8) | (p[2] << 16);
}

uint16_t readUS(uint8_t* p){
    return (p[0]) | (p[1] << 8); 
}

void writeULLI(uint8_t* p, uint64_t val){
    p[0] = val & 0xff;
    p[1] = (val & 0xff00) >> 8;
    p[2] = (val & 0xff0000) >> 16; 
    p[3] = (val & 0xff000000) >> 24;
}

void writeUI(uint8_t* p, uint32_t val){
    p[0] = val & 0xff;
    p[1] = (val & 0xff00) >> 8;
    p[2] = (val & 0xff0000) >> 16;
}
