#include <stdio.h>
#include <stdint.h>

#define src_path "./src.txt"
#define mem_size 65536

typedef enum {
    OK,
    NG,
} status_t;

typedef enum {
    INST_NULL,
    INST_PUSH,
    INST_ASSIGN,
} inst_t;

typedef struct {
    inst_t inst;
    char* token;
} node_t;

union {
    int32_t i32[mem_size / sizeof(int32_t)];
    struct {
        int32_t bin[mem_size / sizeof(int32_t)];
        char src[mem_size / sizeof(char)];
        node_t node[mem_size / sizeof(node_t)];
    } compile_data;
} mem;

status_t readsrc() {
    FILE* file = fopen(src_path, "r");
    if (file == NULL) {
        perror("Error opening file");
        return NG;
    }
    size_t bytes_read = fread(mem.compile_data.src, sizeof(char), mem_size, file);
    if (bytes_read == 0) {
        perror("Error reading file");
        fclose(file);
        return NG;
    }
    mem.compile_data.src[bytes_read] = '\n';
    mem.compile_data.src[bytes_read + 1] = '\0';
    fclose(file);
}

status_t parse() {
}

int main() {
    if (readsrc() == NG) {
        return 1;
    }
    printf("Data read from file:\n%s", mem.compile_data.src);
    return 0;
}