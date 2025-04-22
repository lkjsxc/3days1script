// mem[0] = 0
// mem[1] = ip
// mem[2] = sp
// mem[3] = bp

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define src_path "./src.txt"
#define MEM_SIZE 65536
#define GLOBALMEM_SIZE 16
#define DEFAULT_STACK_SIZE 128

typedef enum {
    OK,
    NG,
} status_t;

typedef enum {
    INST_NULL,
    INST_PUSH_LOCAL,
    INST_PUSH_CONST,
    INST_ASSIGN,
    INST_DEBUG,
} inst_t;

typedef enum {
    GLOBALMEM_NULL,
    GLOBALMEM_IP,
    GLOBALMEM_SP,
    GLOBALMEM_BP,
};

typedef struct {
    inst_t inst;
    char* token;
} node_t;

typedef struct {
    char* key;
    int32_t value;
} cipair_t;

union {
    int32_t i32[MEM_SIZE / sizeof(int32_t)];
    struct {
        int32_t bin[MEM_SIZE / sizeof(int32_t) / 4];
        char src[MEM_SIZE / sizeof(char) / 4];
        node_t node[MEM_SIZE / sizeof(node_t) / 4];
        cipair_t map[MEM_SIZE / sizeof(cipair_t) / 4];
    } compile_data;
} mem;

status_t readsrc() {
    FILE* file = fopen(src_path, "r");
    if (file == NULL) {
        perror("Error opening file");
        return NG;
    }
    size_t bytes_read = fread(mem.compile_data.src, sizeof(char), MEM_SIZE, file);
    if (bytes_read == 0) {
        perror("Error reading file");
        fclose(file);
        return NG;
    }
    mem.compile_data.src[bytes_read] = '\n';
    mem.compile_data.src[bytes_read + 1] = '\0';
    fclose(file);
}

char* token_next(char* itr) {
    while (*itr != ' ' && *itr != '\n' && *itr != '\t') {
        itr++;
    }
    while (*itr == ' ' || *itr == '\n' || *itr == '\t') {
        itr++;
    }
    return itr;
}

bool token_eq(char* token, char* str) {
    while (*str != '\0') {
        if (*token != *str) {
            return false;
        }
        token++;
        str++;
    }
    return true;
}

bool token_isnum(char* token) {
    while (*token != '\0' && *token != ' ' && *token != '\n' && *token != '\t') {
        if (*token < '0' || *token > '9') {
            return false;
        }
        token++;
    }
    return true;
}

int token_toint(char* token) {
    int num = 0;
    while (*token != '\0' && *token != ' ' && *token != '\n' && *token != '\t') {
        num = num * 10 + (*(token++) - '0');
    }
    return num;
}

void parse_indent(char** src_itr, node_t** node_itr) {
    if (token_isnum(*src_itr) == true) {
        *((*node_itr)++) = (node_t){.inst = INST_PUSH_CONST, .token = *src_itr};
        *src_itr = token_next(*src_itr);
    } else {
        *((*node_itr)++) = (node_t){.inst = INST_PUSH_LOCAL, .token = *src_itr};
        *src_itr = token_next(*src_itr);
    }
}

void parse_assign(char** src_itr, node_t** node_itr) {
    parse_indent(src_itr, node_itr);
    if (token_eq(*src_itr, "=")) {
        *src_itr = token_next(*src_itr);
        parse_indent(src_itr, node_itr);
        *((*node_itr)++) = (node_t){.inst = INST_ASSIGN, .token = NULL};
    }
}

void parse_expr(char** src_itr, node_t** node_itr) {
    if (token_eq(*src_itr, "(")) {
        *src_itr = token_next(*src_itr);
        while (!token_eq(*src_itr, ")")) {
            parse_expr(src_itr, node_itr);
        }
        *src_itr = token_next(*src_itr);
    } else {
        parse_assign(src_itr, node_itr);
    }
}

void parse() {
    char* src_itr = mem.compile_data.src;
    node_t* node_itr = mem.compile_data.node;
    parse_expr(&src_itr, &node_itr);
    *node_itr = (node_t){.inst = INST_NULL, .token = NULL};
}

void tobin() {
    node_t* node_itr = mem.compile_data.node;
    int32_t* bin_itr = mem.compile_data.bin + GLOBALMEM_SIZE;
    while (node_itr->inst != INST_NULL) {
        switch (node_itr->inst) {
            case INST_PUSH_CONST:
                *(bin_itr++) = INST_PUSH_CONST;
                *(bin_itr++) = token_toint(node_itr->token);
                break;
            case INST_PUSH_LOCAL:
                break;
            case INST_ASSIGN:
                *(bin_itr++) = INST_ASSIGN;
                break;
            default:
                break;
        }
        node_itr++;
    }
    mem.i32[GLOBALMEM_IP] = GLOBALMEM_SIZE;
    mem.i32[GLOBALMEM_SP] = bin_itr - mem.compile_data.bin;
    mem.i32[GLOBALMEM_BP] = mem.i32[GLOBALMEM_SP] + DEFAULT_STACK_SIZE;
}

void compile() {
    parse();
    tobin();
}

void exec() {
    int32_t* bin_itr = mem.compile_data.bin + 16;
    while (*bin_itr != INST_NULL) {
        switch (*bin_itr) {
            case INST_PUSH_CONST:
                bin_itr++;
                mem.i32[mem.i32[GLOBALMEM_SP]++] = *bin_itr;
                break;
            case INST_PUSH_LOCAL:
                break;
            case INST_ASSIGN:
                mem.i32[mem.i32[mem.i32[GLOBALMEM_SP] - 2]] = mem.i32[mem.i32[GLOBALMEM_SP] - 1];
                break;
            default:
                break;
        }
        bin_itr++;
    }
}

int main() {
    if (readsrc() == NG) {
        return 1;
    }
    compile();
    exec();
    return 0;
}