#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define src_path "./src.txt"
#define mem_size 65536

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
    return (*token == '\0' || *token == ' ' || *token == '\n' || *token == '\t');
}

int token_toint(char* token) {
    int num = 0;
    while (*token != '\0' && *token != ' ' && *token != '\n' && *token != '\t') {
        num = num * 10 + (*token - '0');
        token++;
    }
    return num;
}

void parse_indent(char** src_itr, node_t** node_itr) {
    if (token_isnum(*src_itr) == OK) {
        **node_itr = (node_t){.inst = INST_PUSH_CONST, .token = *src_itr};
        *src_itr = token_next(*src_itr);
        *node_itr = *node_itr + 1;
    } else {
        **node_itr = (node_t){.inst = INST_PUSH_LOCAL, .token = *src_itr};
        *src_itr = token_next(*src_itr);
        *node_itr = *node_itr + 1;
    }
}

void parse_assign(char** src_itr, node_t** node_itr) {
    parse_indent(src_itr, node_itr);
    if (token_eq(*src_itr, "=")) {
        *src_itr = token_next(*src_itr);
        parse_indent(src_itr, node_itr);
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

void compile() {
    parse();
}

int main() {
    if (readsrc() == NG) {
        return 1;
    }
    compile();
    return 0;
}