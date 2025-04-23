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
    INST_PUSH_LOCAL_VAL,
    INST_PUSH_LOCAL_ADDR,
    INST_PUSH_CONST,
    INST_DEREF,
    INST_ASSIGN,
    INST_CALL,
    INST_RETURN,
    INST_JMP,
    INST_JMZ,
    INST_OR,
    INST_AND,
    INST_EQ,
    INST_NE,
    INST_LT,
    INST_LE,
    INST_GT,
    INST_GE,
    INST_ADD,
    INST_SUB,
    INST_MUL,
    INST_DIV,
    INST_MOD,
    INST_SHL,
    INST_SHR,
    INST_BITAND,
    INST_BITOR,
    INST_BITXOR,
    INST_BITNOT,
    LABEL,
    LABEL_FNEND,
} type_t;

// mem[0] = 0
// mem[1] = ip
// mem[2] = sp
// mem[3] = bp
typedef enum {
    GLOBALMEM_ZERO,
    GLOBALMEM_IP,
    GLOBALMEM_SP,
    GLOBALMEM_BP,
} globalmem_t;

typedef struct {
    type_t inst;
    char* token;
    int32_t val;
    int32_t* bin;
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
        cipair_t map[MEM_SIZE / sizeof(cipair_t) / 4];  // 0 ~ label_cnt-1: key is Null, label_cnt ~ label_cnt+localval_cnt-1: key is token
        char* src_itr;
        node_t* node_itr;
        int32_t label_cnt;
    } compile_data;
} mem;

void parse_expr(int label_break, int label_continue);

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

bool token_eq(char* src1, char* src2) {
    while (*src1 != '\0' && *src1 != ' ' && *src1 != '\n' && *src1 != '\t' ||
           *src2 != '\0' && *src2 != ' ' && *src2 != '\n' && *src2 != '\t') {
        if (*src1 != *src2) {
            return false;
        }
        src1++;
        src2++;
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

void parse_primary(int label_break, int label_continue) {
    if (*mem.compile_data.src_itr == '&') {
        mem.compile_data.src_itr = mem.compile_data.src_itr + 1;
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_PUSH_LOCAL_ADDR, .token = mem.compile_data.src_itr, .val = 0};
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
    } else if (token_eq(mem.compile_data.src_itr, "(")) {
        parse_expr(label_break, label_continue);
    } else if (token_eq(mem.compile_data.src_itr, "if")) {
        int label_if = mem.compile_data.label_cnt++;
        int label_else = mem.compile_data.label_cnt++;
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_expr(label_break, label_continue);  // conditional expression
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_JMZ, .token = NULL, .val = label_if};
        parse_expr(label_break, label_continue);  // when true
        if (token_eq(mem.compile_data.src_itr, "else")) {
            mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
            *(mem.compile_data.node_itr++) = (node_t){.inst = INST_JMP, .token = NULL, .val = label_else};
            *(mem.compile_data.node_itr++) = (node_t){.inst = LABEL, .token = NULL, .val = label_if};
            parse_expr(label_break, label_continue);  // when false
            *(mem.compile_data.node_itr++) = (node_t){.inst = LABEL, .token = NULL, .val = label_else};
        } else {
            *(mem.compile_data.node_itr++) = (node_t){.inst = LABEL, .token = NULL, .val = label_if};
        }
    } else if (token_eq(mem.compile_data.src_itr, "return")) {
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_expr(label_break, label_continue);
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_RETURN, .token = NULL, .val = 0};
    } else if (token_eq(mem.compile_data.src_itr, "break")) {
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_JMP, .token = NULL, .val = label_break};
    } else if (token_eq(mem.compile_data.src_itr, "continue")) {
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_JMP, .token = NULL, .val = label_continue};
    } else if (token_isnum(mem.compile_data.src_itr) == true) {
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_PUSH_CONST, .token = mem.compile_data.src_itr, .val = token_toint(mem.compile_data.src_itr)};
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
    } else {
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_PUSH_LOCAL_VAL, .token = mem.compile_data.src_itr, .val = 0};
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
    }
}

void parse_unary(int label_break, int label_continue) {
    if (token_eq(mem.compile_data.src_itr, "*")) {
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_unary(label_break, label_continue);
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_DEREF, .token = NULL, .val = 0};
    } else if (token_eq(mem.compile_data.src_itr, "+")) {
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_primary(label_break, label_continue);
    } else if (token_eq(mem.compile_data.src_itr, "-")) {
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_PUSH_CONST, .token = NULL, .val = 0};
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_primary(label_break, label_continue);
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_SUB, .token = NULL, .val = 0};
    } else if (token_eq(mem.compile_data.src_itr, "!")) {  // !e = (e == 0) https://learn.microsoft.com/ja-jp/cpp/cpp/logical-negation-operator-exclpt?view=msvc-170
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_PUSH_CONST, .token = NULL, .val = 0};
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_primary(label_break, label_continue);
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_EQ, .token = NULL, .val = 0};
    } else if (token_eq(mem.compile_data.src_itr, "~")) {
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_PUSH_CONST, .token = NULL, .val = 0};
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_primary(label_break, label_continue);
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_BITNOT, .token = NULL, .val = 0};
    } else {
        parse_primary(label_break, label_continue);
    }
}

void parse_mul(int label_break, int label_continue) {
    parse_unary(label_break, label_continue);
    while (token_eq(mem.compile_data.src_itr, "*") || token_eq(mem.compile_data.src_itr, "/") || token_eq(mem.compile_data.src_itr, "%")) {
        char* op = mem.compile_data.src_itr;
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_unary(label_break, label_continue);
        if (token_eq(op, "*")) {
            *(mem.compile_data.node_itr++) = (node_t){.inst = INST_MUL, .token = NULL, .val = 0};
        } else if (token_eq(op, "/")) {
            *(mem.compile_data.node_itr++) = (node_t){.inst = INST_DIV, .token = NULL, .val = 0};
        } else if (token_eq(op, "%")) {
            *(mem.compile_data.node_itr++) = (node_t){.inst = INST_MOD, .token = NULL, .val = 0};
        }
    }
}

void parse_add(int label_break, int label_continue) {
    parse_mul(label_break, label_continue);
    while (token_eq(mem.compile_data.src_itr, "+") || token_eq(mem.compile_data.src_itr, "-")) {
        char* op = mem.compile_data.src_itr;
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_mul(label_break, label_continue);
        if (token_eq(op, "+")) {
            *(mem.compile_data.node_itr++) = (node_t){.inst = INST_ADD, .token = NULL, .val = 0};
        } else if (token_eq(op, "-")) {
            *(mem.compile_data.node_itr++) = (node_t){.inst = INST_SUB, .token = NULL, .val = 0};
        }
    }
}

void parse_shift(int label_break, int label_continue) {
    parse_add(label_break, label_continue);
    while (token_eq(mem.compile_data.src_itr, "<<") || token_eq(mem.compile_data.src_itr, ">>")) {
        char* op = mem.compile_data.src_itr;
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_add(label_break, label_continue);
        if (token_eq(op, "<<")) {
            *(mem.compile_data.node_itr++) = (node_t){.inst = INST_SHL, .token = NULL, .val = 0};
        } else if (token_eq(op, ">>")) {
            *(mem.compile_data.node_itr++) = (node_t){.inst = INST_SHR, .token = NULL, .val = 0};
        }
    }
}

void parse_rel(int label_break, int label_continue) {
    parse_shift(label_break, label_continue);
    while (token_eq(mem.compile_data.src_itr, "<") || token_eq(mem.compile_data.src_itr, "<=") || token_eq(mem.compile_data.src_itr, ">") || token_eq(mem.compile_data.src_itr, ">=")) {
        char* op = mem.compile_data.src_itr;
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_shift(label_break, label_continue);
        if (token_eq(op, "<")) {
            *(mem.compile_data.node_itr++) = (node_t){.inst = INST_LT, .token = NULL, .val = 0};
        } else if (token_eq(op, "<=")) {
            *(mem.compile_data.node_itr++) = (node_t){.inst = INST_LE, .token = NULL, .val = 0};
        } else if (token_eq(op, ">")) {
            *(mem.compile_data.node_itr++) = (node_t){.inst = INST_GT, .token = NULL, .val = 0};
        } else if (token_eq(op, ">=")) {
            *(mem.compile_data.node_itr++) = (node_t){.inst = INST_GE, .token = NULL, .val = 0};
        }
    }
}

void parse_eq(int label_break, int label_continue) {
    parse_rel(label_break, label_continue);
    while (token_eq(mem.compile_data.src_itr, "==") || token_eq(mem.compile_data.src_itr, "!=")) {
        char* op = mem.compile_data.src_itr;
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_rel(label_break, label_continue);
        if (token_eq(op, "==")) {
            *(mem.compile_data.node_itr++) = (node_t){.inst = INST_EQ, .token = NULL, .val = 0};
        } else if (token_eq(op, "!=")) {
            *(mem.compile_data.node_itr++) = (node_t){.inst = INST_NE, .token = NULL, .val = 0};
        }
    }
}

void parse_and(int label_break, int label_continue) {
    parse_eq(label_break, label_continue);
    while (token_eq(mem.compile_data.src_itr, "&")) {
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_eq(label_break, label_continue);
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_BITAND, .token = NULL, .val = 0};
    }
}

void parse_xor(int label_break, int label_continue) {
    parse_and(label_break, label_continue);
    while (token_eq(mem.compile_data.src_itr, "^")) {
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_and(label_break, label_continue);
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_BITXOR, .token = NULL, .val = 0};
    }
}

void parse_or(int label_break, int label_continue) {
    parse_xor(label_break, label_continue);
    while (token_eq(mem.compile_data.src_itr, "|")) {
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_xor(label_break, label_continue);
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_BITOR, .token = NULL, .val = 0};
    }
}

void parse_logical_and(int label_break, int label_continue) {
    parse_or(label_break, label_continue);
    while (token_eq(mem.compile_data.src_itr, "&&")) {
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_or(label_break, label_continue);
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_AND, .token = NULL, .val = 0};
    }
}

void parse_logical_or(int label_break, int label_continue) {
    parse_logical_and(label_break, label_continue);
    while (token_eq(mem.compile_data.src_itr, "||")) {
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_logical_and(label_break, label_continue);
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_OR, .token = NULL, .val = 0};
    }
}

void parse_assign(int label_break, int label_continue) {
    parse_logical_or(label_break, label_continue);
    while (token_eq(mem.compile_data.src_itr, "=")) {
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        parse_logical_or(label_break, label_continue);
        *(mem.compile_data.node_itr++) = (node_t){.inst = INST_ASSIGN, .token = NULL, .val = 0};
    }
}

void parse_expr(int label_break, int label_continue) {
    if (token_eq(mem.compile_data.src_itr, "(")) {
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
        while (!token_eq(mem.compile_data.src_itr, ")")) {
            parse_expr(label_break, label_continue);
        }
        mem.compile_data.src_itr = token_next(mem.compile_data.src_itr);
    } else {
        parse_assign(label_break, label_continue);
    }
}

void parse() {
    mem.compile_data.src_itr = mem.compile_data.src;
    mem.compile_data.node_itr = mem.compile_data.node;
    mem.compile_data.label_cnt = 0;
    while (*mem.compile_data.src_itr != '\0') {
        parse_expr(-1, -1);
    }
    *mem.compile_data.node_itr = (node_t){.inst = INST_NULL, .token = NULL};
}

void tobin() {
    int32_t* bin_begin = mem.compile_data.bin + GLOBALMEM_SIZE;
    int32_t* bin_itr = bin_begin;
    int32_t localval_cnt = 0;

    node_t* node_itr = mem.compile_data.node;
    while (node_itr->inst != INST_NULL) {
        node_itr->bin = bin_itr;
        switch (node_itr->inst) {
            case INST_PUSH_CONST:
            case INST_PUSH_LOCAL_VAL:
            case INST_PUSH_LOCAL_ADDR:
                *bin_itr++ = node_itr->inst;
                *bin_itr++ = node_itr->val;
                break;
            case INST_JMP:
            case INST_JMZ:
                *bin_itr++ = node_itr->inst;
                *bin_itr++ = 0;
                break;
            case LABEL:
            case LABEL_FNEND:
                mem.compile_data.map[node_itr->val] = (cipair_t){.key = NULL, .value = bin_itr - mem.compile_data.bin};
                break;
            default:
                *bin_itr++ = node_itr->inst;
                break;
        }
        node_itr++;
    }

    node_itr = mem.compile_data.node;
    while (node_itr->inst != INST_NULL) {
        if (node_itr->inst == INST_JMP || node_itr->inst == INST_JMZ) {
            int32_t addr = mem.compile_data.map[node_itr->val].value;
            *(node_itr->bin + 1) = addr;
        }
        node_itr++;
    }

    node_itr = mem.compile_data.node;
    while (node_itr->inst != INST_NULL) {
        switch (node_itr->inst) {
            case LABEL_FNEND:
                localval_cnt = 0;
                break;
            case INST_PUSH_LOCAL_VAL:
            case INST_PUSH_LOCAL_ADDR: {
                int32_t i;
                for (i = mem.compile_data.label_cnt; i < mem.compile_data.label_cnt + localval_cnt; i++) {
                    if (token_eq(mem.compile_data.map[i].key, node_itr->token)) {
                        node_itr->val = mem.compile_data.map[i].value;
                        break;
                    }
                }
                if (i == mem.compile_data.label_cnt + localval_cnt) {
                    mem.compile_data.map[i] = (cipair_t){.key = node_itr->token, .value = localval_cnt};
                    localval_cnt++;
                }
            } break;
        }
        node_itr++;
    }

    mem.i32[GLOBALMEM_ZERO] = 0;
    mem.i32[GLOBALMEM_IP] = GLOBALMEM_SIZE;
    mem.i32[GLOBALMEM_BP] = bin_itr - mem.compile_data.bin;
    mem.i32[GLOBALMEM_SP] = mem.i32[GLOBALMEM_BP] + DEFAULT_STACK_SIZE;
}

void compile() {
    parse();
    tobin();
}

void exec() {
    while (true) {
        switch (mem.i32[mem.i32[GLOBALMEM_IP]++]) {
            case INST_PUSH_LOCAL_VAL: {
                int32_t addr = mem.i32[mem.i32[GLOBALMEM_IP]++] + mem.i32[GLOBALMEM_BP];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = mem.i32[addr];
            } break;
            case INST_PUSH_LOCAL_ADDR: {
                int32_t addr = mem.i32[mem.i32[GLOBALMEM_IP]++] + mem.i32[GLOBALMEM_BP];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = addr;
            } break;
            case INST_PUSH_CONST: {
                int32_t val = mem.i32[mem.i32[GLOBALMEM_IP]++];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val;
            } break;
            case INST_DEREF: {
                int32_t addr = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = mem.i32[addr];
            } break;
            case INST_ASSIGN: {
                int32_t val = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t addr = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[addr] = val;
            } break;
            case INST_CALL: {
                int32_t addr = mem.i32[mem.i32[GLOBALMEM_IP]++];
                mem.i32[--mem.i32[GLOBALMEM_SP]] = mem.i32[GLOBALMEM_BP];
                mem.i32[GLOBALMEM_BP] = mem.i32[GLOBALMEM_SP];
                mem.i32[GLOBALMEM_IP] = addr;
            } break;
            case INST_RETURN: {
                mem.i32[GLOBALMEM_SP] = mem.i32[GLOBALMEM_BP];
                mem.i32[GLOBALMEM_BP] = mem.i32[mem.i32[GLOBALMEM_SP]++];
                mem.i32[GLOBALMEM_IP] = mem.i32[GLOBALMEM_SP];
            } break;
            case INST_JMP: {
                int32_t addr = mem.i32[mem.i32[GLOBALMEM_IP]++];
                mem.i32[GLOBALMEM_IP] = addr;
            } break;
            case INST_JMZ: {
                int32_t addr = mem.i32[mem.i32[GLOBALMEM_IP]++];
                int32_t val = mem.i32[--mem.i32[GLOBALMEM_SP]];
                if (val == 0) {
                    mem.i32[GLOBALMEM_IP] = addr;
                }
            } break;
            case INST_OR: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 | val2;
            } break;
            case INST_AND: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 & val2;
            } break;
            case INST_EQ: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 == val2;
            } break;
            case INST_NE: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 != val2;
            } break;
            case INST_LT: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 < val2;
            } break;
            case INST_LE: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 <= val2;
            } break;
            case INST_GT: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 > val2;
            } break;
            case INST_GE: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 >= val2;
            } break;
            case INST_ADD: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 + val2;
            } break;
            case INST_SUB: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 - val2;
            } break;
            case INST_MUL: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 * val2;
            } break;
            case INST_DIV: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 / val2;
            } break;
            case INST_MOD: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 % val2;
            } break;
            case INST_SHL: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 << val2;
            } break;
            case INST_SHR: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 >> val2;
            } break;
            case INST_BITAND: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 & val2;
            } break;
            case INST_BITOR: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 | val2;
            } break;
            case INST_BITXOR: {
                int32_t val1 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                int32_t val2 = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = val1 ^ val2;
            } break;
            case INST_BITNOT: {
                int32_t val = mem.i32[--mem.i32[GLOBALMEM_SP]];
                mem.i32[mem.i32[GLOBALMEM_SP]++] = ~val;
            } break;

            default:
                return;
        }
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