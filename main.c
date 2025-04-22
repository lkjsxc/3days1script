#include <stdio.h>

#define src_path "./src.txt"
#define src_data_size 65536

char src_data[src_data_size];

typedef enum {
    OK,
    NG,
} status_t;

status_t readsrc() {
    FILE* file = fopen(src_path, "r");
    if (file == NULL) {
        perror("Error opening file");
        return NG;
    }
    size_t bytes_read = fread(src_data, 1, src_data_size - 1, file);
    if (bytes_read == 0) {
        perror("Error reading file");
        fclose(file);
        return NG;
    }
    src_data[bytes_read] = '\n';
    src_data[bytes_read + 1] = '\0';
    fclose(file);
}

int main() {
    if (readsrc() == NG) {
        return 1;
    }
    printf("Data read from file:\n%s", src_data);
    return 0;
}