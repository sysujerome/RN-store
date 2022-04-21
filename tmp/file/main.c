#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
// #define _GNU_SOURCE



int main() {
    const char *file_path = "/home/pjl/benchmark/workloads_500w/workloada-load-5000000.log.formated";\
    FILE *fp = fopen(file_path, "r");
    if (fp == NULL) exit(EXIT_FAILURE);
    char *line = NULL;
    size_t len;
    ssize_t read;
    int i = 0;
    while ((read = getline(&line, &len, fp)) != -1) {
        printf("line %d : %s", i++, line);
        
        if (i > 100) break;
    }
    fclose(fp);
    if (line) free(line);
    return 0;
}


        // if (line[strlen(line)-1] == '\n') {
        //     line[strlen(line) - 1] = '\0';
        //     // --len;
        // }