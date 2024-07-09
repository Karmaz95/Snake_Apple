// clang -o sbpl_compiler_wrapper sbpl_compiler_wrapper.c -lsandbox
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define a struct to hold the compiled sandbox profile
struct compiled_sbp {
    int64_t field_0; // unknown, maybe type?
    void * data;     // pointer to the compiled sandbox profile
    size_t size;     // size of the compiled sandbox profile
};
// Declare the sandbox_compile_file function
struct compiled_sbp *sandbox_compile_file(const char *inputPath, __int64_t a2, char **error_msg);
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s input_sb output_bin\n", argv[0]);
        return 1;
    }
    // Get the full path of the input file so we skip the sandbox_compile_file relative path check
    char *inputPath = realpath(argv[1], NULL);
    if (!inputPath) {
        perror("Failed to resolve input file path");
        return 1;
    }
    const char *outputPath = argv[2];
    // Declare variables to store the compiled sandbox profile and error message
    char *error_msg = NULL;
    struct compiled_sbp *compiled_file = NULL;
    // Call sandbox_compile_file
    compiled_file = sandbox_compile_file(inputPath, 0, &error_msg);
    // Write result (bytecode) to output file
    FILE *outputFile = fopen(outputPath, "wb");
    if (!outputFile) {
        perror("Failed to open output file");
        return 1;
    }
    size_t bytesWritten = fwrite(compiled_file->data, 1, compiled_file->size, outputFile);
    if (bytesWritten != compiled_file->size) {
        fprintf(stderr, "Failed to write all bytecode to output file\n");
    }
    
    fclose(outputFile);
    return 0;
}