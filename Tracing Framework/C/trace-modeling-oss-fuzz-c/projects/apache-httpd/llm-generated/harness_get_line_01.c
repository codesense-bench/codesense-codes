// #include <cstddef>
// #include <cstdint>
// #include <cstdlib>

#include "apr_file_io.h"
#include "apr_general.h"
#include <stddef.h>

// Function signature we are testing
int get_line(char *s, int n, apr_file_t *f);

// Entry point for the fuzzer
// extern "C"
int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    // Initialize APR library
    if (apr_initialize() != APR_SUCCESS) {
        return 0;
    }

    // Create a temporary file to use with get_line
    apr_pool_t* pool = NULL;
    apr_pool_create(&pool, NULL);
    apr_file_t* temp_file = NULL;
    apr_file_open(&temp_file, "/tmp/fuzz_temp_file", APR_WRITE | APR_CREATE | APR_TRUNCATE, APR_OS_DEFAULT, pool);

    // Write the fuzzing data to the file
    apr_size_t written = size;
    apr_file_write(temp_file, data, &written);

    // Reset the file pointer to the beginning of the file
    apr_file_seek(temp_file, APR_SET, NULL);

    // Allocate memory for the buffer
    // char* buffer = new char[size];
    char* buffer = malloc(size);

    // Call the function with the fuzzing data
    get_line(buffer, size, temp_file);

    // Cleanup
    // delete[] buffer;
    free(buffer);
    apr_file_close(temp_file);
    apr_pool_destroy(pool);
    apr_terminate();

    return 0;
}
