// #include <cstdio>
// #include <cstdint>
// #include <cstdlib>
// #include <cstring>
#include <stddef.h>

#include "apr_file_io.h"
#include "apr_strings.h"

// extern "C"
int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    // Ensure APR is initialized
    if (apr_initialize() != APR_SUCCESS) {
        return 0;
    }
    atexit(apr_terminate);

    // Create an in-memory file to use as a placeholder
    apr_pool_t* pool = NULL;
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS) {
        return 0;
    }

    apr_file_t* memfile = NULL;
    if (apr_file_open_memfile(&memfile, "fuzzed_file", data, size, pool) != APR_SUCCESS) {
        apr_pool_destroy(pool);
        return 0;
    }

    // Prepare user and realm strings from input data
    // Assuming input data is large enough to split into two parts
    if (size < 2) {
        apr_file_close(memfile);
        apr_pool_destroy(pool);
        return 0;
    }

    size_t split_point = size / 2;
    char* user = apr_pstrndup(pool, (data), split_point);
    char* realm = apr_pstrndup(pool, (data) + split_point, size - split_point);

    // Call the target function
    add_password(user, realm, memfile);

    // Cleanup
    apr_file_close(memfile);
    apr_pool_destroy(pool);

    return 0;
}
