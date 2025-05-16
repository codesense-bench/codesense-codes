// #include <cstddef>
// #include <cstdint>
// #include <cstdlib>
// #include <string>
#include <stddef.h>

#include "apr_general.h"
#include "apr_file_io.h"
#include "apr_pools.h"

// extern "C" {
    void add_password(char *user, char *realm, apr_file_t *f);
// }

// extern "C"
int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    // Initialize APR
    if (apr_initialize() != APR_SUCCESS) {
        return 0;
    }
    atexit(apr_terminate);

    // Create an APR memory pool
    apr_pool_t *pool = NULL;
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS) {
        return 0;
    }

    // Create a temporary file
    apr_file_t *temp_file = NULL;
    if (apr_file_mktemp(&temp_file, "/tmp/fuzzfileXXXXXX", 0, pool) != APR_SUCCESS) {
        apr_pool_destroy(pool);
        return 0;
    }

    // Use the input data to create user and realm strings
    user = data;
    realm = data + size / 2;

    // Call the target function
    add_password(user.c_str(), realm.c_str(), temp_file);

    // Cleanup
    apr_file_close(temp_file);
    apr_pool_destroy(pool);

    return 0;
}
