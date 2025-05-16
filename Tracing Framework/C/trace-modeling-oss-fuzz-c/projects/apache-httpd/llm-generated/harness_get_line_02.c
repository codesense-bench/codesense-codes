// #include <cstddef>
// #include <cstdint>
// #include <cstdlib>

#include "apr_file_io.h"
#include "apr_general.h"
#include <stddef.h>

// Function prototype for get_line, as it's not included in any header.
// extern "C"
int get_line(char *s, int n, apr_file_t *f);

// extern "C"
int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
  // Initialize APR library.
  apr_initialize();
  atexit(apr_terminate);

  // Ensure there is at least one byte of data to avoid division by zero.
  if (size == 0) {
    return 0;
  }

  // Divide the input data into two parts: file content and buffer size.
  size_t file_size = size / 2;
  size_t buffer_size = size - file_size;

  // Create a memory-based file with the first part of the input data.
  apr_file_t *memfile;
  apr_pool_t *pool;
  apr_pool_create(&pool, NULL);
  apr_file_open_memfile(&memfile, "fuzzfile", (char*)data, file_size, pool);

  // Allocate a buffer for the string.
  char *buffer = (char *)malloc(buffer_size);
  if (!buffer) {
    apr_pool_destroy(pool);
    return 0;
  }

  // Call the target function.
  get_line(buffer, buffer_size, memfile);

  // Clean up.
  free(buffer);
  apr_file_close(memfile);
  apr_pool_destroy(pool);

  return 0;
}
