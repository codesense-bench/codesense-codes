// #include <cstddef>
// #include <cstdint>
// #include <cstdlib>
#include <stddef.h>

// Assuming the definitions of rotate_config_t and rotate_status_t are included from your project's headers
#include "rotate_config.h"
#include "rotate_status.h"

// extern "C"
int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    // Since we're not using FuzzedDataProvider, we directly use the input data.
    // Ensure that the size is sufficient for our structure initialization.
    if (size < sizeof(rotate_config_t) + sizeof(rotate_status_t)) {
        return 0;
    }

    // Initialize rotate_config_t and rotate_status_t instances
    rotate_config_t config;
    rotate_status_t status;

    // Example of initializing the config and status.
    // This should be replaced with actual initialization logic based on your application's requirements.
    memset(&config, 0, sizeof(config));
    memset(&status, 0, sizeof(status));

    // Here, you can manually set the fields of config and status as required.
    // For instance:
    // config.angle = 90;  // Just an example, replace with actual fields and values.
    // status.success = false; // Same as above.

    // Call the target function
    doRotate(&config, &status);

    // Optionally process the status after rotation

    return 0;
}
