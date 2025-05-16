#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	// If size is 0 we need a null-terminated string.
	// We dont null-terminate the string and by the design
	// of the API passing 0 as size with non null-terminated string
	// gives undefined behavior. 	
	if(size==0){
		return 0;
	}
	ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_t *other = ucl_object_typed_new(UCL_OBJECT);

	ucl_object_insert_key(obj, (char *)data, size, 0, 0);
	ucl_object_insert_key(other, (char *)data, size, 0, 0);
	
	if (ucl_object_merge(obj, other, 0) != 0) {
		return 0;
	}
	
	ucl_object_compare(obj,other);
	
	ucl_object_unref(obj);
	ucl_object_unref(other);
        return 0;
}

