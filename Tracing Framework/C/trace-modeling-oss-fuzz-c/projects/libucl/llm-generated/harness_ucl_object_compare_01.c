#include <stdio.h>
#include <stdlib.h>
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
	struct ucl_parser *parser1, *parser2;
       	parser1 = ucl_parser_new(0);
	parser2 = ucl_parser_new(0);
	
	ucl_parser_add_string(parser1, (char *)data, size);
	ucl_parser_add_string(parser2, (char *)data, size);
	
	if (ucl_parser_get_error(parser1) != NULL || ucl_parser_get_error(parser2) != NULL) {
		return 0;
	}

	ucl_object_t *o1, *o2;
	o1 = ucl_parser_get_object(parser1);
	o2 = ucl_parser_get_object(parser2);

	int ret = ucl_object_compare(o1, o2);
	ucl_parser_free (parser1);
	ucl_parser_free (parser2);
        return 0;
}

