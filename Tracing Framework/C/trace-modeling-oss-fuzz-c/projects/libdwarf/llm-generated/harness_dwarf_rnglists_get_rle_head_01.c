#include "dwarf.h"
#include "libdwarf.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  Dwarf_Error *errp = 0;
  Dwarf_Debug dbg = 0;
  int res = 0;
  int chosengroup = DW_GROUPNUMBER_ANY;
  Dwarf_Error error = 0;
  Dwarf_Unsigned section_count = 0;
  Dwarf_Unsigned group_count = 0;
  Dwarf_Unsigned selected_group = 0;
  Dwarf_Unsigned map_entry_count = 0;
  Dwarf_Unsigned *group_numbers_array = 0;
  Dwarf_Unsigned *sec_numbers_array = 0;
  const char **sec_names_array = 0;

  int run = dwarf_init_path(filename, 0, 0, chosengroup, 0, 0, &dbg, errp);
  if (run != -1) {
    if (run == DW_DLV_ERROR) {
      dwarf_finish(dbg);
      unlink(filename);
      return 0;
    }
    if (run == DW_DLV_NO_ENTRY) {
      dwarf_finish(dbg);
      unlink(filename);
      return 0;
    }
    res = dwarf_sec_group_sizes(dbg, &section_count, &group_count,
                                &selected_group, &map_entry_count, errp);
    if (res != DW_DLV_OK) {
      dwarf_dealloc_error(dbg, error);
      error = 0;
      dwarf_finish(dbg);
      unlink(filename);
      close(run);
      return 0;
    }
    group_numbers_array =
        (Dwarf_Unsigned *)calloc(map_entry_count, sizeof(Dwarf_Unsigned));
    sec_numbers_array =
        (Dwarf_Unsigned *)calloc(map_entry_count, sizeof(Dwarf_Unsigned));
    sec_names_array =
        (const char **)calloc(map_entry_count, sizeof(const char *));
    res = dwarf_sec_group_map(dbg, map_entry_count, group_numbers_array,
                              sec_numbers_array, sec_names_array, &error);
    free(sec_names_array);
    free(sec_numbers_array);
    free(group_numbers_array);
    dwarf_dealloc_error(dbg, error);
  }
  dwarf_finish(dbg);
  unlink(filename);
  close(run);
  return 0;
}

int dwarf_rnglists_get_rle_head(struct Dwarf_Attribute_s *attr, bool theform, size_t attr_val, struct Dwarf_Rnglists_Head_s **head_out, size_t *entries_count_out, size_t *global_offset_of_rle_set, struct Dwarf_Error_s **error) {
  return 0;
}

