/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

/************************************************************************
** Author: Juan Caballero <jcaballero@cmu.edu>
**
*
*/

#include "config.h"
#include "../../hookapi.h"

#ifdef PLUGIN_PROTOS
#define TAINT_RECORD_ONLY
#include "../../../protos/protos.h" //for taint_record_t
#undef TAINT_RECORD_ONLY
#include "../../../protos/ext_hooks.h"
#endif

#ifdef PLUGIN_TRACECAP
#define TAINT_RECORD_ONLY
#include "../../../tracecap/trace.h" //for taint_record_t
#undef TAINT_RECORD_ONLY
#include "../../../tracecap/ext_hooks.h"
#endif

typedef struct {
  uint32_t hook_handle;
} retaddr_t;

void initialize_plugin(hook_t *hooks,int num_funs);
void print_buffer(uint32_t start, uint32_t len);
int is_str_tainted(uint32_t vaddr, int *len);
int get_string(uint32_t address, char *str, int max_size);
uint32_t get_arg(int argnum);
int is_arg_tainted(int argnum);
int get_string_taint(uint32_t address, uint32_t taintinfo[][2], int size);
int get_unicode_string(uint32_t address, char *str, int str_max_size);
int get_bin_string(const char *str, int str_len, char *out, int out_size);
void print_string_taint(FILE *fd,  uint32_t taintinfo[][2], int size,
  unsigned int bytes_per_line);

