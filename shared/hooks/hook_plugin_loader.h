/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#ifndef _HOOK_PLUGIN_LOADER_H_
#define _HOOK_PLUGIN_LOADER_H_
#include "hook_plugins/hook_plugin.h"

enum confType { pactive = 0, ini };

#ifdef __cplusplus
extern "C" {
#endif
void load_hook_plugins(unsigned int *mon_cr3, /* cr3 of proc to monitor*/
		  const char *const pa_path,  /* path of plugins.active */
		  const char *const pl_path,  /* path of plugins        */
		  hook_plugin_info_t *plugin_info,
		  enum confType); 

void unload_hook_plugins();

int
should_hook(const char *mod_name, const char *fun_name);

#ifdef __cplusplus
};
#endif

#endif /*_PLUGIN_LOADER_H_*/
