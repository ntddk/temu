/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

/********************************************************************
** function_map.h
** Author: Cody Hartwig <chartwig@cs.cmu.edu>
			Heng Yin <hyin@ece.cmu.edu>
**
*
** this module maps eips to function names.  this 
** facilitates printing the names of functions called
** by executables run inside TEMU.
**
*/

#ifndef _FUNCTION_MAP_H_
#define _FUNCTION_MAP_H_


#ifdef __cplusplus
extern "C" {
#endif

struct names_t {
        const char* mod_name;
        const char* fun_name;
};

void handle_message(char *message);

/// @ingroup Semantics Extractor
/// Given an EIP, it returns the corresponding function name if exists
const char * function_map_search(uint32_t eip);

void add_fun_to_hook (const char *module_name, const char *function_name, 
					uint32_t hookfn, int is_global);

struct names_t * query_name(unsigned long eip);

///@ingroup Semantics Extractor
///Dump the function map to a file.
void map_to_file(const char *filename);

uint32_t query_eip(const char *module_name, const char *function_name);

void function_map_init();
void function_map_cleanup();


#ifdef __cplusplus
};
#endif


#endif
