/*
TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

As an additional exception, the XED and Sleuthkit libraries, including
updated or modified versions, are excluded from the requirements of
the LGPL as if they were standard operating system libraries.
*/

#ifndef _CONDITIONS_H_
#define _CONDITIONS_H_

#include <inttypes.h>

extern int (*comparestring)(const char *, const char*);
extern int tracing_start_condition;

void procname_clear();
char *procname_get();
void procname_set(const char *name);
int procname_match(const char *name);
int procname_is_set();

void modname_clear();
void modname_set(const char *name);
int modname_match(const char *name);
int modname_is_set();


int uint32_compare(const void* u1, const void* u2);
void tc_modname(const char *modname);
void tc_address(uint32_t address);
void tc_address_start(uint32_t address, uint32_t at_counter);
void tc_address_stop(uint32_t address, uint32_t at_counter);

#endif // _CONDITIONS_H_

