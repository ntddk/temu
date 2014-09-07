/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#ifndef _TEMU_PHYSADDR_INFO_H_INCLUDED_
#define _TEMU_PHYSADDR_INFO_H_INCLUDED_

typedef struct {
  int size;
  uint8_t *ptr;
} physaddr_info_t;

extern physaddr_info_t physaddr_info_list[8 + 32];
extern int physaddr_index;

static inline void dump_physaddr_info(int size, uint8_t * p)
{
  physaddr_info_list[physaddr_index].size = size;
  physaddr_info_list[physaddr_index++].ptr = (uint8_t *) p;
}


#endif //_TEMU_PHYSADDR_INFO_H_INCLUDED_
