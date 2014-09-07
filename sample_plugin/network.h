/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#ifndef _NETWORK_H_
#define _NETWORK_H_

/* Functions */
void do_taint_nic(int state);
void my_nic_recv(uint8_t * buf, int size, int index, int start, int stop);
void my_nic_send(uint32_t addr, int size, uint8_t * buf);

#endif // _NETWORK_H_

