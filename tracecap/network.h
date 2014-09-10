/*
TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

As an additional exception, the XED and Sleuthkit libraries, including
updated or modified versions, are excluded from the requirements of
the LGPL as if they were standard operating system libraries.
*/

#ifndef _NETWORK_H_
#define _NETWORK_H_

/* Functions */
void do_taint_nic(int state);
void print_nic_filter ();
int update_nic_filter (const char *filter_str, const char *value_str);
void tracing_nic_recv(uint8_t * buf, int size, int index, int start, int stop);
void tracing_nic_send(uint32_t addr, int size, uint8_t * buf);

#endif // _NETWORK_H_

