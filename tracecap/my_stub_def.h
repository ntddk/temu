/*
TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

As an additional exception, the XED and Sleuthkit libraries, including
updated or modified versions, are excluded from the requirements of
the LGPL as if they were standard operating system libraries.
*/

#ifndef _MY_STUB_DEF_H_
#define _MY_STUB_DEF_H_

#include "tracecap.h"

typedef struct {
  uint32_t source;
  uint32_t origin;
  uint32_t offset;
}hook_taint_record_t;

#endif // _MY_STUB_DEF_H_

