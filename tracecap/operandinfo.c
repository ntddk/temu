/*
TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

As an additional exception, the XED and Sleuthkit libraries, including
updated or modified versions, are excluded from the requirements of
the LGPL as if they were standard operating system libraries.
*/

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>
#include "operandinfo.h"
#include "config.h"
#include "tracecap.h"
#include "TEMU_main.h"

/* Flag that states if tainted data has already been seen during trace */
int received_tainted_data = 0;



/* Copy the given taint record into the given operand
     and check whether this is the first tainted operand seen
*/
inline void record_taint_value(OperandVal * op, taint_record_t * tr)
{
  struct timeval ftime;

  if (0 == received_tainted_data) {
    received_tainted_data = 1;
    if (gettimeofday(&ftime, 0) == 0) {
      term_printf("Time of first tainted data: %ld.%ld\n",
                  ftime.tv_sec, ftime.tv_usec);
    }
  }

  assert(op->length <= MAX_OPERAND_LEN);
  memcpy(op->records, tr, op->length*sizeof(taint_record_t));

}

/* Given an operand, check taint information and store it */
void set_operand_data(OperandVal *op)
{
#if TAINT_ENABLED
  taint_record_t taintrec[MAX_OPERAND_LEN];
  switch (op->type) {
    case TRegister: {
      int regnum = regmapping[op->addr - 100];
      int offset = getOperandOffset(op);
      op->tainted =
        (uint16_t) taintcheck_register_check(regnum, offset, op->length,
          (uint8_t *)taintrec);
      break;
    }
    case TMemLoc: {
      uint32_t addr = TEMU_get_phys_addr( op->addr);
      op->tainted =
        (uint16_t) taintcheck_memory_check(addr, op->length, (uint8_t *)taintrec);
      break;
    }
    default:
      break;
  }

  if (op->tainted) {
    record_taint_value(op, taintrec);
  }
#endif
}
