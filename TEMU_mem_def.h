/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#include "TEMU_physaddr_info.h"

#define TC_ldub_raw(a, t) \
	(		\
		taintcheck_mem2reg(laddr((a)), 1, t),  \
		ldub_raw(a) \
	)

#define TC_ldsb_raw(a, t) \
	( \
		taintcheck_mem2reg(laddr((a)), 1, t), \
		ldsb_raw(a) \
	)

#define TC_lduw_raw(a, t) \
	( \
		taintcheck_mem2reg(laddr((a)), 2, t), \
		lduw_raw(a) \
	)

#define TC_ldsw_raw(a, t)	\
	( \
		taintcheck_mem2reg(laddr((a)), 2, t), \
		ldsw_raw(a)	\
	)

#define TC_ldl_raw(a, t) \
	(  \
		taintcheck_mem2reg(laddr((a)), 4, t), \
		ldl_raw(a) \
	)

#define TC_ldq_raw(a, t) \
	( \
		taintcheck_reg_clean2(t, 4), \
		ldq_raw(a) \
	)

#define TC_stb_raw(a, s, t) \
	do { \
		taintcheck_reg2mem(t, 1, laddr((a)));\
		stb_raw(a, s); \
	}while(0);

#define TC_stw_raw(a, s, t) \
	do {	\
		taintcheck_reg2mem(t, 2, laddr((a))); \
		stw_raw(a, s); \
	}while(0);

#define TC_stl_raw(a, s, t) \
	do { \
		taintcheck_reg2mem(t, 4, laddr((a))); \
		stl_raw(a, s); \
	}while(0);

#define TC_stq_raw(a, s, t) \
	do {	\
		stq_raw(a, s); \
		taintcheck_mem_clean(a, 8); \
	}while(0);

#define TD_ldub_raw(p) \
 	( \
      dump_physaddr_info(1, laddr((p))), \
      ldub_raw(p) \
    )

#define TD_ldsb_raw(p) \
        ( \
          dump_physaddr_info(1, laddr((p))), \
          ldsb_raw(p) \
        )

#define TD_lduw_raw(p) \
        ( \
          dump_physaddr_info(2, laddr((p))), \
          lduw_raw(p) \
        )

#define TD_ldsw_raw(p) \
        ( \
          dump_physaddr_info(2, laddr((p))), \
          ldsw_raw(p) \
        )

#define TD_ldl_raw(p) \
        ( \
          dump_physaddr_info(4, laddr((p))), \
          ldl_raw(p) \
        )

#define TD_ldq_raw(p) \
        ( \
          dump_physaddr_info(8, laddr((p))), \
          ldq_raw(p) \
        )

#define TD_stb_raw(p, v) \
    do { \
          stb_raw(saddr((p)), v); \
          dump_physaddr_info(1, laddr((p))); \
        }while(0);

#define TD_stw_raw(p, v) \
        do {    \
          stw_raw(p, v); \
          dump_physaddr_info(2, laddr((p))); \
        }while(0);

#define TD_stl_raw(p, v) \
        do { \
          stl_raw(p, v); \
          dump_physaddr_info(4, laddr((p))); \
        }while(0);

#define TD_stq_raw(p, v) \
        do { \
          stq_raw(p, v); \
          dump_physaddr_info(8, laddr((p))); \
        }while(0);
