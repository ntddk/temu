/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#ifndef _DISASM_PP_H
#define _DISASM_PP_H

#include "disasm.h"
#include <stdint.h>
#include <libiberty.h>
//#include <irtoir.h>

#ifdef __cplusplus

#include <iostream>
#include <sstream>

using namespace std;

void ostream_i386_register(int regnum, ostream &out);

void
ostream_i386_mnemonic(Instruction *inst, ostream &out);

void ostream_i386_insn(Instruction *inst, ostream &out);

extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
