/*
TEMU is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.
*/

#ifndef __DISASM_H__
#define __DISASM_H__

enum OpType { TNone = 0, TRegister, TMemLoc, TImmediate, TJump, TFloatRegister, TMemAddress };

/* PREFIX flags */
#define PREFIX_REPZ 1
#define PREFIX_REPNZ 2
#define PREFIX_LOCK 4
#define PREFIX_CS 8
#define PREFIX_SS 0x10
#define PREFIX_DS 0x20
#define PREFIX_ES 0x40
#define PREFIX_FS 0x80
#define PREFIX_GS 0x100
#define PREFIX_OP 0x200
#define PREFIX_ADDR 0x400
#define PREFIX_FWAIT 0x800
#define PREFIX_TAKEN 0x1000
#define PREFIX_NOT_TAKEN 0x2000


/*** Address Modes ***/

#define b_mode 1  /* byte operand */
#define w_mode 2  /* word operand */
#define d_mode 3  /* double word operand  */

#define v_mode 5  /* operand size depends on prefixes */


/*** Define Registers ***/

/* segment registers */
#define es_reg 100
#define cs_reg 101
#define ss_reg 102
#define ds_reg 103
#define fs_reg 104
#define gs_reg 105

/* address-modifier dependent registers */
#define eAX_reg 108
#define eCX_reg 109
#define eDX_reg 110
#define eBX_reg 111
#define eSP_reg 112
#define eBP_reg 113
#define eSI_reg 114
#define eDI_reg 115

/* 8-bit registers */
#define al_reg 116
#define cl_reg 117
#define dl_reg 118
#define bl_reg 119
#define ah_reg 120
#define ch_reg 121
#define dh_reg 122
#define bh_reg 123

/* 16-bit registers */
#define ax_reg 124
#define cx_reg 125
#define dx_reg 126
#define bx_reg 127
#define sp_reg 128
#define bp_reg 129
#define si_reg 130
#define di_reg 131

/* 32-bit registers */
#define eax_reg 132
#define ecx_reg 133
#define edx_reg 134
#define ebx_reg 135
#define esp_reg 136
#define ebp_reg 137
#define esi_reg 138
#define edi_reg 139


#define indir_dx_reg 150

#endif
