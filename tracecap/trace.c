/*
TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

As an additional exception, the XED and Sleuthkit libraries, including
updated or modified versions, are excluded from the requirements of
the LGPL as if they were standard operating system libraries.
*/

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <assert.h>
#include "TEMU_lib.h"
#include "trace.h"
#include "read_linux.h"
#include "operandinfo.h"
#include <xed-interface.h>
#include "disasm.h"
#include "tracecap.h"
#include "procmod.h"

/* Map to convert register numbers */
int regmapping[] = { -1, -1, -1, -1, -1, -1, -1, -1,
  R_EAX, R_ECX, R_EDX, R_EBX, R_ESP, R_EBP, R_ESI, R_EDI,
  R_EAX, R_ECX, R_EDX, R_EBX, R_EAX, R_ECX, R_EDX, R_EBX,
  R_EAX, R_ECX, R_EDX, R_EBX, R_ESP, R_EBP, R_ESI, R_EDI,
  R_EAX, R_ECX, R_EDX, R_EBX, R_ESP, R_EBP, R_ESI, R_EDI
};

/* Map from XED register numbers to
    0) Christopher's register numbers
    1) Regnum
*/
static int xed2chris_regmapping[XED_REG_LAST + 1][2];

static void init_xed2chris(void) {
  int (*x2c)[2] = xed2chris_regmapping;
  int i;
  for (i = 0; i <= XED_REG_LAST; i++)
    x2c[i][0] = x2c[i][1] = -1;
  x2c[XED_REG_EAX][0] = eax_reg; x2c[XED_REG_EAX][1] = R_EAX;
  x2c[ XED_REG_AX][0] =  ax_reg; x2c[ XED_REG_AX][1] = R_EAX;
  x2c[ XED_REG_AH][0] =  ah_reg; x2c[ XED_REG_AH][1] = R_EAX;
  x2c[ XED_REG_AL][0] =  al_reg; x2c[ XED_REG_AL][1] = R_EAX;
  x2c[XED_REG_ECX][0] = ecx_reg; x2c[XED_REG_ECX][1] = R_ECX;
  x2c[ XED_REG_CX][0] =  cx_reg; x2c[ XED_REG_CX][1] = R_ECX;
  x2c[ XED_REG_CH][0] =  ch_reg; x2c[ XED_REG_CH][1] = R_ECX;
  x2c[ XED_REG_CL][0] =  cl_reg; x2c[ XED_REG_CL][1] = R_ECX;
  x2c[XED_REG_EDX][0] = edx_reg; x2c[XED_REG_EDX][1] = R_EDX;
  x2c[ XED_REG_DX][0] =  dx_reg; x2c[ XED_REG_DX][1] = R_EDX;
  x2c[ XED_REG_DH][0] =  dh_reg; x2c[ XED_REG_DH][1] = R_EDX;
  x2c[ XED_REG_DL][0] =  dl_reg; x2c[ XED_REG_DL][1] = R_EDX;
  x2c[XED_REG_EBX][0] = ebx_reg; x2c[XED_REG_EBX][1] = R_EBX;
  x2c[ XED_REG_BX][0] =  bx_reg; x2c[ XED_REG_BX][1] = R_EBX;
  x2c[ XED_REG_BH][0] =  bh_reg; x2c[ XED_REG_BH][1] = R_EBX;
  x2c[ XED_REG_BL][0] =  bl_reg; x2c[ XED_REG_BL][1] = R_EBX;
  x2c[XED_REG_ESP][0] = esp_reg; x2c[XED_REG_ESP][1] = R_ESP;
  x2c[ XED_REG_SP][0] =  sp_reg; x2c[ XED_REG_SP][1] = R_ESP;
  x2c[XED_REG_EBP][0] = ebp_reg; x2c[XED_REG_EBP][1] = R_EBP;
  x2c[ XED_REG_BP][0] =  bp_reg; x2c[ XED_REG_BP][1] = R_EBP;
  x2c[XED_REG_ESI][0] = esi_reg; x2c[XED_REG_ESI][1] = R_ESI;
  x2c[ XED_REG_SI][0] =  si_reg; x2c[ XED_REG_SI][1] = R_ESI;
  x2c[XED_REG_EDI][0] = edi_reg; x2c[XED_REG_EDI][1] = R_EDI;
  x2c[ XED_REG_DI][0] =  di_reg; x2c[ XED_REG_DI][1] = R_EDI;
  x2c[ XED_REG_CS][0] =  cs_reg;
  x2c[ XED_REG_DS][0] =  ds_reg;
  x2c[ XED_REG_ES][0] =  es_reg;
  x2c[ XED_REG_SS][0] =  ss_reg;
  x2c[ XED_REG_FS][0] =  fs_reg;
  x2c[ XED_REG_GS][0] =  gs_reg;
}

/* Buffer to store instructions */
char filebuf[FILEBUFSIZE];

/* Trace statistics */
struct trace_stats tstats = {0};

/* This flags we might want to put as part of the EntryHeader without 
 * writing to file */
int has_page_fault = 0;
int access_user_mem = 0;
int insn_already_written = 0;

/* Variables to keep disassembler state */
xed_state_t dstate;
xed_decoded_inst_t xedd;

/* Flag to signal that no writing should be done */
int trace_do_not_write = 0;

/* Variable to signal that only writing certain thread (ignore if -1) */
unsigned int tid_to_trace = -1;

/* Flag to indicate that header has been written to file */
int header_already_written = 0;

/* XED2 initialization */
void xed2_init() {
  xed_tables_init ();
  xed_state_zero (&dstate);

  xed_state_init(&dstate,
    XED_MACHINE_MODE_LEGACY_32,
    XED_ADDRESS_WIDTH_32b,
    XED_ADDRESS_WIDTH_32b);

}

/* Get register number */
inline int get_regnum(OperandVal op) {
  if (op.type != TRegister) return -1;
  return regmapping[op.addr - 100];
}

/* Print the statistics variables */
void print_trace_stats() {
  term_printf("Number of instructions decoded: %ld\n", 
    tstats.insn_counter_decoded);
  term_printf("Number of operands decoded: %ld\n", 
    tstats.operand_counter);
  term_printf("Number of instructions written to trace: %ld\n",
    tstats.insn_counter_traced);
  term_printf("Number of tainted instructions written to trace: %ld\n",
    tstats.insn_counter_traced_tainted);
}

/* Clear trace statistics */
void clear_trace_stats() {
  memset(&tstats, 0, sizeof(struct trace_stats));
}

/* Return the offset of the operand. Zero except for AH,BH,CH,DH that is one */
inline int getOperandOffset (OperandVal *op) {
  if ((op->type == TRegister) && ((op->addr >= ah_reg) && (op->addr <= bh_reg)))
    return 1;

  return 0;
}

/* This is the central function
  Given a memory address, reads a bunch of memory bytes and
    calls the disassembler to obtain the information
  Then it stores the information into the eh EntryHeader
*/
void decode_address(uint32_t address, EntryHeader *eh, int ignore_taint)
{
  unsigned char insn_buf[MAX_INSN_BYTES];
  unsigned int is_stackpush = 0, is_stackpop = 0;
  unsigned int stackpushpop_acc = 0;

  if (xed2chris_regmapping[XED_REG_EAX][0] == 0) {
    init_xed2chris();
    assert(xed2chris_regmapping[XED_REG_EAX][0] != 0);
  }

  /* Read memory from TEMU */
  TEMU_read_mem(address, MAX_INSN_BYTES, insn_buf);

  /* Disassemble instruction buffer */
  xed_decoded_inst_zero_set_mode(&xedd, &dstate);
  xed_error_enum_t xed_error =
    xed_decode(&xedd, STATIC_CAST(const xed_uint8_t*,insn_buf), MAX_INSN_BYTES);
  xed_bool_t okay = (xed_error == XED_ERROR_NONE);
  if (!okay) return;

  // Increase counters
  tstats.insn_counter_decoded++;

  int i;

  /* Clear out Entry header */
  memset(eh, 0, sizeof(EntryHeader));

  /* Copy the address and instruction size */
  eh->address = address;
  eh->inst_size = xed_decoded_inst_get_length(&xedd);
  if (eh->inst_size > MAX_INSN_BYTES) eh->inst_size = MAX_INSN_BYTES;

  /* Copy instruction rawbytes */
  memcpy(eh->rawbytes, insn_buf, eh->inst_size);

  /* Get the number of XED operands */
  const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
  int xed_ops = xed_inst_noperands(xi);
  int op_idx = -1;

  /* Get the category of the instruction */
  xed_category_enum_t category = xed_decoded_inst_get_category(&xedd);

  /* Iterate over the XED operands */
  for(i = 0; i < xed_ops; i++) {
  	if(op_idx >= MAX_NUM_OPERANDS)
  	  break;
    //assert(op_idx < MAX_NUM_OPERANDS);

    /* Get operand */
    const xed_operand_t* op = xed_inst_operand(xi,i);
    xed_operand_enum_t op_name = xed_operand_name(op);

    switch(op_name) {
      /* Register */
      case XED_OPERAND_REG0:
      case XED_OPERAND_REG1:
      case XED_OPERAND_REG2:
      case XED_OPERAND_REG3:
      case XED_OPERAND_REG4:
      case XED_OPERAND_REG5:
      case XED_OPERAND_REG6:
      case XED_OPERAND_REG7:
      case XED_OPERAND_REG8:
      case XED_OPERAND_REG9:
      case XED_OPERAND_REG10:
      case XED_OPERAND_REG11:
      case XED_OPERAND_REG12:
      case XED_OPERAND_REG13:
      case XED_OPERAND_REG14:
      case XED_OPERAND_REG15: {
        xed_reg_enum_t reg_id = xed_decoded_inst_get_reg(&xedd, op_name);
        int regnum = xed2chris_regmapping[reg_id][1];

        // Special handling for Push
        if (reg_id == XED_REG_STACKPUSH) is_stackpush = 1;
        else if (reg_id == XED_REG_STACKPOP) is_stackpop = 1;

        if (-1 == regnum)
          break;
        else {
	  op_idx++;
          eh->num_operands++;
          eh->operand[op_idx].type = TRegister;
          eh->operand[op_idx].addr = xed2chris_regmapping[reg_id][0];
	  eh->operand[op_idx].length = 
	    (uint8_t) xed_decoded_inst_operand_length (&xedd, i);
	  eh->operand[op_idx].access = (uint8_t) xed_operand_rw (op);
          eh->operand[op_idx].value = TEMU_cpu_regs[regnum];
          switch (eh->operand[op_idx].addr) {
            case ax_reg:
            case bx_reg:
            case cx_reg:
            case dx_reg:
            case bp_reg:
            case sp_reg:
            case si_reg:
            case di_reg:
              eh->operand[op_idx].value &= 0xFFFF;
              break;
            case al_reg:
            case bl_reg:
            case cl_reg:
            case dl_reg:
              eh->operand[op_idx].value &= 0xFF;
              break;
            case ah_reg:
            case bh_reg:
            case ch_reg:
            case dh_reg:
              eh->operand[op_idx].value = (eh->operand[i].value & 0xFF00) >> 8;
              break;
            default:
              break;
          }
        }
        if (ignore_taint == 0) set_operand_data(&(eh->operand[op_idx]));
        break;
      }

      /* Immediate */
      case XED_OPERAND_IMM0: {
        op_idx++;
        eh->num_operands++;
        eh->operand[op_idx].type = TImmediate;
	eh->operand[op_idx].length = 
	  (uint8_t) xed_decoded_inst_operand_length (&xedd, i);
	eh->operand[op_idx].access = (uint8_t) xed_operand_rw (op);
        //xed_uint_t width = xed_decoded_inst_get_immediate_width(&xedd);
        if (xed_decoded_inst_get_immediate_is_signed(&xedd)) {
          xed_int32_t signed_imm_val = 
	    xed_decoded_inst_get_signed_immediate(&xedd);
          eh->operand[op_idx].value = (uint32_t) signed_imm_val;
        }
        else {
          xed_uint64_t unsigned_imm_val =
            xed_decoded_inst_get_unsigned_immediate(&xedd);
          eh->operand[op_idx].value = (uint32_t) unsigned_imm_val;
        }
        break;
      break;
      }
      /* Special immediate only used in ENTER instruction */
      case XED_OPERAND_IMM1: {
        op_idx++;
        eh->num_operands++;
        eh->operand[op_idx].type = TImmediate;
	eh->operand[op_idx].length = 
	  (uint8_t) xed_decoded_inst_operand_length (&xedd, i);
	eh->operand[op_idx].access = (uint8_t) xed_operand_rw (op);
        xed_uint8_t unsigned_imm_val = 
	  xed_decoded_inst_get_second_immediate(&xedd);
        eh->operand[op_idx].value = (uint32_t) unsigned_imm_val;
        break;
      }


      /* Memory */
      case XED_OPERAND_AGEN:
      case XED_OPERAND_MEM0:
      case XED_OPERAND_MEM1: {
	unsigned long base = 0;
	unsigned long index = 0;
	unsigned long scale = 1;
	unsigned long segbase = 0;
	unsigned short segsel = 0;
	unsigned long displacement = 0;
	unsigned int j;
	size_t remaining = 0;

	/* Set memory index */
        int mem_idx = 0;
        if (op_name == XED_OPERAND_MEM1) mem_idx = 1;

	unsigned int memlen = xed_decoded_inst_operand_length (&xedd, i);

	for (j = 0; j < memlen; j+=4) {
	  /* Initialization */
	  base = 0;
	  index = 0;
	  scale = 1;
	  segbase = 0;
	  segsel = 0;
	  displacement = 0;
	  remaining = memlen - j;

	  op_idx++;
	  if(op_idx >= MAX_NUM_OPERANDS)
	    break;
	  //assert(op_idx < MAX_NUM_OPERANDS);
	  eh->num_operands++;
	  eh->operand[op_idx].type = TMemLoc;
	  eh->operand[op_idx].access = (uint8_t) xed_operand_rw (op);
	  eh->operand[op_idx].length = 
	    remaining > 4 ? 4 : (uint8_t) remaining;

	  // Get Segment register
	  xed_reg_enum_t seg_regid = 
	    xed_decoded_inst_get_seg_reg(&xedd,mem_idx);

	  if (seg_regid != XED_REG_INVALID) {
	    const xed_operand_values_t *xopv = 
	      xed_decoded_inst_operands_const(&xedd);
	    xed_bool_t default_segment = 
	      xed_operand_values_using_default_segment (xopv,mem_idx);

	    if (!default_segment) {
	      eh->num_operands++;
	      int segmentreg = xed2chris_regmapping[seg_regid][0] - 100;

	      segbase = TEMU_cpu_segs[segmentreg].base;
	      segsel = TEMU_cpu_segs[segmentreg].selector;

	      eh->memregs[op_idx][0].type = TRegister;
	      eh->memregs[op_idx][0].length = 2;
	      eh->memregs[op_idx][0].addr = xed2chris_regmapping[seg_regid][0];
	      eh->memregs[op_idx][0].access = (uint8_t) XED_OPERAND_ACTION_R;
	      eh->memregs[op_idx][0].value = segsel;
	      eh->memregs[op_idx][0].usage = memsegment;
	      if (ignore_taint == 0) 
		set_operand_data(&(eh->memregs[op_idx][0]));

	      int dt;
	      if (segsel & 0x4)       // ldt
		dt = TEMU_cpu_ldt->base;
	      else                    //gdt
		dt = TEMU_cpu_gdt->base;
	      segsel = segsel >> 3;

	      unsigned long segent = dt + 8 * segsel;
	      unsigned char segdes[8];
	      TEMU_read_mem(segent, 8, segdes);

#if 0
	      // debugging code to double check segbase value
	      unsigned long segbasenew = segdes[2] + segdes[3] * 256 +
	      segdes[4] * 256 * 256 + segdes[7] * 256 * 256 * 256;
	      if (segbase != segbasenew) {
		term_printf("segbase unexpected: 0x%08lX v.s 0x%08lX\n",
			segbase, segbasenew);
	      }
#endif
	      /* Segment descriptor is stored as a memory operand */
	      eh->num_operands+=2;
	      eh->memregs[op_idx][3].type = TMemLoc;
	      eh->memregs[op_idx][3].length = 4;
	      eh->memregs[op_idx][3].addr = segent;
	      eh->memregs[op_idx][3].access = 
		(uint8_t) XED_OPERAND_ACTION_INVALID;
	      eh->memregs[op_idx][3].value = *(uint32_t *) segdes;
	      eh->memregs[op_idx][3].tainted = 0;
	      eh->memregs[op_idx][3].usage = memsegent0;

	      eh->memregs[op_idx][4].type = TMemLoc;
	      eh->memregs[op_idx][4].length = 4;
	      eh->memregs[op_idx][4].addr = segent + 4;
	      eh->memregs[op_idx][4].access = 
		(uint8_t) XED_OPERAND_ACTION_INVALID;
	      eh->memregs[op_idx][4].value = *(uint32_t *) (segdes + 4);
	      eh->memregs[op_idx][4].tainted = 0;
	      eh->memregs[op_idx][4].usage = memsegent1;
	    }
	  }

	  // Get Base register
	  xed_reg_enum_t base_regid = 
	    xed_decoded_inst_get_base_reg(&xedd,mem_idx);
	  if (base_regid != XED_REG_INVALID) {
	    eh->num_operands++;
	    int basereg = xed2chris_regmapping[base_regid][1];
	    base = TEMU_cpu_regs[basereg];
	    eh->memregs[op_idx][1].type = TRegister;
	    eh->memregs[op_idx][1].addr = xed2chris_regmapping[base_regid][0];
	    eh->memregs[op_idx][1].length = 4;
	    eh->memregs[op_idx][1].access = (uint8_t) XED_OPERAND_ACTION_R;
	    eh->memregs[op_idx][1].value = base;
	    eh->memregs[op_idx][1].usage = membase;
	    if (ignore_taint == 0) set_operand_data(&(eh->memregs[op_idx][1]));
	  }
	  // Get Index register and Scale
	  xed_reg_enum_t index_regid = 
	    xed_decoded_inst_get_index_reg(&xedd,mem_idx);
	  if (mem_idx == 0 && index_regid != XED_REG_INVALID) {
	    eh->num_operands++;
	    int indexreg = xed2chris_regmapping[index_regid][1];
	    index = TEMU_cpu_regs[indexreg];
	    eh->memregs[op_idx][2].type = TRegister;
	    eh->memregs[op_idx][2].addr = xed2chris_regmapping[index_regid][0];
	    eh->memregs[op_idx][2].length = 4;
	    eh->memregs[op_idx][2].access = (uint8_t) XED_OPERAND_ACTION_R;
	    eh->memregs[op_idx][2].value = index;
	    eh->memregs[op_idx][2].usage = memindex;
	    if (ignore_taint == 0) set_operand_data(&(eh->memregs[op_idx][2]));

	    // Get Scale (AKA width) (only have a scale if the index exists)
	    if (xed_decoded_inst_get_scale(&xedd,i) != 0) {
	      scale = (unsigned long) xed_decoded_inst_get_scale(&xedd,mem_idx);
	    }
	  }
	  // Get displacement (AKA offset)
	  displacement = 
	    (unsigned long) xed_decoded_inst_get_memory_displacement
	    (&xedd,mem_idx);

	  // Fix displacement for:
	  //   1) Any instruction that pushes into the stack, since ESP is 
	  //        decremented before memory operand is written using ESP. 
	  //        Affects: ENTER,PUSH,PUSHA,PUSHF,CALL
	  if (is_stackpush) {
            stackpushpop_acc += eh->operand[op_idx].length;
            displacement = displacement - stackpushpop_acc -j;
	  }
	  //   2) Pop instructions where the 
	  //      destination operand is a memory location that uses ESP 
	  //        as base or index register. 
	  //      The pop operations increments ESP and the written memory 
	  //        location address needs to be adjusted.
	  //      Affects: pop (%esp)
	  else if ((category == XED_CATEGORY_POP) && (!is_stackpop)) {
	    if ((eh->memregs[op_idx][1].addr == esp_reg) || 
		(eh->memregs[op_idx][2].addr == esp_reg)) 
	    {
	      displacement = displacement + eh->operand[op_idx].length;
	    }
	  }

	  // Calculate memory address accessed
	  eh->operand[op_idx].addr =
	    j + segbase + base + index * scale + displacement;

	  // Special handling for LEA instructions
	  if (op_name == XED_OPERAND_AGEN) {
	    eh->operand[op_idx].type = TMemAddress;
	    eh->operand[op_idx].length = 4;
	    has_page_fault = 0; // LEA won't trigger page fault
	  }
	  else {
	    has_page_fault = TEMU_read_mem(eh->operand[op_idx].addr,
	      (int)(eh->operand[op_idx].length), 
	      (uint8_t *)&(eh->operand[op_idx].value));
	  }

	  // Check if instruction accesses user memory
	  // kernel_mem_start defined in shared/read_linux.c
	  if ((eh->operand[op_idx].addr < kernel_mem_start) &&
	    (op_name != XED_OPERAND_AGEN))
	  {
	    access_user_mem = 1;
	  }
	  if (ignore_taint == 0) set_operand_data(&(eh->operand[op_idx]));
	}
	break;
      }

      /* Jumps */
      case XED_OPERAND_PTR:  // pointer (always in conjunction with a IMM0)
      case XED_OPERAND_RELBR: { // branch displacements
          xed_uint_t disp = xed_decoded_inst_get_branch_displacement(&xedd);
	  /* Displacement is from instruction end */
	  /* Adjust displacement with instruction size */
	  disp = disp + eh->inst_size;
	  op_idx++;
	  eh->num_operands++;
	  eh->operand[op_idx].type = TJump;
	  eh->operand[op_idx].length = 4;
	  eh->operand[op_idx].access = (uint8_t) xed_operand_rw (op);
	  eh->operand[op_idx].value = disp;
          break;
      }

      /* Floating point registers */
      case XED_REG_X87CONTROL:
      case XED_REG_X87STATUS:
      case XED_REG_X87TOP:
      case XED_REG_X87TAG:
      case XED_REG_X87PUSH:
      case XED_REG_X87POP:
      case XED_REG_X87POP2:
          op_idx++;
          eh->num_operands++;
          eh->operand[op_idx].type = TFloatRegister;
          eh->operand[op_idx].length = 4;
	  eh->operand[op_idx].access = (uint8_t) xed_operand_rw (op);
      default:
        break;
     }
  }

  /* Increment the operand counter without including ESP */
  tstats.operand_counter += eh->num_operands;

  /* Remainig fields in EntryHeader */
  eh->eflags = 0; /* Gets updated at insn_end */
  eh->df = 0; /* Gets updated at insn_end */

  eh->cc_op = *TEMU_cc_op;

//  free(inst);

}

#ifdef INSN_INFO
long savedeip;
#endif

/* Output function
   Writes an operand structure to the given file
*/
unsigned int write_operand(FILE *stream, OperandVal op) {
  unsigned int i = 0;
  unsigned int num_elems_written = 0;

  if (stream == NULL) return 0;

  /* Write fixed part of operand */
  num_elems_written += fwrite(&op, OPERAND_VAL_FIXED_SIZE, 1, stream);

  /* Write enums */
  uint16_t enums = (((uint16_t) op.usage) << 8) | ((uint16_t) op.type);
  num_elems_written += fwrite(&enums, OPERAND_VAL_ENUMS_REAL_SIZE, 1, stream);

  /* For each byte in the operand, check if tainted.
      If tainted, write taint record */
  assert(op.length <= MAX_OPERAND_LEN);
  for (i = 0; i < op.length; i++) {
    if (op.tainted & (1 << i)) {
      /* Write fixed part of taint_record */
      num_elems_written += 
	fwrite(&(op.records[i]), TAINT_RECORD_FIXED_SIZE, 1, stream);

      /* Write only the non-empty taint_byte_record */
      assert(op.records[i].numRecords <= MAX_NUM_TAINTBYTE_RECORDS);
      num_elems_written += fwrite(&(op.records[i].taintBytes), 
	sizeof(TaintByteRecord), op.records[i].numRecords, stream);
    }
  }
  return num_elems_written;
}

/* Output function
   Writes an EntryHeader to the given file
*/
unsigned int write_insn(FILE *stream, EntryHeader *eh)
{
  unsigned int num_elems_written = 0;

  /* If trace_do_not_write is set, ignore write */
  if (trace_do_not_write) return 0;

  /* If no stream or no instruction, ignore write */
  if ((stream == NULL) || (eh == NULL)) return 0;

  /* If tid_to_trace is set, write only if we're in the thread tid */
  if (tid_to_trace != -1 && tid_to_trace != eh->tid) return 0;

  /* If trace header still not written, write it 
   * Delaying writing the header till here allows to get more module
   * information when tracing a process by name */
  if (header_already_written == 0) {
    /* writing the trace header */
    TraceHeader th;
    th.magicnumber = MAGIC_NUMBER;
    th.version = VERSION_NUMBER;
    th.n_procs = 1;
    th.gdt_base = TEMU_cpu_gdt->base;
    th.idt_base = TEMU_cpu_idt->base;
    num_elems_written += fwrite(&th, sizeof(th), 1, stream);

    /* Set flag */
    header_already_written = 1;

    /* for each process */
    ProcRecord pr;
    memset(&pr,0,sizeof(ProcRecord));
    pr.n_mods = find_process(tracecr3, pr.name, &pr.pid);

    old_modinfo_t *pmr = 
      (old_modinfo_t *) malloc(pr.n_mods * sizeof(old_modinfo_t));
    if (pmr) {
      get_proc_modules(pr.pid, pmr, pr.n_mods);
    }
    else {
      pr.n_mods = -1;
    }
    pr.ldt_base = TEMU_cpu_ldt->base;

    num_elems_written += fwrite(&pr, sizeof(pr), 1, stream);

    if (pmr) {
      int i;
      ModuleRecord mr;
      for (i = 0; i < pr.n_mods; i++) {
        strncpy(mr.name, pmr[i].name, MAX_STRING_LEN);
        mr.base = pmr[i].base;
        mr.size = pmr[i].size;
        num_elems_written += fwrite(&mr, sizeof(mr), 1, stream);
      }
      free(pmr);
    }
    fflush(tracelog);
  }

  if (stream && (eh->inst_size > 0)) {

    /* Write fixed part of entry header */
    num_elems_written += fwrite(eh, ENTRY_HEADER_FIXED_SIZE, 1, stream);

    /* Write rawbytes */
    num_elems_written += fwrite(&(eh->rawbytes), eh->inst_size, 1, stream);

    /* Write remaining operands */
    int i = 0,j = 0;
    while ((eh->operand[i].type != TNone) && (i < MAX_NUM_OPERANDS)) {
      write_operand(stream, eh->operand[i]);

      /* For Memory operands, need to write memregs and segent's */
      if ((eh->operand[i].type == TMemLoc) ||
	(eh->operand[i].type == TMemAddress))
      {
	/* Write Memregs operands */
	for (j = 0; j < MAX_NUM_MEMREGS; j++) {
	  if (eh->memregs[i][j].type != TNone) {
	    write_operand(stream, eh->memregs[i][j]);
	  }
	}
      }
      i++;
    }

    insn_already_written = 1;
    tstats.insn_counter_traced++;
#if TAINT_ENABLED    
    if (insn_tainted) tstats.insn_counter_traced_tainted++;
#endif
    /* Avoid flushing to improve performance */
    //fflush(stream);

#ifdef INSN_INFO
    char name[MAX_STRING_LEN];
    uint32_t offset;
    char insninfostr[256];
    insninfostr[0] = 0;
    checkcr3(temu_plugin->monitored_cr3, savedeip, tracepid, name, 
      MAX_STRING_LEN, &offset);
    snprintf(insninfostr, sizeof(insninfostr),
      "EIP = 0x%08lx, Module = %s, Offset = %ud", savedeip, name, offset);
    fprintf(infolog, "%s\n", insninfostr);
#endif
  }

  return num_elems_written;
}
