/*
TEMU is Copyright (C) 2006-2010, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY.
*/

/// @file taintcheck.h
/// @author: Heng Yin
/// \defgroup taintcheck taintcheck: Dynamic Taint Analysis Engine

#ifndef _TAINTCHECK_H_INCLUDED_
#define _TAINTCHECK_H_INCLUDED_

//////////////////////////////////////////////////
// DEFINES 
//////////////////////////////////////////////////

/*! \typedef taint_operand_t
 This structure contains taint information for an operand (memory or register).
 @ingroup taintcheck
*/ 
typedef struct {
#define OPERAND_REG 0
#define OPERAND_MEM 1
#define OPERAND_NIC 2
#define OPERAND_DISK 3
  char type; 
  char size;
  uint8_t taint;
  uint32_t addr;
  uint8_t *records; 
} taint_operand_t;


extern uint64_t regs_bitmap;
extern uint8_t *regs_records;
extern uint64_t nic_bitmap[1024 * 32 / 64];
extern uint8_t *nic_records;
extern int insn_tainted;

#ifdef IMPACT_ANALYSIS
extern int impact_propagate;
#endif

/////////////////////////////////////////////////////////
// PROTOTYPES
/////////////////////////////////////////////////////////

/// Obtain taint information of a memory region by its physical address
///
/// @param addr physical address
/// @param size size of memory region
/// @param records the output buffer for storing taint records
/// @retval bitmap that indicates which bytes are tainted
///
/// @ingroup taintcheck
uint64_t taintcheck_memory_check(uint32_t addr, int size,
                                 uint8_t * records);

/// Obtain taint information of a register
///
/// @param reg index of a full register, such as R_EAX, R_EBX
/// @param offset offset within a full register, e.g., AH has offset 1
/// @param size register size, e.g., the size of AX is 2
/// @param records output buffer for storing taint records
/// @retval bitmap that indicates which bytes are tainted
///
/// @ingroup taintcheck
uint64_t taintcheck_register_check(int reg, int offset, int size,
                                   uint8_t * records);

/// Set taint information of a register
///
/// @param reg index of a full register, such as R_EAX, R_EBX
/// @param offset offset within a full register, e.g., AH has offset 1
/// @param size register size, e.g., the size of AX is 2
/// @param taint bitmap that indicates which bytes are tainted
/// @param records user-specified buffer for storing taint records
/// @retval always 0
///
/// @ingroup taintcheck
int taintcheck_taint_register(int reg, int offset, int size,
                              uint64_t taint, uint8_t * records);

/// Set taint information of a memory region by its physical address
///
/// @param addr physical address of memory region
/// @param size size of memory region
/// @param taint bitmap that indicates which bytes are tainted
/// @param records user-specified buffer for storing taint records
/// @retval always 0
///
/// @ingroup taintcheck
int taintcheck_taint_memory(uint32_t addr, int size, uint64_t taint, uint8_t * records);

/// Set taint information of a memory region by its virtual address
///
/// @param vaddr virtual address of memory region
/// @param size size of memory region
/// @param taint bitmap that indicates which bytes are tainted
/// @param records user-specified buffer for storing taint records
///
/// @ingroup taintcheck
void taintcheck_taint_virtmem(uint32_t vaddr, uint32_t size, uint64_t taint, void *records);

/// Obtain taint information of a memory region by its virtual address
///
/// @param vaddr virtual address of memory region
/// @param size size of memory region
/// @param records the output buffer for storing taint records
/// @retval bitmap that indicates which bytes are tainted
///
/// @ingroup taintcheck
uint64_t taintcheck_check_virtmem(uint32_t vaddr, uint32_t size, void *records);


/// This is the default taint_propagate implementation.
/// For a Temu plugin, if it does not need to handle it specially, 
/// it can specify this function in its callback function definitions
///
/// @param nr_src Number of source operands
/// @param src_oprnds source operand array
/// @param dst_oprnd destination operand
/// @param mode propagation mode
///
/// @ingroup taintcheck
void default_taint_propagate(int nr_src,
                            taint_operand_t * src_oprnds,
                            taint_operand_t * dst_oprnd,
                            int mode);

/// Get number of tainted bytes in the physcal memory
/// @retval number of tainted bytes
///
/// @ingroup taintcheck
int taintcheck_get_sizeof_taintmem();



int taintcheck_init();
int taintcheck_create();
void taintcheck_cleanup();
void taintcheck_bswap(int reg, int size);
void taintcheck_fn1reg(int reg, int size);
void taintcheck_clear_ones(int reg, int size, uint32_t val);
void taintcheck_clear_zeros(int reg, int size, uint32_t val);
void taintcheck_fn2regs(int sreg1, int sreg2, int dreg, int size);
void taintcheck_logic_T0_T1();
void taintcheck_fn3regs(int sreg1, int sreg2, int sreg3, int dreg, int size);
void taintcheck_mem2reg(void *ptr, int size, int reg);
void taintcheck_reg2mem(int reg, int size, void *ptr);
void taintcheck_reg2reg(int sreg, int dreg, int size);
void taintcheck_reg_clean(int reg);
void taintcheck_reg2reg_shift(int sregidx, int dregidx, int size);
void taintcheck_reg_clean2(int regidx, int size);
void taintcheck_mem_clean(void *ptr, int size);
void taintcheck_clean_memory(uint32_t phys_addr, int size);

int taintcheck_taint_disk(uint64_t index, uint64_t taint, int offset,
                          int size, uint8_t * record, void *bs);


int taintcheck_nic_writebuf(uint32_t addr, int size, uint64_t bitmap, uint8_t * records);       //size<=64
uint64_t taintcheck_nic_readbuf(uint32_t addr, int size, uint8_t * records);    //size<=64
int taintcheck_nic_in(uint32_t addr, int size);
int taintcheck_nic_out(uint32_t addr, int size);
int taintcheck_check_eip(uint32_t reg);

int taintcheck_jnz_T0_label( /*uint32_t t0 */ );
void taintcheck_jcc_target(uint32_t taken_eip, uint32_t not_taken_eip);

#ifdef DEFINE_EIP_TAINTED
int taintcheck_check_eip(uint32_t reg);
#endif
int taintcheck_patch();

int taintcheck_chk_hdread(uint32_t paddr, int size, int64_t sect_num,
                          void *s);
int taintcheck_chk_hdwrite(uint32_t paddr, int size, int64_t sect_num,
                           void *s);
int taintcheck_chk_hdin(int size, int64_t sect_num, uint32_t offset,
                        void *s);
int taintcheck_chk_hdout(int size, int64_t sect_num, uint32_t offset,
                         void *s);
void taintcheck_clean_memreg();

void taintcheck_reg2TN(int reg, int t, int size);
void taintcheck_regh2TN(int reg, int t);
uint32_t taintcheck_sidt(void);
void taintcheck_update_cr3();

#if TAINT_FLAGS
void taintcheck_update_eflags(uint32_t mask, int which);

#ifndef CPU_I386_H //copy from cpu.h
#define CC_C   	0x0001
#define CC_P 	0x0004
#define CC_A	0x0010
#define CC_Z	0x0040
#define CC_S    0x0080
#define CC_O    0x0800
#endif

static inline void taintcheck_update_all_eflags(int which) 
{
  taintcheck_update_eflags( CC_C|CC_P|CC_A|CC_Z|CC_S|CC_O, which);
}

void taintcheck_reg2flag(int regidx, int size, uint32_t mask);

void taintcheck_flag2reg(uint32_t mask, int regidx, int size);

#else
#define taintcheck_flag2reg(mask, regidx, size) \
	taintcheck_reg_clean2(regidx, size)

#endif

#define REG_ID(reg, ot) \
 (((ot) ==0 && (reg) > 3)?  ((reg) - 4) * 4 + 1 : (reg) * 4)


void taintcheck_mov_i2m();
void taintcheck_mov_m2r(int base, int index, int dreg_id);
void taintcheck_mov_r2m(int base, int index, int reg_id);

void taintcheck_code2TN(uint32_t vaddr, uint32_t regid, int size);

void do_info_taintmem(void);

#endif
