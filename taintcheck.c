/*
TEMU is Copyright (C) 2006-2010, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY.
*/

/********************************************************************
 * @brief This file contains the major functionality of maintaining taint 
 * information in registers and memory and devices (like NIC and HD).
 */


#include <dlfcn.h>
#include <assert.h>
#include <sys/queue.h>
#include "hw/hw.h"
#include "qemu-common.h"
#include "sysemu.h"
#include "hw/hw.h" /* {de,}register_savevm */
#include "taintcheck.h"
#include "TEMU_main.h"

#if TAINT_ENABLED

#define TAINTCHECK_DEBUG 0

#ifdef IMPACT_ANALYSIS
int impact_propagate = 1;
#endif

#define min(X,Y) ((X) < (Y) ? (X) : (Y))

/*!
 An internal data structure for holding 64-byte taint information in memory
 */
typedef struct _tpage_entry {
  uint64_t bitmap;              /*!<one bit for each byte. */
  uint8_t records[0];           /*!<stores taint records defined by plugin. */
} tpage_entry_t;

uint64_t regs_bitmap = 0; //!<bitmap for registers
uint8_t *regs_records = NULL; //!<taint records for registers
static tpage_entry_t **tpage_table = NULL; //!<memory page table

uint64_t nic_bitmap[1024 * 32 / 64]; //!<bitmap for nic
uint8_t *nic_records = NULL; //!<taint records for nic

#if TAINT_FLAGS
uint32_t eflags_bitmap = 0; //!<bitmap for eflags
uint8_t * eflags_records = NULL; //!<taint records for eflags
#endif

int taintcheck_keyorigin = 0;
int insn_tainted = 0; //!<flag that indicates if the current instruction propagates taint

static inline uint64_t size_to_taint(int size)  //size<=64
{
  return (size < 64) ? (1ULL << size) - 1 : (uint64_t) (-1);
}


static inline uint8_t taint_reg_check(int regidx, int size)
{
  return ((1ULL << size) - 1) & (regs_bitmap >> regidx);
}

///fast version memory taint check, without boundary check
static inline uint64_t fast_taint_mem_check(uint32_t addr, int size)
{
  tpage_entry_t * entry = tpage_table[addr>>6];
  return entry? (entry->bitmap >> (addr &63)) & size_to_taint(size): 0; 
}

static inline uint64_t taint_mem_check(uint32_t addr, int size) //size <=64
{
  uint32_t margin = 64 - (addr & 63);
  if(size <= margin)
    return fast_taint_mem_check(addr, size);
  
  uint64_t taint = fast_taint_mem_check(addr, margin);
  taint |= (fast_taint_mem_check(addr + margin, size - margin) << margin); 
  return taint;
}

static void fast_taint_memory(uint32_t addr, int size, uint64_t taint)
{
  uint32_t index = addr >> 6;
  tpage_entry_t *entry = tpage_table[index];
  if(entry == NULL) {
    if(taint == 0)
      return;
    entry = (tpage_entry_t *)qemu_mallocz(
		sizeof(tpage_entry_t) + 64 * temu_plugin->taint_record_size);
    if(!entry) {
      fprintf(stderr, "out of memory \n");
      return;
    } 
    tpage_table[index] = entry;
    entry->bitmap = taint << (addr & 63);
  } else {
    uint32_t offset = addr & 63;
    entry->bitmap &= ~(size_to_taint(size) << offset);
    entry->bitmap |= (taint << offset);
    if (entry->bitmap == 0) {
      qemu_free(entry);
      tpage_table[index] = NULL;
    }
  }
}


static void taint_memory(uint32_t addr, int size, uint64_t taint)
{
  uint32_t margin = 64 - (addr & 63);

  if(size <= margin)
    fast_taint_memory(addr, size, taint);
  else {
    fast_taint_memory(addr, margin, taint & size_to_taint(margin));
    fast_taint_memory(addr+margin, size-margin, taint>>margin);
  }
}

static void fast_clean_memory(uint32_t addr, int size)
{
  tpage_entry_t *entry;
  uint32_t index = addr >> 6;
  if((entry = tpage_table[index])) {
    uint32_t offset = addr & 63;
#if 0 //def MEM_CLEAN
    uint64_t taint = (entry->bitmap >> offset) & size_to_taint(size);
    if(taint) 
      temu_plugin->mem_clean(addr, size, taint, 
		entry->records+offset*temu_plugin->taint_record_size);
#endif
    entry->bitmap &= ~(size_to_taint(size) << offset);
    if (entry->bitmap == 0) {
      qemu_free(entry);
      tpage_table[index] = NULL;
    }
  }
}

static void clean_memory(uint32_t addr, int size) //size <= 64
{
  uint32_t margin = 64 - (addr&63);

  if(size <= margin) 
    fast_clean_memory(addr, size);
  else {
    fast_clean_memory(addr, margin);
    fast_clean_memory(addr + margin, size - margin);
  }
}


static inline void taint_register(int regidx, int size, uint64_t taint)
{
#ifdef STACK_REGISTER_NO_TAINT
  if(regidx >= 16 && regidx <24) return; 
#endif
  uint64_t mask = (1ULL << size) - 1;
  regs_bitmap &= ~(mask << regidx);
  regs_bitmap |= (taint & mask) << regidx;
}

static inline void clean_register(int regidx, int size)
{
  uint64_t mask = (1ULL << size) - 1;
  regs_bitmap &= ~(mask << regidx);
}

static inline uint8_t clear_zero(uint32_t value, int size, uint8_t taint)       //size<=4
{
#if 1
  int i;
  uint32_t v = 0xff;
  uint8_t taint2 = taint;

  for (i = 0; i < size; i++, v <<= 8) {
    if ((value & v) == 0)
      taint2 &= ~(1 << i);
  }
  return taint2;
#endif
//  if (!value)
//    return 0;
  return taint;
}

/// Propagate taint info from register to memory
void __attribute__((fastcall)) taintcheck_reg2mem(int regidx, int size, void *ptr)
{
  if(!TEMU_emulation_started) return;

  uint32_t addr = (uint8_t *) ptr - phys_ram_base;
  if(__builtin_expect(addr >= ram_size, 0)) return;

#ifdef REG_CHECK
  temu_plugin->reg_read(regidx, size);
#endif

#ifdef PRE_MEM_WRITE
  temu_plugin->pre_mem_write(cpu_single_env->regs[R_A0], addr, size);
#endif


#ifndef NO_PROPAGATE
  uint8_t taint;
  uint32_t offset = addr & 63;

  if (offset + size <= 64) {
    taint = taint_reg_check(regidx, size);
#ifdef TAINTCHECK_CLEAR_ZERO
    if (taint)
      taint = clear_zero(cpu_single_env->regs[regidx >> 2] >> (regidx & 3),
                       size, taint);
#endif

    if(taint) {
      fast_taint_memory(addr, size, taint);
      insn_tainted = 1;
      taint_operand_t src, dst;
      src.type = 0; dst.type = 1;
      src.size = dst.size = size;
      dst.taint = src.taint = taint;
      src.addr = regidx, dst.addr = addr;
      src.records =
        regs_records + regidx * temu_plugin->taint_record_size;
      dst.records =
        tpage_table[addr >> 6]->records + offset * temu_plugin->taint_record_size;
      temu_plugin->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
    } else
      fast_clean_memory(addr, size);
  } else {
    int size1 = 64-offset, size2 = size - size1;
    taint = taint_reg_check(regidx, size1);
#ifdef TAINTCHECK_CLEAR_ZERO
    if (taint)
      taint = clear_zero(cpu_single_env->regs[regidx >> 2] >> (regidx & 3),
                       size1, taint);
#endif

    if(taint) {
      fast_taint_memory(addr, size1, taint);
      insn_tainted = 1;
      taint_operand_t src, dst;
      src.type = 0; dst.type = 1;
      src.size = dst.size = size1;
      dst.taint = src.taint = taint;
      src.addr = regidx, dst.addr = addr;
      src.records =
        regs_records + regidx * temu_plugin->taint_record_size;
      dst.records =
        tpage_table[addr >> 6]->records + offset * temu_plugin->taint_record_size;
      temu_plugin->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
    } else 
      fast_clean_memory(addr, size1);

    taint = taint_reg_check(regidx+size1, size2);
#ifdef TAINTCHECK_CLEAR_ZERO
    if (taint)
      taint = clear_zero(cpu_single_env->regs[regidx >> 2] >> ((regidx+size1)& 3),
                       size2, taint);
#endif
    if(taint) {
      fast_taint_memory(addr+size1, size2, taint);
      insn_tainted = 1;
      taint_operand_t src, dst;
      src.type = 0; dst.type = 1;
      src.size = dst.size = size2;
      dst.taint = src.taint = taint;
      src.addr = regidx + size1, dst.addr = addr + size1;
      src.records =
        regs_records + (regidx+size1)*temu_plugin->taint_record_size;
      dst.records = tpage_table[(addr>>6)+1]->records;
      temu_plugin->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
    } else 
      fast_clean_memory(addr+size1, size2);
  }
#endif //NO_PROPAGATE

#ifdef MEM_CHECK
  temu_plugin->mem_write(cpu_single_env->regs[R_A0], addr, size);
#endif
}


void __attribute__((fastcall)) taintcheck_mem2reg(void *ptr, int size, int regidx)
{
  if(!TEMU_emulation_started) return;

  uint32_t addr = (uint8_t *) ptr - phys_ram_base;
  if(__builtin_expect(addr >= ram_size, 0)) return;

#ifdef MEM_CHECK
  temu_plugin->mem_read(cpu_single_env->regs[R_A0], addr, size);
#endif

#ifndef NO_PROPAGATE
  uint8_t taint, taint1;
  uint32_t offset = addr & 63;
  uint8_t index_taint = taint_reg_check(R_A0 * 4, 4);

  if(offset + size <= 64) {
    taint1 = fast_taint_mem_check(addr, size);
    taint = index_taint? (1<<size)-1 : taint1;
    if (taint) {
      insn_tainted = 1;
      taint_register(regidx, size, taint);
      taint_operand_t src[2], dst;
      src[0].type = 1; //memory
      dst.type = 0;                 //register
      src[0].size = dst.size = size;
      src[0].taint = taint1;

      dst.taint = taint;
      src[0].addr = addr, dst.addr = regidx;
      src[0].records = tpage_table[addr>>6]->records + 
				offset*temu_plugin->taint_record_size;
      dst.records = regs_records + temu_plugin->taint_record_size*regidx;

      if(index_taint) {
        src[1].type = 0;
        src[1].size = 4;
        src[1].taint = index_taint;
        src[1].records = regs_records + temu_plugin->taint_record_size * R_A0 * 4;
        src[1].addr = R_A0 * 4;
      }
      temu_plugin->taint_propagate(index_taint? 2:1, src, &dst, PROP_MODE_MOVE);
    } else 
     clean_register(regidx, size);
  } 
  else {
    int size1 = 64 - offset;
    int size2 = size - size1;
    taint_operand_t src[2], dst;
    if(index_taint) {
      src[1].type = 0;
      src[1].size = 4;
      src[1].taint = index_taint;
      src[1].records = regs_records + temu_plugin->taint_record_size * R_A0 * 4;
      src[1].addr = R_A0 * 4;
    }

    taint1 = fast_taint_mem_check(addr, size1);
    taint = index_taint? (1<<size1)-1 : taint1;
    if (taint) {
      insn_tainted = 1;
      taint_register(regidx, size1, taint);
      src[0].type = 1; //memory
      dst.type = 0;                 //register
      src[0].size = dst.size = size1;
      src[0].taint = taint1;

      dst.taint = taint;
      src[0].addr = addr, dst.addr = regidx;
      src[0].records = tpage_table[addr>>6]->records + 
				offset*temu_plugin->taint_record_size;
      dst.records = regs_records + temu_plugin->taint_record_size*regidx;
      temu_plugin->taint_propagate(index_taint? 2:1, src, &dst, PROP_MODE_MOVE);
    } else 
     clean_register(regidx, size1);

    taint1 = fast_taint_mem_check(addr+size1, size2);
    taint = index_taint? (1<<size2)-1 : taint1;
    if (taint) {
      insn_tainted = 1;
      taint_register(regidx+size1, size2, taint);
      src[0].type = 1; //memory
      dst.type = 0;                 //register
      src[0].size = dst.size = size2;
      src[0].taint = taint1;

      dst.taint = taint;
      src[0].addr = addr+size1, dst.addr = regidx+size1;
      src[0].records = tpage_table[(addr>>6)+1]->records;
      dst.records = regs_records + temu_plugin->taint_record_size*(regidx+size1);
      temu_plugin->taint_propagate(index_taint? 2:1, src, &dst, PROP_MODE_MOVE);
    } else 
     clean_register(regidx+size1, size2);
  }

#endif //NO_PROPAGATE

#ifdef REG_CHECK
  temu_plugin->reg_write(regidx, size);
#endif

}


void __attribute__((fastcall)) taintcheck_mem2reg_nolookup(uint32_t paddr, uint32_t vaddr, int size, int regidx)
{
  if(!TEMU_emulation_started) return;
  if(__builtin_expect(paddr >= ram_size, 0)) return;

#ifdef MEM_CHECK
  temu_plugin->mem_read(vaddr, paddr, size);
#endif

#ifndef NO_PROPAGATE
  uint8_t taint = 0;
  uint32_t offset = paddr & 63;
  
  if (offset + size <= 64) {
    taint = taint_mem_check(paddr, size);
    if (taint) {
      insn_tainted = 1;
      taint_register(regidx, size, taint);
      taint_operand_t src, dst;
      src.type = 1;              //memory
      dst.type = 0;              //register
      src.size = dst.size = size;
      src.taint = dst.taint = taint;
      src.addr = paddr, dst.addr = regidx;
      src.records = tpage_table[paddr >> 6]->records +
      			offset * temu_plugin->taint_record_size;
      dst.records = regs_records + temu_plugin->taint_record_size * regidx;
      temu_plugin->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
    } else     
      clean_register(regidx, size);
  } 
  else {
    int size1 = 64 - offset;
    int size2 = size - size1;
    taint = taint_mem_check(paddr, size1);
    if (taint) {
      insn_tainted = 1;
      taint_register(regidx, size1, taint);
      taint_operand_t src, dst;
      src.type = 1;              //memory
      dst.type = 0;                 //register
      src.size = dst.size = size1;
      src.taint = dst.taint = taint;
      src.addr = paddr, dst.addr = regidx;
      src.records = tpage_table[paddr >> 6]->records +
      			offset * temu_plugin->taint_record_size;
      dst.records = regs_records + temu_plugin->taint_record_size * regidx;
      temu_plugin->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
    } else     
      clean_register(regidx, size1);

    taint = taint_mem_check(paddr+size1, size2);
    if (taint) {
      insn_tainted = 1;
      taint_register(regidx+size1, size2, taint);
      taint_operand_t src, dst;
      src.type = 1;              //memory
      dst.type = 0;                 //register
      src.size = dst.size = size2;
      src.taint = dst.taint = taint;
      src.addr = paddr+size1, dst.addr = regidx+size1;
      src.records = tpage_table[(paddr>>6) + 1]->records;
      dst.records = regs_records + temu_plugin->taint_record_size * (regidx+size1);
      temu_plugin->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
    } else     
      clean_register(regidx+size1, size2);
  }
#endif //NO_PROPAGATE

#ifdef REG_CHECK
  temu_plugin->reg_write(regidx, size);
#endif

}


static inline void reg2reg_internal(int sregidx, int dregidx, 
	int size)
{
  uint8_t taint;

  if(regs_bitmap == 0)
	return;

  taint = taint_reg_check(sregidx, size);
#ifdef TAINTCHECK_CLEAR_ZERO
  if (__builtin_expect(taint, 0))
    taint = clear_zero(cpu_single_env->regs[sregidx >> 2] >> (sregidx & 3),
                       size, taint);
#endif
  if(!taint) {
	clean_register(dregidx, size);
	return;
  }

  taint_register(dregidx, size, taint);
  insn_tainted = 1;
  taint_operand_t src, dst;
  src.type = dst.type = 0;
  src.size = dst.size = size;
  src.taint = dst.taint = taint;
  src.addr = sregidx, dst.addr = dregidx;
  src.records =
      regs_records + sregidx * temu_plugin->taint_record_size;
  dst.records =
      regs_records + dregidx * temu_plugin->taint_record_size;
  temu_plugin->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
}


void __attribute__((fastcall)) taintcheck_reg2reg(int sreg, int dreg, int size)
{
  if(!TEMU_emulation_started) return;
#ifdef REG_CHECK
  temu_plugin->reg_read(sreg<<2, size);
#endif

#ifndef NO_PROPAGATE
  reg2reg_internal(sreg<<2, dreg<<2, size);
#endif  

#ifdef REG_CHECK
  temu_plugin->reg_write(dreg<<2, size);
#endif
}


void __attribute__((fastcall)) taintcheck_reg2reg_shift(int sregidx, int dregidx, int size)
{
  if(!TEMU_emulation_started) return;

#ifdef REG_CHECK
   temu_plugin->reg_read(sregidx, size);
#endif

#ifndef NO_PROPAGATE
  reg2reg_internal(sregidx, dregidx, size);
#endif  

#ifdef REG_CHECK
  temu_plugin->reg_write(dregidx, size);
#endif
}

void __attribute__((fastcall)) taintcheck_reg_clean(int reg)
{
  if(!TEMU_emulation_started) return;
#ifndef NO_PROPAGATE
  clean_register(reg << 2, 4);
#endif  
}

void __attribute__((fastcall)) taintcheck_reg_clean2(int regidx, int size)
{
  if(!TEMU_emulation_started) return;
#ifndef NO_PROPAGATE
  clean_register(regidx, size);
#endif  
}

void __attribute__((fastcall)) taintcheck_mem_clean(void *ptr, int size)
{
  if (!TEMU_emulation_started) return;
  uint32_t addr = (uint8_t *) ptr - phys_ram_base;
  if (__builtin_expect(addr + size >= ram_size, 0)) return;

  uint32_t i, len;
  for (i = 0; i < size; i += 64) {
    len = min(64, size - i);
    clean_memory(addr + i, len);
  }
}

void __attribute__((fastcall)) taintcheck_clean_memory(uint32_t phys_addr, int size)
{
  if (!TEMU_emulation_started) return;
  if (__builtin_expect(phys_addr + size >= ram_size, 0)) return;

  uint32_t i, len;
  for (i = 0; i < size; i += 64) {
    len = min(64, size - i);
    clean_memory(phys_addr + i, len);
  }
}



void __attribute__((fastcall)) taintcheck_bswap(int reg, int size)
{
  if(__builtin_expect(!TEMU_emulation_started, 0)) return;

#ifndef NO_PROPAGATE
  uint8_t taint, taint2 = 0;
  int i, regidx;
  char *record2 = NULL;

  regidx = reg << 2;
  if (!(taint = taint_reg_check(regidx, size)))
    return ;
  if (!(record2 = qemu_mallocz(temu_plugin->taint_record_size * size)))
    return;

  insn_tainted = 1;
  for (i = 0; i < size; i++) {
    if (taint & (1 << i)) {
      taint2 |= 1 << (size - i - 1);
      memcpy(record2 + (size - i - 1) * temu_plugin->taint_record_size,
             regs_records + (regidx + i) * temu_plugin->taint_record_size,
             temu_plugin->taint_record_size);
    }
  }
  memcpy(regs_records + regidx * temu_plugin->taint_record_size, record2,
         size * temu_plugin->taint_record_size);

  taint_register(regidx, size, taint2);
  //may call taint_propagate here

  qemu_free(record2);
#endif //NO_PROPAGATE
}

void __attribute__((fastcall)) taintcheck_fn1reg(int reg, int size)        //size<=4
{
  if(__builtin_expect(!TEMU_emulation_started, 0)) return;

#ifdef REG_CHECK
  temu_plugin->reg_read(reg<<2, size);
#endif

#ifndef NO_PROPAGATE
  uint8_t taint;
  int regid = reg << 2;

  if (__builtin_expect(!(taint = taint_reg_check(regid, size)), 1))
    return;

  taint_register(regid, size, (1 << size) - 1);

  insn_tainted = 1;
  taint_operand_t oprnd;
  oprnd.type = 0;
  oprnd.size = size;
  oprnd.taint = taint;
  oprnd.addr = regid;
  oprnd.records =
      regs_records + temu_plugin->taint_record_size * regid;

  temu_plugin->taint_propagate(1, &oprnd, &oprnd, PROP_MODE_XFORM);
#endif  

#ifdef REG_CHECK
  temu_plugin->reg_write(reg<<2, size);
#endif

}

void __attribute__((fastcall)) 
taintcheck_fn2regs(int sreg1, int sreg2, int dreg, int size)        //size<=4
{
  if(__builtin_expect(!TEMU_emulation_started, 0)) return;

#ifdef REG_CHECK
  temu_plugin->reg_read(sreg1<<2, size);
  temu_plugin->reg_read(sreg2<<2, size);
#endif

#ifndef NO_PROPAGATE
  int sregid1 = sreg1 << 2, sregid2 = sreg2 << 2, dregid = dreg << 2;
  uint8_t taint1, taint2, taint;

  taint1 = (sreg1 < 0) ? 0 : taint_reg_check(sregid1, size);
  taint2 = (sreg2 < 0) ? 0 : taint_reg_check(sregid2, size);
  if (__builtin_expect(taint1 == 0 &&  taint2== 0, 1)) {
	clean_register(dregid, size);
	return;
  }

  taint = (1<<size) -1;
  taint_register(dregid, size, taint);

  insn_tainted = 1;
  taint_operand_t src[2], dst;
  src[0].type = src[1].type = dst.type = 0;
  src[0].size = src[1].size = dst.size = size;
  src[0].taint = taint1, src[1].taint = taint2;
  src[0].addr = sregid1, src[1].addr = sregid2, dst.addr = dregid;
  src[0].records =
      regs_records + temu_plugin->taint_record_size * sregid1;
  src[1].records =
      regs_records + temu_plugin->taint_record_size * sregid2;
  dst.records = regs_records + temu_plugin->taint_record_size * dregid;
  temu_plugin->taint_propagate(2, src, &dst, PROP_MODE_XFORM);
#endif

#ifdef REG_CHECK
  temu_plugin->reg_write(dreg<<2, size);
#endif

}

#if TAINT_FLAGS


//which=1 means cc_src, which=2 means cc_dst, which=3 means both
void __attribute__((fastcall)) 
taintcheck_update_eflags(uint32_t mask, int which) 
{
#ifndef NO_PROPAGATE
  if(__builtin_expect(!TEMU_emulation_started, 0)) 
	return;

  uint8_t taint1 = 0, taint2 = 0;

  if(which & 1) taint1 = taint_reg_check(R_CC_SRC*4, 4);
  if(which & 2) taint2 = taint_reg_check(R_CC_DST*4, 4);
  if (taint1 == 0 && taint2== 0) {
	eflags_bitmap &= ~mask;
	return;
  }

  eflags_bitmap |= mask;
  insn_tainted = 1;

  int i;
  uint8_t *dst_rec, *src_rec=NULL;

  if(taint1) {
   for (i = 0; i < 4; i++) 
    if(taint1 & (1 << i)) {
      src_rec = regs_records + (R_CC_SRC*4 + i) * temu_plugin->taint_record_size;
      break;
    }
  }
  if(src_rec == NULL) {
   for (i = 0; i < 4; i++) 
    if(taint2 & (1 << i)) {
      src_rec = regs_records + (R_CC_DST*4 + i) * temu_plugin->taint_record_size;
      break;
    }
  }

  assert(src_rec);

  for (i = 0; i < 12; i++) { //the highest bit is 12 for cc_eflags
    if(mask & (1<<i)) {
      dst_rec = eflags_records + i*temu_plugin->taint_record_size;
      memcpy(dst_rec, src_rec, temu_plugin->taint_record_size);
    }
  }

#endif
}


void  __attribute__((fastcall)) 
taintcheck_flag2reg(uint32_t mask, int regidx, int size) 
{
#ifndef NO_PROPAGATE
  if(__builtin_expect(!TEMU_emulation_started, 0)) 
	return;

  uint32_t taint = mask & eflags_bitmap;
  if (!taint) {
    clean_register(regidx, size);
    return;
  }  

  taint_register(regidx, size, (1<<size)-1);
  insn_tainted = 1;

  int i;
  uint8_t *dst_rec, *src_rec=NULL;
  for (i = 0; i < 13; i++) 
    if(taint & (1 << i)) { //the highest bit is 12 for cc_eflags
      src_rec = eflags_records + i * temu_plugin->taint_record_size;
      break;
    }

  assert(src_rec);
  for (i = 0; i < size; i++) { 
    dst_rec = regs_records + (regidx+i)*temu_plugin->taint_record_size;
    memcpy(dst_rec, src_rec, temu_plugin->taint_record_size);
  }

#endif //NO_PROPAGATE
} 

void __attribute__((fastcall)) 
taintcheck_reg2flag(int regidx, int size, uint32_t mask)
{
#ifndef NO_PROPAGATE
  if(__builtin_expect(!TEMU_emulation_started, 0)) 
	return;

  uint32_t taint = taint_reg_check(regidx, size);
  if (!taint) {
    eflags_bitmap &= ~mask;
    return;
  }  

  eflags_bitmap |= mask;
  insn_tainted = 1;

  int i;
  uint8_t *dst_rec, *src_rec=NULL;
  for (i = 0; i < size; i++) 
    if(taint & (1 << i)) {
      src_rec = regs_records + i * temu_plugin->taint_record_size;
      break;
    }

  assert(src_rec);
  for (i = 0; i < size*8; i++) {
    if(mask & (1<<i)) { 
      dst_rec = eflags_records + i*temu_plugin->taint_record_size;
      memcpy(dst_rec, src_rec, temu_plugin->taint_record_size);
    }
  }

#endif //NO_PROPAGATE
}


#endif


void __attribute__((fastcall)) taintcheck_logic_T0_T1()
{
  if(__builtin_expect(!TEMU_emulation_started, 0)) return;

#ifndef NO_PROPAGATE
  uint8_t taint1, taint2, taint;
  taint1 = taint_reg_check(R_T0*4, 4);
  taint2 = taint_reg_check(R_T1*4, 4);
  taint = taint1 | taint2;
  if(__builtin_expect(0 == taint, 1)) return;
 
  taint_register(R_T0*4, 4, taint);
  insn_tainted = 1;
  taint_operand_t src[2], dst;
  int i;
  src[0].type = src[1].type = dst.type = 0; //register
  src[0].size = src[1].size = dst.size = 1; //we do it byte by byte
  for (i=0; i<4; i++) {
    if(!(taint & (1<<i))) continue;
    
    src[0].taint = (taint1 >> i) & 1;
    src[1].taint = (taint2 >> i) & 1;
    dst.addr = src[0].addr = R_T0*4 + i;
    src[1].addr = R_T1*4 + i;
    src[0].records = regs_records + temu_plugin->taint_record_size * src[0].addr;
    src[1].records = regs_records + temu_plugin->taint_record_size * src[1].addr;
    dst.records = src[0].records;
    temu_plugin->taint_propagate(2, src, &dst, PROP_MODE_XFORM);
  }

#endif
}

void taintcheck_clear_ones(int reg, int size, uint32_t val)     //size<=4
{
#ifndef NO_PROPAGATE
  if(__builtin_expect(!TEMU_emulation_started, 0)) return;

  int i;
  uint8_t taint = taint_reg_check(reg << 2, size);
  if (!taint)
    return;

  for (i = 0; i < size; i++) {
    if (((val >> i) & 0xff) == 0xff)
      taint &= ~(1 << i);
  }
  taint_register(reg << 2, size, taint);
#endif
}

void taintcheck_clear_zeros(int reg, int size, uint32_t val)    //size<=4
{
#ifndef NO_PROPAGATE
  if (__builtin_expect(!TEMU_emulation_started, 0)) return;

  uint8_t taint = taint_reg_check(reg << 2, size);
  if (__builtin_expect(!taint, 1))
    return;
  taint = clear_zero(val, size, taint);
  taint_register(reg << 2, size, taint);
#endif
}

void __attribute__((fastcall)) 
taintcheck_fn3regs(int sreg1, int sreg2, int sreg3, int dreg, int size)     //size<=4
{
  if(__builtin_expect(!TEMU_emulation_started, 0)) return;

#ifdef REG_CHECK
  temu_plugin->reg_read(sreg1<<2, size);
  temu_plugin->reg_read(sreg2<<2, size);
  temu_plugin->reg_read(sreg3<<2, size);
#endif


#ifndef NO_PROPAGATE
  int sregid1 = sreg1 << 2, sregid2 = sreg2 << 2, sregid3 =
      sreg3 << 2, dregid = dreg << 2;
  uint8_t taint1, taint2, taint3, taint = 0;

  taint1 = taint_reg_check(sregid1, size);
  taint2 = taint_reg_check(sregid2, size);
  taint3 = taint_reg_check(sregid3, size);
  if (__builtin_expect(!taint1 && !taint2 && !taint3, 1)) {
    clean_register(dregid, size);
    return;
  }

  taint = (1 << size) - 1;
  taint_register(dregid, size, taint);
  insn_tainted = 1;
  taint_operand_t src[3], dst;
  src[0].type = src[1].type = src[2].type = dst.type = 0;
  src[0].size = src[1].size = src[2].size = dst.size = size;
 
  src[0].taint = taint1, src[1].taint = taint2, src[2].taint = taint3;
  src[0].addr = sregid1, src[1].addr = sregid2, src[2].addr =
      sregid3, dst.addr = dregid;
  src[0].records =
      regs_records + temu_plugin->taint_record_size * sregid1;
  src[1].records =
      regs_records + temu_plugin->taint_record_size * sregid2;
  src[2].records =
      regs_records + temu_plugin->taint_record_size * sregid3;
  dst.records = regs_records + temu_plugin->taint_record_size * dregid;

  temu_plugin->taint_propagate(3, src, &dst, PROP_MODE_XFORM);
#endif

#ifdef REG_CHECK
  temu_plugin->reg_write(dreg<<2, size);
#endif
}

typedef struct disk_record{
  void *bs;
  uint64_t index;
  uint64_t bitmap;
  LIST_ENTRY(disk_record) entry;
  uint8_t records[0];
} disk_record_t;

#define DISK_HTAB_SIZE (1024)
static LIST_HEAD(disk_record_list_head, disk_record) 
	disk_record_heads[DISK_HTAB_SIZE];
//static struct list_head disk_records_htab[DISK_HTAB_SIZE];

int taintcheck_taint_disk(uint64_t index, uint64_t taint, int offset,
                          int size, uint8_t * record, void *bs)
{
  if(!TEMU_emulation_started) return 0;

#ifndef NO_PROPAGATE
  struct disk_record_list_head *head =
      &disk_record_heads[index & (DISK_HTAB_SIZE - 1)];
  disk_record_t *drec,  *new_drec;
  int found = 0;
  int size2 = 0;
  uint64_t taint2 = 0;

  if (offset + size > 64) {
    size = 64 - offset, taint &= size_to_taint(size);
    size2 = offset + size - 64;
    taint2 = taint >> offset;
  }

  LIST_FOREACH(drec, head, entry) {
    if (drec->index == index && drec->bs == bs) {
      found = 1;
      break;
    }
    if (drec->index > index)
      break;
  }
  if (!found) {
    if (!taint)
      return 0;

    if (!(new_drec = qemu_mallocz(sizeof(disk_record_t) +
                              64 * temu_plugin->taint_record_size)))
      return 0;

    new_drec->index = index;
    new_drec->bs = bs;
    new_drec->bitmap = taint << offset;
    memcpy(new_drec->records + offset * temu_plugin->taint_record_size,
           record, size * temu_plugin->taint_record_size);
    LIST_INSERT_HEAD(head, new_drec, entry);
  }
  else {
    drec->bitmap &= ~(size_to_taint(size) << offset);
    if (taint) {
      drec->bitmap |= taint << offset;
      memcpy(drec->records + offset * temu_plugin->taint_record_size,
             record, size * temu_plugin->taint_record_size);
    }
    else if (!drec->bitmap) {
      LIST_REMOVE(drec, entry);
      qemu_free(drec);
    }
  }

  if (size2)
    taintcheck_taint_disk(index + 1, taint2, 0, size2,
                          record + size * temu_plugin->taint_record_size,
                          bs);
#endif
  return 0;
}

uint64_t taintcheck_disk_check(uint64_t index, int offset, int size,
                               uint8_t * record, void *bs)
{
  if(!TEMU_emulation_started) return 0;

#ifndef NO_PROPAGATE
  struct disk_record_list_head *head =
      &disk_record_heads[index & (DISK_HTAB_SIZE - 1)];
  disk_record_t *drec;
  int found = 0;
  uint64_t taint;

  if (offset + size > 64)
    size = 64 - offset, taint &= size_to_taint(size);   //fixme:ignore the unalignment

  LIST_FOREACH(drec, head, entry) {
    if (drec->index == index && drec->bs == bs) {
      found = 1;
      break;
    }
    if (drec->index > index)
      break;
  }

  if (!found)
    return 0;

  taint = (drec->bitmap >> offset) & size_to_taint(size);
  if (taint)
    memcpy(record, drec->records + offset * temu_plugin->taint_record_size,
           size * temu_plugin->taint_record_size);
  return taint;
#else
  return 0;
#endif  
}


int taintcheck_chk_hdout(int size, int64_t sect_num, uint32_t offset,
                         void *s)
{
#ifndef NO_PROPAGATE
  uint8_t taint;
  int i, regidx = cpu_single_env->tempidx << 2;

  if (!TEMU_emulation_started)
    return 0;

  taint = taint_reg_check(regidx, size);
  taintcheck_taint_disk(sect_num * 8 + offset / 64, taint, offset & 63,
                        size,
                        regs_records +
                        regidx * temu_plugin->taint_record_size, s);
  if(temu_plugin->taint_disk) {
    for (i = 0; i < size; i++) {
      if (taint & (1 << i))
        temu_plugin->taint_disk(sect_num * 512 + offset + i, regs_records +
                              (regidx +
                               i) * temu_plugin->taint_record_size,
                              (BlockDriverState *) s);
	}
  }
#endif
  return 0;
}

int taintcheck_chk_hdin(int size, int64_t sect_num, uint32_t offset,
                        void *s)
{
#ifndef NO_PROPAGATE
  uint64_t taint = 0;
  uint8_t *records;
  int regidx = cpu_single_env->tempidx << 2;

  if (!TEMU_emulation_started)
    return 0;

  records = qemu_malloc(temu_plugin->taint_record_size * 4);
  if (!records)
    return 0;

  taint =
      taintcheck_disk_check(sect_num * 8 + offset / 64, offset & 63, size,
                            records, s);
  if (taint) {
	if(temu_plugin->read_disk_taint) {
      int i;
      for (i = 0; i < size; i++) {
        if (taint & (1 << i))
          temu_plugin->read_disk_taint(sect_num * 512 + offset + i,
                                       records +
                                       temu_plugin->taint_record_size * i,
                                       s);
      }
    }
    taint_register(regidx, size, taint);
    memcpy(regs_records + regidx * temu_plugin->taint_record_size,
           records, size * temu_plugin->taint_record_size);
  }
  qemu_free(records);
#endif
  return 0;
}


int taintcheck_chk_hdwrite(uint32_t paddr, int size, int64_t sect_num,
                           void *s)
{
#ifndef NO_PROPAGATE
  uint32_t i, j;
  tpage_entry_t *entry;

  if (!TEMU_emulation_started || (paddr & 63))
    return 0;
  for (i = paddr; i < paddr + size; i += 64) {
    entry = tpage_table[i >> 6];
    taintcheck_taint_disk(sect_num * 8 + (i - paddr) / 64,
                          (entry) ? entry->bitmap : 0, 0, 64,
                          (entry) ? entry->records : NULL, s);
    if (!entry || !temu_plugin->taint_disk)
      continue;

    for (j = 0; j < 64; j++) {
      if (entry->bitmap & (1ULL << j))
        temu_plugin->taint_disk(sect_num * 512 + i + j - paddr,
                                entry->records +
                                j * temu_plugin->taint_record_size,
                                (BlockDriverState *) s);
    }
  }
#endif
  return 0;
}

int taintcheck_chk_hdread(uint32_t paddr, int size, int64_t sect_num,
                          void *s)
{
#ifndef NO_PROPAGATE
  uint32_t i, j;
  uint64_t taint;
  uint8_t *records;

  if (!TEMU_emulation_started)
    return 0;

  records = qemu_malloc(64 * temu_plugin->taint_record_size);
  if (!records)
    return 0;

  for (i = paddr; i < paddr + size; i += 64) {
    taint =
        taintcheck_disk_check(sect_num * 8 + (i - paddr) / 64, 0, 64,
                              records, s);
    if (!taint)
      continue;
    taint_memory(i, 64, taint);
    memcpy(tpage_table[i >> 6]->records, records,
           64 * temu_plugin->taint_record_size);

    if (!temu_plugin->read_disk_taint)
      continue;

    for (j = 0; j < 64; j++) {
      if (taint & (1ULL << j))
        temu_plugin->read_disk_taint(sect_num * 512 + (i - paddr) + j,
                                     records +
                                     temu_plugin->taint_record_size * j,
                                     s);
    }
  }
  qemu_free(records);
#endif
  return 0;
}


int taintcheck_get_sizeof_taintmem()
{
  int i, j, size = 0;

  for (i = 0; i < ram_size / 64; i++)
    if (tpage_table[i]) {
      for (j = 0; j < 64; j++)
        if ((1ULL << j) & tpage_table[i]->bitmap)
          size++;
    }
  return size;
}


void taintcheck_clean_memreg()
{
  int i;
  regs_bitmap = 0;
  for (i = 0; i < ram_size / 64; i++)
    if (tpage_table[i]) {
      qemu_free(tpage_table[i]);
      tpage_table[i] = 0;
    }
}



int taintcheck_nic_writebuf(uint32_t addr, int size, uint64_t bitmap, uint8_t * records)        //size<=64
{
  int size1 = size, size2 = 0, index, offset;

  if (!TEMU_emulation_started || addr >= 32 * 1024)
    return 0;

  index = addr >> 6, offset = addr & 63;
  if (offset + size > 64) {
    size2 = offset + size - 64;
    size1 = 64 - offset;
  }
  nic_bitmap[index] &= ~(((1ULL << size1) - 1) << offset);
  nic_bitmap[index] |= (bitmap & size_to_taint(size1)) << offset;
  if (size2) {
    nic_bitmap[index + 1] &= ~size_to_taint(size2);
    nic_bitmap[index + 1] |= bitmap >> size1;
  }

  if (bitmap)
    memcpy(nic_records + addr * temu_plugin->taint_record_size,
           records, size * temu_plugin->taint_record_size);
  return 0;
}

uint64_t taintcheck_nic_readbuf(uint32_t addr, int size, uint8_t * records)     //size<=64
{
  int size1 = size, size2 = 0, index, offset;
  uint64_t taint;

  if (!TEMU_emulation_started || addr >= 32 * 1024)
    return 0;

  index = addr >> 6, offset = addr & 63;
  if (offset + size > 64) {
    size2 = offset + size - 64;
    size1 = 64 - offset;
  }
  taint = (nic_bitmap[index] >> offset) & size_to_taint(size1);
  if (size2) {
    taint |= (nic_bitmap[index + 1] & size_to_taint(size2)) << offset;
  }

  if (taint)
    memcpy(records, nic_records + addr * temu_plugin->taint_record_size,
           size * temu_plugin->taint_record_size);
  return taint;
}


int taintcheck_nic_out(uint32_t addr, int size)
{
  uint64_t taint;

  taint = taint_reg_check(cpu_single_env->tempidx << 2, size);
  taintcheck_nic_writebuf(addr, size, taint, regs_records +
                          cpu_single_env->tempidx * 4 *
                          temu_plugin->taint_record_size);
  return 0;
}


int taintcheck_nic_in(uint32_t addr, int size)
{
  char * records = qemu_malloc(temu_plugin->taint_record_size * size);
  if(records) {
	uint64_t taint = taintcheck_nic_readbuf(addr, size, records);
	taintcheck_taint_register(cpu_single_env->tempidx, 0, size, taint, records);
	qemu_free(records);
  }
  return 0;
}


int taintcheck_patch()          //patch for keystroke propagation on Windows XP sp2
{
#ifndef NO_PROPAGATE
  if (cpu_single_env->eip != 0xbf8a4bde &&
      cpu_single_env->eip != 0xbf84a74f && 
      cpu_single_env->eip != 0xbf848d65 &&  //for sp3
      cpu_single_env->eip != 0xbf848d1c ) // updated sp3
    return 0;
  
  if(!TEMU_emulation_started) return 0;

  uint32_t phys_addr, addr, addr2, phys_addr2;
  addr = cpu_single_env->regs[R_EBP] + 8;
  phys_addr = TEMU_get_phys_addr(addr);
  if (phys_addr == -1)
    return 0;

  if (!taint_mem_check(phys_addr, 1))
    return 0;

  addr2 = cpu_single_env->regs[R_EBP] + 0x14;
  if (TEMU_read_mem(addr2, 4,  &addr2) >= 0 && 
      (phys_addr2 = TEMU_get_phys_addr(addr2)) != -1) {
    taintcheck_mem2reg_nolookup(phys_addr, addr, 1, R_T0 * 4);
    taintcheck_reg2mem(R_T0 * 4, 1, phys_ram_base + phys_addr2);
  }
#endif
  return 0;
}


uint64_t taintcheck_memory_check(uint32_t addr, int size,
                                 uint8_t * records)
{
  uint64_t taint;
  int len, len2;
  uint32_t offset = addr & 63;
  tpage_entry_t *entry;

  if (!TEMU_emulation_started || addr >= ram_size)
    return 0;
  if (!(taint = taint_mem_check(addr, size)))
    return 0;

  if (!records)
    return taint;

  len = min(64 - offset, size);
  if ((entry = tpage_table[addr >> 6]))
    memcpy(records,
           entry->records + offset * temu_plugin->taint_record_size,
           len * temu_plugin->taint_record_size);
  len2 = size - len, entry = tpage_table[(addr >> 6) + 1];
  if (len2 && entry)
    memcpy(records + len * temu_plugin->taint_record_size,
           entry->records, len2 * temu_plugin->taint_record_size);
  return taint;
}

uint64_t taintcheck_register_check(int reg, int offset, int size,
                                   uint8_t * records)
{
  uint64_t taint;
  if (!TEMU_emulation_started)
    return 0;
  taint = taint_reg_check((reg << 2) + offset, size);
  if (taint && records)
    memcpy(records,
           regs_records + (reg * 4 +
                           offset) * temu_plugin->taint_record_size,
           size * temu_plugin->taint_record_size);
  return taint;
}

int taintcheck_taint_register(int reg, int offset, int size,
                              uint64_t taint, uint8_t * records)
{
  if (!TEMU_emulation_started)
    return 0;
  taint_register((reg << 2) + offset, size, taint);
  if (taint) {
    memcpy(regs_records +
           (reg * 4 + offset) * temu_plugin->taint_record_size, records,
           size * temu_plugin->taint_record_size);
  }
  return 0;
}

/** 
 * Taint a physical memory region:
 * addr: physical address
 * size:  size of memory to taint (size <= 64)
 * taint: bitmap of taint
 * records: an array of taint records
 */
int taintcheck_taint_memory(uint32_t addr, int size, uint64_t taint, uint8_t * records) 
{
  tpage_entry_t *entry;
  int len, len2, offset = addr & 63;

  if (!TEMU_emulation_started || addr > ram_size)
    return 0;
  if (!taint)
    clean_memory(addr, size);
  else {
    taint_memory(addr, size, taint);
    len = min(64 - offset, size);
    if ((entry = tpage_table[addr >> 6])) {
      memcpy(entry->records + offset * temu_plugin->taint_record_size,
             records, len * temu_plugin->taint_record_size);
    }
    len2 = size - len, entry = tpage_table[(addr >> 6) + 1];
    if (len2 && entry) {
      memcpy(entry->records,
             records + len * temu_plugin->taint_record_size,
             len2 * temu_plugin->taint_record_size);
    }
  }
  return 0;
}

void taintcheck_taint_virtmem(uint32_t vaddr, uint32_t size, uint64_t taint, void *records) 
{
  uint32_t paddr =0, offset;
  uint32_t size1, size2;
  uint64_t taint1, taint2;
  
  paddr = TEMU_get_phys_addr(vaddr);
  if(paddr == -1) return;

  offset = vaddr & ~TARGET_PAGE_MASK;
  if(offset+size > TARGET_PAGE_SIZE) {
	size1 = TARGET_PAGE_SIZE - offset;
	size2 = size - size1;
	taint1 = size_to_taint(size1) & taint;
	taint2 = taint>>size1;
  } else 
	size1 = size, size2 = 0, taint1 = taint, taint2=0;
  taintcheck_taint_memory(paddr, size1, taint1, records);
  if(size2) {
	paddr = TEMU_get_phys_addr((vaddr&TARGET_PAGE_MASK)+TARGET_PAGE_SIZE);
	if(paddr != -1)
	  taintcheck_taint_memory(paddr, size2, taint2, 
	  		records + size1*temu_plugin->taint_record_size);
  }
}

uint64_t taintcheck_check_virtmem(uint32_t vaddr, uint32_t size, void *records) 
{
  uint64_t ret	= 0;
  uint32_t paddr = 0, offset;
  uint32_t size1, size2;
  
  paddr = TEMU_get_phys_addr(vaddr);
  if(paddr == -1) return 0;

  offset = vaddr& ~TARGET_PAGE_MASK;
  if(offset+size > TARGET_PAGE_SIZE) {
	size1 = TARGET_PAGE_SIZE-offset;
	size2 = size -size1;
  } else 
	size1 = size, size2 = 0;

  ret = taintcheck_memory_check(paddr, size1, records);
  if(size2) {
	paddr = TEMU_get_phys_addr((vaddr&TARGET_PAGE_MASK)+TARGET_PAGE_SIZE);
	if(paddr != -1)
	  ret |= taintcheck_memory_check(paddr,size2, 
	  		(uint8_t *)records+size1*temu_plugin->taint_record_size)<<size1;
  }

  return ret;
}



int taintcheck_jnz_T0_label()
{
  int res = 0;
  if (!TEMU_emulation_started || !should_monitor)
    return 0;

  if (taint_reg_check(R_T0 * 4, 4) && temu_plugin && temu_plugin->cjmp) {
	insn_tainted = 1; //set it to indicate cjmp propagating taint
    res = temu_plugin->cjmp(cpu_single_env->regs[R_T0]);
    /* res = 1 or 2 */
    //if(jcc_inv) res ^= 3;
  }
  return res;
}

void taintcheck_jcc_target(uint32_t taken_eip, uint32_t not_taken_eip){
#ifdef JCC_ANALYSIS
  if(temu_plugin->jcc_analysis){
    temu_plugin->jcc_analysis(taken_eip, not_taken_eip);
  }
#endif
}

int taintcheck_check_eip(uint32_t reg)
{
#ifdef DEFINE_EIP_TAINTED
  uint8_t taint;
  if (!TEMU_emulation_started || !should_monitor
      || !(taint = taint_reg_check(R_T0 * 4, 4))
      || !temu_plugin->eip_tainted)
    return 0;

  int i;
  for (i = 0; i < 4; i++)
    if (taint & (1 << i)) {
      temu_plugin->eip_tainted(regs_records +
                               (R_T0 * 4 +
                                i) * temu_plugin->taint_record_size);
      break;
    }
#endif
#ifdef DEFINE_MEMREG_EIP_CHANGE
  uint8_t taint;
  if (!TEMU_emulation_started || !should_monitor)
    return 0;

  temu_plugin->memreg_eip_change();

#endif
 
  return 0;
}


static void taintcheck_save(QEMUFile * f, void *opaque)
{
  TEMU_CompressState_t state;
  uint32_t ending = -1;
  uint8_t separator = 0;
  
  if(TEMU_compress_open(&state, f) < 0)
    return;
  
  TEMU_compress_buf(&state, (uint8_t *)&temu_plugin->taint_record_size, 4);  
  /*save registers' taint info */
  TEMU_compress_buf(&state, (uint8_t *)&regs_bitmap, 8);  
  TEMU_compress_buf(&state, regs_records, 64 * temu_plugin->taint_record_size);

  /*save memory taint info */
  int i;
  for (i = 0; i < ram_size / 64; i++) {
    if (!tpage_table[i])
      continue;

	TEMU_compress_buf(&state, (uint8_t *)&i, 4);
	TEMU_compress_buf(&state, (uint8_t *)&tpage_table[i]->bitmap, 8);
    TEMU_compress_buf(&state, tpage_table[i]->records,
                    64 * temu_plugin->taint_record_size);
	TEMU_compress_buf(&state, &separator, 1); //separator
  }
  TEMU_compress_buf(&state, (uint8_t *)&ending, 4); //ending
  /*TODO: save disk and nic info */
  
  TEMU_compress_close(&state);
}


static int taintcheck_load(QEMUFile * f, void *opaque, int version_id)
{
  uint32_t val;
  uint8_t separator;
  TEMU_CompressState_t state;
  if(TEMU_decompress_open(&state, f) < 0)
    return -EINVAL;

  taintcheck_clean_memreg();

  TEMU_decompress_buf(&state, (uint8_t *)&val, 4);
  if (val != temu_plugin->taint_record_size)
    return -EINVAL;

  TEMU_decompress_buf(&state, (uint8_t *)&regs_bitmap, 8);
  TEMU_decompress_buf(&state, regs_records, 64 * val);

  int i;
  for (TEMU_decompress_buf(&state, (uint8_t *)&i, 4); 
       i != -1; 
       TEMU_decompress_buf(&state, (uint8_t *)&i, 4)
       ) 
  {
    tpage_entry_t *entry =
        (tpage_entry_t *) qemu_mallocz(sizeof(tpage_entry_t) + 64 * val);
    if (!entry)
      return -EINVAL;

    TEMU_decompress_buf(&state, (uint8_t *)&entry->bitmap, 8);
    TEMU_decompress_buf(&state, entry->records, 64 * val);
    TEMU_decompress_buf(&state, &separator, 1);
    if(separator != 0) {
      fprintf(stderr, "Invalid taintcheck vm state\n");
      return -EINVAL;
    }
    tpage_table[i] = entry;
  }

  return 0;
}


int taintcheck_init()
{
  int i;
  for (i = 0; i < DISK_HTAB_SIZE; i++)
    LIST_INIT(&disk_record_heads[i]);

  return 0;
}


int taintcheck_create()
{
  int nic_records_len, reg_records_len;

  assert(tpage_table == NULL); //make sure it is not double created

  tpage_table = (tpage_entry_t **) qemu_malloc((ram_size/64) * sizeof(void*));
  nic_records_len = 32 * 1024 * temu_plugin->taint_record_size;
  nic_records = qemu_malloc(nic_records_len);
  reg_records_len = 64 * temu_plugin->taint_record_size;
  regs_records = qemu_mallocz(reg_records_len);
#if TAINT_FLAGS
  eflags_records = qemu_mallocz(32 * temu_plugin->taint_record_size);
#endif

  if (!tpage_table || !nic_records || !regs_records 
#if TAINT_FLAGS
	|| !eflags_records
#endif
    ) {
    fprintf(stderr, "out of memory\n");
    exit(-1);
  }

  bzero(tpage_table, (ram_size/64) * sizeof(void*));
  bzero(nic_records, nic_records_len);
  regs_bitmap = 0;
  bzero(nic_bitmap, sizeof(nic_bitmap));
#if TAINT_FLAGS
  eflags_bitmap = 0;
  bzero(eflags_records, 32 * temu_plugin->taint_record_size);
#endif
  
  register_savevm("taintcheck", 0, 1, taintcheck_save, taintcheck_load,
                  NULL);
  return 0;
}

void taintcheck_cleanup()
{
  int i;
 
  //clean nic buffer
  bzero(nic_bitmap, sizeof(nic_bitmap));
  qemu_free(nic_records);
  nic_records = NULL;
 
  //clean registers
  regs_bitmap = 0;
  qemu_free(regs_records);
  regs_records = NULL;

#if TAINT_FLAGS
  eflags_bitmap = 0;
  qemu_free(eflags_records);
  eflags_records = NULL;
#endif

  //clean memory
  for (i = 0; i < ram_size / 64; i++)
    if (tpage_table[i]) {
      qemu_free(tpage_table[i]);
      tpage_table[i] = 0;
    }
  qemu_free(tpage_table);
  tpage_table = NULL;

  //clean disk
  struct disk_record_list_head *head;
  disk_record_t *rec;
  for (i = 0; i < DISK_HTAB_SIZE; i++) {
    head = &disk_record_heads[i];
    while (!LIST_EMPTY(head)) {
      rec = LIST_FIRST(head);
      LIST_REMOVE(rec, entry);
      qemu_free(rec);
    }
  }

  deregister_savevm("taintcheck", 0);
}


void taintcheck_mov_i2m()
{
  int i;
  for (i = 0; i < physaddr_index; i++)
    taintcheck_mem_clean(physaddr_info_list[i].ptr,
                         physaddr_info_list[i].size);

  physaddr_index = 0;
}

void taintcheck_mov_m2r(int base, int index, int dreg_id)
{
  int i, regid;
  taintcheck_fn2regs(base, index, R_A0, 4);

  for (i = 0, regid = dreg_id; i < physaddr_index;
       i++, regid += physaddr_info_list[i].size) {
    taintcheck_mem2reg(physaddr_info_list[i].ptr,
                       physaddr_info_list[i].size, regid);
  }
  physaddr_index = 0;
}

void taintcheck_mov_r2m(int base, int index, int reg_id)
{
  int i, regid;
  taintcheck_fn2regs(base, index, R_A0, 4);

  for (i = 0, regid = reg_id; i < physaddr_index;
       i++, regid += physaddr_info_list[i].size) {
    taintcheck_reg2mem(regid, physaddr_info_list[i].size,
                       physaddr_info_list[i].ptr);
  }
  physaddr_index = 0;
}


void taintcheck_reg2TN(int reg, int t, int size)
{
  clean_register(t << 2, 4);
  taintcheck_reg2reg(reg, t, size);
}

void taintcheck_regh2TN(int reg, int t)
{
  clean_register(t << 2, 4);
  taintcheck_reg2reg_shift(reg * 4 + 1, t << 2, 1);
}

uint32_t taintcheck_sidt()
{
  if (!TEMU_emulation_started)
    goto no_cheat;
#ifdef CHEAT_SIDT
  if (temu_plugin->cheat_sidt()) {
/*		uint32_t val;
		asm ("sidt %0;"
		   	: :"m"(val)
		   	);*/
    return 0xe59007ff;
  }
#endif
no_cheat:
  return cpu_single_env->idt.base;
}

void taintcheck_code2TN(uint32_t vaddr, uint32_t regid, int size)
{
  //in the execution context, there should be no page fault
  uint32_t phys_addr = TEMU_get_phys_addr(vaddr);
  taintcheck_mem2reg_nolookup(phys_addr, vaddr, size, regid);
}


/*
 * This is the default taint_propagate implementation.
 * For a Temu plugin, if it does not need to handle it specially, 
 * it can specify this function in its callback function definitions
 */
void default_taint_propagate(int nr_src,
                            taint_operand_t * src_oprnds,
                            taint_operand_t * dst_oprnd,
                            int mode)
{
  int i, j;
  uint8_t *dst_rec, *src_rec=NULL;

  if (mode == PROP_MODE_MOVE && nr_src == 1) {
    //assert(src_oprnds[0].taint);
    memmove(dst_oprnd->records, src_oprnds[0].records, 
                 temu_plugin->taint_record_size * src_oprnds[0].size);
    return;
  }

  /* deal with multiple sources and tainted index*/
  for (i = 0; i < nr_src; i++) {
    if (src_oprnds[i].taint == 0)
      continue;

    for (j = 0; j < src_oprnds[i].size; j++)
      if (src_oprnds[i].taint & (1 << j)) {
        src_rec = src_oprnds[i].records + j*temu_plugin->taint_record_size;
   	    goto copy_taint_record;
      }

  }

  if (!src_rec) return;

copy_taint_record:

  for (i = 0; i < dst_oprnd->size; i++) {
    dst_rec = dst_oprnd->records + i*temu_plugin->taint_record_size;
    memmove(dst_rec, src_rec, temu_plugin->taint_record_size);
  }
}

void do_info_taintmem(void)
{
  term_printf("Tainted memory: %d \n", taintcheck_get_sizeof_taintmem());
}


#endif //#if TAINT_ENABLED
