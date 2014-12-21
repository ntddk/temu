/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

/// @file TEMU_main.h
/// @author: Heng Yin <hyin@ece.cmu.edu>
/// \addtogroup main temu: Main TEMU Module


#ifndef _TEMU_MAIN_H_INCLUDED_
#define _TEMU_MAIN_H_INCLUDED_

#undef INLINE

#include "config.h"

#ifdef TARGET_X86_64
#define TARGET_LONG_BITS 64
#else
#define TARGET_LONG_BITS 32
#endif

#include "cpu-defs.h"

#include "fpu/softfloat.h"

#if TAINT_ENABLED
#include "taintcheck.h"
#endif


/*** Define Registers ***/
/* copied from shared/disasm.h */

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

#define eip_reg 140
#define cr3_reg 141




#ifndef CPU_I386_H

#define R_EAX 0
#define R_ECX 1
#define R_EDX 2
#define R_EBX 3
#define R_ESP 4
#define R_EBP 5
#define R_ESI 6
#define R_EDI 7
#if 1//TAINT_ENABLED
#define R_T0 CPU_NB_REGS
#define R_T1 (CPU_NB_REGS + 1)
#define R_A0 (CPU_NB_REGS + 2)
#define R_CC_SRC (CPU_NB_REGS + 3)
#define R_CC_DST (CPU_NB_REGS + 4)
#endif

#define R_ES 0
#define R_CS 1
#define R_SS 2
#define R_DS 3
#define R_FS 4
#define R_GS 5

#define HF_CPL_SHIFT         0
#define HF_CPL_MASK          (3 << HF_CPL_SHIFT)

#define CR0_PE_MASK  (1 << 0)
#define CR0_MP_MASK  (1 << 1)
#define CR0_EM_MASK  (1 << 2)
#define CR0_TS_MASK  (1 << 3)
#define CR0_ET_MASK  (1 << 4)
#define CR0_NE_MASK  (1 << 5)
#define CR0_WP_MASK  (1 << 16)
#define CR0_AM_MASK  (1 << 18)
#define CR0_PG_MASK  (1 << 31)

#define CR4_VME_MASK  (1 << 0)
#define CR4_PVI_MASK  (1 << 1)
#define CR4_TSD_MASK  (1 << 2)
#define CR4_DE_MASK   (1 << 3)
#define CR4_PSE_MASK  (1 << 4)
#define CR4_PAE_MASK  (1 << 5)
#define CR4_PGE_MASK  (1 << 7)
#define CR4_PCE_MASK  (1 << 8)
#define CR4_OSFXSR_MASK (1 << 9)
#define CR4_OSXMMEXCPT_MASK  (1 << 10)


#define PG_PRESENT_BIT	0
#define PG_RW_BIT	1
#define PG_USER_BIT	2
#define PG_PWT_BIT	3
#define PG_PCD_BIT	4
#define PG_ACCESSED_BIT	5
#define PG_DIRTY_BIT	6
#define PG_PSE_BIT	7
#define PG_GLOBAL_BIT	8
#define PG_NX_BIT	63

#define PG_PRESENT_MASK  (1 << PG_PRESENT_BIT)
#define PG_RW_MASK	 (1 << PG_RW_BIT)
#define PG_USER_MASK	 (1 << PG_USER_BIT)
#define PG_PWT_MASK	 (1 << PG_PWT_BIT)
#define PG_PCD_MASK	 (1 << PG_PCD_BIT)
#define PG_ACCESSED_MASK (1 << PG_ACCESSED_BIT)
#define PG_DIRTY_MASK	 (1 << PG_DIRTY_BIT)
#define PG_PSE_MASK	 (1 << PG_PSE_BIT)
#define PG_GLOBAL_MASK	 (1 << PG_GLOBAL_BIT)
#define PG_NX_MASK	 (1LL << PG_NX_BIT)

#ifdef TARGET_X86_64
#define CPU_NB_REGS 16
#else
#define CPU_NB_REGS 8
#endif


typedef struct SegmentCache {
    uint32_t selector;
    uint32_t base;
    uint32_t limit;
    uint32_t flags;
} SegmentCache;

typedef union {
    uint8_t _b[16];
    uint16_t _w[8];
    uint32_t _l[4];
    uint64_t _q[2];
    float32 _s[4];
    float64 _d[2];
} XMMReg;

typedef union {
    uint8_t _b[8];
    uint16_t _w[2];
    uint32_t _l[1];
    uint64_t q;
} MMXReg;

#ifdef FLOATX80
#define USE_X86LDOUBLE
#endif

#ifdef USE_X86LDOUBLE
typedef floatx80 CPU86_LDouble;
#else
typedef float64 CPU86_LDouble;
#endif


#endif

typedef union {
#ifdef USE_X86LDOUBLE
        CPU86_LDouble d __attribute__((aligned(16)));
#else
#error host architecture other than IA-32 and IA-64 is not supported
        CPU86_LDouble d;
#endif
        MMXReg mmx;
} FPReg;


/* @{ */ //start of group

//move from monitor.c
/// structure for defining a terminal command
typedef struct term_cmd_t {
    const char *name; /// command name
    const char *args_type; /// command argument list
    void (*handler)(); /// command handler
    const char *params; /// parameters of command handler
    const char *help; /// help message
} term_cmd_t;

/* Static in monitor.c for QEMU, but we use it for plugins: */
///send a keystroke into the guest system
void do_send_key(const char *string);

/// \brief read or write a physical memory region
///
/// @param addr physical address
/// @param buf buffer (output buffer for read and input buffer for write)
/// @param len length of memory region
/// @param is_write true for write and false for read
void cpu_physical_memory_rw(target_phys_addr_t addr, uint8_t *buf, int len, int is_write);

/// print a message to TEMU terminal
extern void term_printf(const char *fmt, ...);


/*
 * These are extracted from CPUX86State
 */
/// array of CPU general-purpose registers, such as R_EAX, R_EBX
extern target_ulong *TEMU_cpu_regs; 
/// pointer to instruction pointer EIP
extern target_ulong *TEMU_cpu_eip;
/// pointer to EFLAGS
extern target_ulong *TEMU_cpu_eflags;
/// pointer to hidden flags
extern uint32_t *TEMU_cpu_hflags;
/// array of CPU segment registers, such as R_FS, R_CS
extern SegmentCache *TEMU_cpu_segs;
/// pointer to LDT
extern SegmentCache *TEMU_cpu_ldt;
/// pointer to GDT
extern SegmentCache *TEMU_cpu_gdt;
/// pointer to IDT
extern SegmentCache *TEMU_cpu_idt;
/// array of CPU control registers, such as CR0 and CR1
extern target_ulong *TEMU_cpu_cr;
/// pointer to DF register
extern int32_t *TEMU_cpu_df; 
/// array of XMM registers
extern XMMReg *TEMU_cpu_xmm_regs;
/// array of MMX registers
extern MMXReg *TEMU_cpu_mmx_regs;
/// FPU - array of Floating Point registers
extern FPReg *TEMU_cpu_fp_regs;
/// FPU - top of Floating Point register stack 
extern unsigned int * TEMU_cpu_fp_stt;
/// FPU - Status Register
extern unsigned int * TEMU_cpu_fpus;
/// FPU - Control Register
extern unsigned int * TEMU_cpu_fpuc;
/// FPU - Tag Register
extern uint8_t * TEMU_cpu_fptags;


extern uint32_t *TEMU_cc_op;

/// primary structure for TEMU plugin, including callbacks and states
typedef struct {
  /// array of terminal commands
  term_cmd_t *term_cmds; 
  /// array of informational commands
  term_cmd_t *info_cmds; 
  /*!
   * \brief callback for cleaning up states in plugin.
   * TEMU plugin must release all allocated resources in this function
   */
  void (*plugin_cleanup)(); 
#if TAINT_ENABLED
  /// \brief size of taint record for each tainted byte. 
  /// TEMU sees taint record as untyped buffer, so it only cares about the 
  /// size of taint record
  int taint_record_size; 

#define PROP_MODE_MOVE 	0
#define PROP_MODE_XFORM	1

  /// \brief This callback customizes its own policy for taint propagation
  ///
  /// TEMU asks plugin how to propagate tainted data. If the plugin does not 
  /// want to customize the propagation policy, it can simply specify 
  /// default_taint_propagate().
  ///
  /// @param nr_src number of source operands
  /// @param src_oprnds array of source operands
  /// @param dst_oprnd destination operand
  /// @param mode mode of propagation (either direct move or transformation)
  void (*taint_propagate) (int nr_src, taint_operand_t *src_oprnds, 
		taint_operand_t *dst_oprnd, int mode);
#endif 

  /// \brief This callback handles OS-level semantics information.
  ///
  /// It needs to parse the message and maintain process, module, and function 
  /// information, using functionality in \ref semantics.
  void (*guest_message) (char *message);

  void (*send_keystroke) (int reg);
#ifdef DEFINE_BLOCK_BEGIN
  /// This callback is invoked at the beginning of each basic block
  int (*block_begin) ();
#endif  
#ifdef DEFINE_BLOCK_END
  /// This callback is invoked at the end of each basic block
  void (*block_end) ();
#endif
#ifdef DEFINE_INSN_BEGIN
  /// This callback is invoked at the beginning of each instruction
  void (*insn_begin) ();
#endif
#ifdef DEFINE_INSN_END
  /// This callback is invoked at the end of each instruction
  void (*insn_end) ();
#endif
  void (*bdrv_open) (int index, void *opaque);
  void (*taint_disk) (uint64_t addr, uint8_t * record, void *opaque);
  void (*read_disk_taint)(uint64_t addr, uint8_t * record, void *opaque);
  /// This callback is invoked when a network packet is received by NIC
  void (*nic_recv) (uint8_t * buf, int size, int cur_pos, int start,
                    int stop);
  /// This callback is invoked when a network packet is sent out by NIC
  void (*nic_send) (uint32_t addr, int size, uint8_t * buf);

  int (*cjmp) (uint32_t t0);
#ifdef DEFINE_EIP_TAINTED
  // void (*eip_tainted) (uint8_t * record);
  void (*eip_tainted) (uint32_t next_eip);
#endif
#ifdef DEFINE_MEMREG_EIP_CHANGE
  void (*memreg_eip_change)();
#endif
  void (*after_loadvm) (const char *param);
#ifdef CHEAT_SIDT
  int (*cheat_sidt) ();
#endif
  /// \brief CR3 of a specified process to be monitored.
  /// 0 means system-wide monitoring, including all processes and kernel.
  uint32_t monitored_cr3;

#ifdef MEM_CHECK
  /// \brief This callback is invoked when the current instruction reads a memory region.
  ///
  /// @param virt_addr virtual address of memory region
  /// @param phys_addr physical address of memory region
  /// @param size size of memory region
  void (*mem_read)(uint32_t virt_addr, uint32_t phys_addr, int size);
  /// \brief This callback is invoked when the current instruction writes a memory region.
  ///
  /// @param virt_addr virtual address of memory region
  /// @param phys_addr physical address of memory region
  /// @param size size of memory region
  void (*mem_write)(uint32_t virt_addr, uint32_t phys_addr, int size);
#endif

#ifdef REG_CHECK
  /// \brief This callback is invoked when the current instruction reads a register.
  ///
  /// @param regidx register index, e.g., the index of R_BH is R_EBX*4 + 1
  /// @param size size of register in bytes
  void (*reg_read)(uint32_t regidx, int size);

  /// \brief This callback is invoked when the current instruction writes a register.
  ///
  /// @param regidx register index, e.g., the index of R_BH is R_EBX*4 + 1
  /// @param size size of register in bytes
  void (*reg_write)(uint32_t regidx, int size);
#endif

#ifdef HANDLE_INTERRUPT
  /// \brief This callback indicates an interrupt is happening
  ///
  /// @param intno interrupt number
  /// @param is_int is it software interrupt?
  /// @param next_eip EIP value when interrupt returns
  void (*do_interrupt)(int intno, int is_int, uint32_t next_eip);

  /// This callback indicates an interrupt is returned
  void (*after_iret_protected)();
#endif

#ifdef CALLSTRING_ANALYSIS
  void (*call_analysis)(uint32_t next_eip);
#endif

#ifdef RET_ANALYSIS
  void (*ret_analysis)(uint32_t next_eip);
#endif

#ifdef CMP_ANALYSIS
  void (*cmp_analysis)(uint32_t op1, uint32_t op2);
#endif

#ifdef TEST_ANALYSIS
  void (*test_analysis)(uint32_t op1, uint32_t op2);
#endif

#ifdef PRE_MEM_WRITE
  void (*pre_mem_write)(uint32_t virt_addr, uint32_t phys_addr, int size);
#endif

  void (*syscall_monitor)();

  void (*set_initial_taint_file)();
} plugin_interface_t;

/// This flag tells if emulation mode is enabled
extern int TEMU_emulation_started;

/****** Functions used by TEMU plugins ****/

/// \brief Read from a register.
///
/// Note that reg_id is register ID, which is different from register index.
/// Register ID is defined by Kruegel's disassembler, whereas register index is 
/// the index of CPU register array.
/// @param reg_id register ID
/// @param buf output buffer of the value to be read
void TEMU_read_register(int reg_id, void *buf);

/// \brief Write into a register.
///
/// Note that reg_id is register ID, which is different from register index.
/// Register ID is defined by Kruegel's disassembler, whereas register index is 
/// the index of CPU register array.
/// @param reg_id register ID
/// @param buf input buffer of the value to be written
void TEMU_write_register(int reg_id, void *buf);

/// Convert virtual address into physical address
target_ulong TEMU_get_phys_addr(target_ulong addr);

/// \brief Given a virtual address, this function returns the page access status.
///
///  @param addr virtual memory address
///  @return page access status: -1 means not present, 0 means readonly, 
///   and 1 means writable.
int TEMU_get_page_access(uint32_t addr);

int TEMU_memory_rw(uint32_t addr, void *buf, int len, int is_write);

/// \brief Read from a memory region by its virtual address.
///
/// @param vaddr virtual memory address
/// @param len length of memory region (in bytes)
/// @param buf output buffer of the value to be read
/// @return status: 0 for success and -1 for failure
///
/// If failure, it usually means that the given virtual address cannot be converted 
/// into physical address. It could be either invalid address or swapped out.
int TEMU_read_mem(uint32_t vaddr, int len, void *buf);

/// \brief Write into a memory region by its virtual address.
///
/// @param vaddr virtual memory address
/// @param len length of memory region (in bytes)
/// @param buf input buffer of the value to be written
/// @return status: 0 for success and -1 for failure
///
/// If failure, it usually means that the given virtual address cannot be converted 
/// into physical address. It could be either invalid address or swapped out.
int TEMU_write_mem(uint32_t vaddr, int len, void *buf);


int TEMU_read_mem_with_cr3(target_ulong cr3, uint32_t vaddr, int len, void *buf);
int TEMU_write_mem_with_cr3(target_ulong cr3, uint32_t vaddr, int len, void *buf); 

/// Pause the guest system
void TEMU_stop_vm();

/// Check if the current execution of guest system is in kernel mode (i.e., ring-0)
static inline int TEMU_is_in_kernel()
{
  return ((*TEMU_cpu_hflags & HF_CPL_MASK) == 0);
}


/* @} */ //end of group


extern plugin_interface_t *temu_plugin;
extern void * TEMU_KbdState;
extern int should_monitor; //!<this flag indicates whether the plugin should receive callback

int TEMU_bdrv_pread(void *bs, int64_t offset, void *buf, int count); //for SleuthKit

/****** Functions used internally ******/
void do_enable_emulation(void);
void do_disable_emulation(void);
void do_load_plugin(const char *plugin_path);
void do_unload_plugin(void);
void TEMU_nic_receive(const uint8_t * buf, int size, int cur_pos, int start, int stop);
void TEMU_nic_send(uint32_t addr, int size, uint8_t * buf);
void TEMU_nic_in(uint32_t addr, int size);
void TEMU_nic_out(uint32_t addr, int size);
void TEMU_read_keystroke(void *s);
void TEMU_virtdev_init();
void TEMU_after_loadvm();
void TEMU_init();
#ifdef DEFINE_BLOCK_BEGIN
int TEMU_block_begin();
#endif
#ifdef DEFINE_INSN_BEGIN
// void TEMU_insn_begin(uint32_t pc_start);
void TEMU_insn_begin();
#endif
#ifdef DEFINE_INSN_END
void TEMU_insn_end();
#endif
void TEMU_update_cr3();
void TEMU_do_interrupt(int intno, int is_int, target_ulong next_eip);
void TEMU_after_iret_protected(void);
void TEMU_update_cpustate();
void TEMU_loadvm(void *opaque);

#ifdef RET_ANALYSIS
void TEMU_ret_analysis(uint32_t next_eip);
#endif

#ifdef CMP_ANALYSIS
void TEMU_cmp_analysis(uint32_t op1, uint32_t op2);
#endif

#ifdef TEST_ANALYSIS
void TEMU_test_analysis(uint32_t op1, uint32_t op2);
#endif

#include "TEMU_vm_compress.h"

#endif //_TEMU_MAIN_H_INCLUDED_
