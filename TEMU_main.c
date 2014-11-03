/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#include "config.h"
#include <dlfcn.h>
#include <assert.h>
#include "hw/hw.h"
#include "hw/pc.h"
#include "hw/isa.h" /* for register_ioport_write */
#include "block.h" /* for bdrv_pread */
#include "qemu-timer.h"
#include "sysemu.h"
#include "TEMU_main.h"
#include "../shared/hookapi.h"


int TEMU_emulation_started = 0;
plugin_interface_t *temu_plugin = NULL;
int should_monitor = 1;

target_ulong *TEMU_cpu_regs = NULL;
target_ulong *TEMU_cpu_eip = NULL;
target_ulong *TEMU_cpu_eflags = NULL;
uint32_t *TEMU_cpu_hflags = NULL;
SegmentCache *TEMU_cpu_segs = NULL;
SegmentCache *TEMU_cpu_ldt = NULL;
SegmentCache *TEMU_cpu_gdt = NULL;
SegmentCache *TEMU_cpu_idt = NULL;
target_ulong *TEMU_cpu_cr = NULL;
int32_t *TEMU_cpu_df = NULL; 
uint32_t *TEMU_cc_op = NULL;
XMMReg *TEMU_cpu_xmm_regs = NULL;
MMXReg *TEMU_cpu_mmx_regs = NULL;
FPReg *TEMU_cpu_fp_regs = NULL;
unsigned int * TEMU_cpu_fp_stt = NULL;
unsigned int * TEMU_cpu_fpus = NULL;
unsigned int * TEMU_cpu_fpuc = NULL;
uint8_t * TEMU_cpu_fptags = NULL;

#if TAINT_FLAGS
uint32_t TEMU_eflags = 0;
#endif


extern CPUState *first_cpu;

static FILE *temulog = NULL;
static void *plugin_handle = NULL;
static char temu_plugin_path[PATH_MAX]="";

void do_enable_emulation()
{
  if(!TEMU_emulation_started) {
	if (temu_plugin == NULL) {
	  term_printf("You have to load a plugin before switching to emulated mode!\n");
	}
	else {
	  TEMU_emulation_started = 1;
	  term_printf("Emulation is now enabled\n");
	}
  }
  else 
    term_printf("Emulation has been already enabled!\n");
}

void do_disable_emulation()
{
  if(TEMU_emulation_started) {
	TEMU_emulation_started = 0;
	term_printf("Emulation is now disabled\n");
  }
}


void do_load_plugin(const char *plugin_path)
{
  plugin_interface_t *(*init_plugin) (void);
  char *error;

  if (temu_plugin_path[0]) {
    term_printf("%s has already been loaded! \n", plugin_path);
    return;
  }

  plugin_handle = dlopen(plugin_path, RTLD_NOW);
  if (NULL == plugin_handle) {
    term_printf("%s\n", dlerror());
    return;
  }

  dlerror();

  init_plugin = dlsym(plugin_handle, "init_plugin");
  if ((error = dlerror()) != NULL) {
    fprintf(stderr, "%s\n", error);
    dlclose(plugin_handle);
    plugin_handle = NULL;
    return;
  }

  temu_plugin = init_plugin();
  if (NULL == temu_plugin) {
    term_printf("fail to initialize the plugin!\n");
    dlclose(plugin_handle);
    plugin_handle = NULL;
    return;
  }

  temulog = fopen("temu.log", "w");
  assert(temulog != NULL);
#if TAINT_ENABLED
  taintcheck_create();
#endif 

  if(temu_plugin->bdrv_open) {
    int i;
    for(i = 0; i <= nb_drives; ++i) {
      if (drives_table[i].bdrv) 
        temu_plugin->bdrv_open(i, drives_table[i].bdrv);
    }
  }
 
  strncpy(temu_plugin_path, plugin_path, PATH_MAX);
  term_printf("%s is loaded successfully!\n", plugin_path);
}

void do_unload_plugin()
{
  do_disable_emulation();

  if(temu_plugin_path[0]) {
    temu_plugin->plugin_cleanup();
    fclose(temulog);
    temulog = NULL;
    dlclose(plugin_handle);
    plugin_handle = NULL;
    temu_plugin = NULL;
  
#if TAINT_ENABLED
    taintcheck_cleanup();
#endif
    term_printf("%s is unloaded!\n", temu_plugin_path);
    temu_plugin_path[0] = 0;
  }
}


/*
 * Update CPU States 
 */
void TEMU_update_cpustate()
{
  static CPUState *last_env = 0;
  CPUState *cur_env = cpu_single_env? cpu_single_env: first_cpu;
  if(last_env != cur_env) {
    last_env = cur_env;
	TEMU_cpu_regs = cur_env->regs;
    TEMU_cpu_eip = &cur_env->eip;
#if TAINT_FLAGS
    TEMU_cpu_eflags = &TEMU_eflags;
#else
    TEMU_cpu_eflags = &cur_env->eflags;
#endif    
	TEMU_cpu_hflags = &cur_env->hflags;
	TEMU_cpu_segs = cur_env->segs;
	TEMU_cpu_ldt = &cur_env->ldt;
	TEMU_cpu_gdt = &cur_env->gdt;
	TEMU_cpu_idt = &cur_env->idt;
	TEMU_cpu_cr = cur_env->cr;
	TEMU_cpu_df = &cur_env->df;
	TEMU_cc_op = &cur_env->cc_op;
    TEMU_cpu_xmm_regs = (XMMReg *)&cur_env->xmm_regs;
    //TEMU_cpu_mmx_regs = (MMXReg *)&cur_env->fpregs;
    TEMU_cpu_fp_regs = cur_env->fpregs;
	TEMU_cpu_fp_stt = &cur_env->fpstt;
	TEMU_cpu_fpus = &cur_env->fpus;
	TEMU_cpu_fpuc = &cur_env->fpuc;
	TEMU_cpu_fptags = cur_env->fptags;
  }
}


/*
 * NIC related functions
 */

void TEMU_nic_receive(const uint8_t * buf, int size, int cur_pos,
                      int start, int stop)
{
  if (temu_plugin && temu_plugin->nic_recv)
    temu_plugin->nic_recv((uint8_t *) buf, size, cur_pos, start, stop);
}


void TEMU_nic_send(uint32_t addr, int size, uint8_t * buf)
{
  if (temu_plugin && temu_plugin->nic_send)
    temu_plugin->nic_send(addr, size, buf);
}


void TEMU_nic_out(uint32_t addr, int size)
{
  if (!TEMU_emulation_started)
    return;
#if TAINT_ENABLED
  taintcheck_nic_out(addr, size);
#endif
}


void TEMU_nic_in(uint32_t addr, int size)
{
  if (!TEMU_emulation_started)
    return;
#if TAINT_ENABLED
  taintcheck_nic_in(addr, size);
#endif
}

/* 
 * keyboard related functions 
 */
void *TEMU_KbdState = NULL;

void TEMU_read_keystroke(void *s)
{
  if (s != TEMU_KbdState)
    return;

  if (temu_plugin && temu_plugin->send_keystroke)
    temu_plugin->send_keystroke(cpu_single_env->tempidx);
}


/*
 * A virtual device that reads messages from the kernel module in the guest windows
 */

static FILE *guestlog = NULL;

static void TEMU_virtdev_write_data(void *opaque, uint32_t addr,
                                    uint32_t val)
{
  static char syslogline[512];
  static int pos = 0;

  if (pos >= 510)
    pos = 510;

  if ((syslogline[pos++] = (char) val) == 0) {
    if (temu_plugin && temu_plugin->guest_message)
      temu_plugin->guest_message(syslogline);
    fprintf(guestlog, "%s", syslogline);
    fflush(guestlog);
    pos = 0;
  }
}


void TEMU_virtdev_init()
{
  int res =
      register_ioport_write(0x68, 1, 1, TEMU_virtdev_write_data, NULL);
  if (res) {
    fprintf(stderr, "failure on initializing TEMU virtual device\n");
    exit(-1);
  }
  if (!(guestlog = fopen("guest.log", "w"))) {
    fprintf(stderr, "failure on opening guest.log \n");
    exit(-1);
  }
}


void TEMU_after_loadvm(const char *param)
{
  if (temu_plugin && temu_plugin->after_loadvm)
    temu_plugin->after_loadvm(param);
}

static void TEMU_register_rw(int reg_id, void *buf, int is_write)
{
  assert(cpu_single_env != NULL);

  uint32_t offset, size;

  switch(reg_id) {
    case eax_reg: offset = R_EAX*4, size=4;
    	break;
    case ecx_reg: offset = R_ECX*4, size=4;
    	break;
    case edx_reg: offset = R_EDX*4, size=4;
    	break;
    case ebx_reg: offset = R_EBX*4, size=4;
    	break;
    case esp_reg: offset = R_ESP*4, size=4;
    	break;
    case ebp_reg: offset = R_EBP*4, size=4;
    	break;
    case esi_reg: offset = R_ESI*4, size=4;
    	break;
    case edi_reg: offset = R_EDI*4, size=4;
    	break;

    case al_reg: offset = R_EAX*4, size=1;
			   break;
    case cl_reg: offset = R_ECX*4, size=1;
			   break;
    case dl_reg: offset = R_EDX*4, size=1;
			   break;
    case bl_reg: offset = R_EBX*4, size=1;
			   break;
    case ah_reg: offset = R_EAX*4+1, size=1;
			   break;
    case ch_reg: offset = R_ECX*4+1, size=1;
			   break;
    case dh_reg: offset = R_EDX*4+1, size=1;
			   break;
    case bh_reg: offset = R_EBX*4+1, size=1;
			   break;
       
    case ax_reg: offset = R_EAX*4, size=2; 
			   break;
    case cx_reg: offset = R_ECX*4, size=2; 
			   break;
    case dx_reg: offset = R_EDX*4, size=2; 
			   break;
    case bx_reg: offset = R_EBX*4, size=2; 
			   break;
    case sp_reg: offset = R_ESP*4, size=2; 
			   break;
    case bp_reg: offset = R_EBP*4, size=2; 
			   break;
    case si_reg: offset = R_ESI*4, size=2; 
			   break;
    case di_reg: offset = R_EDI*4, size=2; 
			   break;

    case eip_reg: 
            if (is_write) 
              cpu_single_env->eip = *(uint32_t *)buf;
            else
    		  *(uint32_t *)buf = cpu_single_env->eip;
    		return;
    case cr3_reg: 
     		if (is_write) assert(0);
     		else
    			*(uint32_t *)buf = cpu_single_env->cr[3];
    		return;

    default: 
     	assert(0);
  }
  
  //XXX:Here, we assume little endian in the host machine!!! 
  if(is_write)
    memcpy((unsigned char *)cpu_single_env->regs + offset, buf, size);
  else
    memcpy(buf, (unsigned char *)cpu_single_env->regs + offset, size); 
}

void TEMU_read_register(int reg_id, void *buf)
{
  TEMU_register_rw(reg_id, buf, 0);
}

void TEMU_write_register(int reg_id, void *buf)
{
  TEMU_register_rw(reg_id, buf, 1);
}

target_ulong TEMU_get_phys_addr(target_ulong addr)
{
    int mmu_idx, index;
	uint32_t phys_addr;
	CPUState *env = cpu_single_env? cpu_single_env: first_cpu;

    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    mmu_idx = cpu_mmu_index(env);
    if (__builtin_expect(env->tlb_table[mmu_idx][index].addr_read !=
                         (addr & TARGET_PAGE_MASK), 0)) {
		phys_addr = cpu_get_phys_page_debug(env, addr&TARGET_PAGE_MASK);
        if(phys_addr == -1) return -1;
		phys_addr += addr&(TARGET_PAGE_SIZE - 1);
 		return phys_addr;
    }
#if 0 //not sure if we need it --Heng Yin   
    pd = env->tlb_table[mmu_idx][index].addr_read & ~TARGET_PAGE_MASK;
    if (pd > IO_MEM_ROM && !(pd & IO_MEM_ROMD)) {
        cpu_abort(env, "Trying to execute code outside RAM or ROM at 0x" TARGET_FMT_lx "\n", addr);
    }
#endif
    return addr + env->tlb_table[mmu_idx][index].addend - (unsigned long)phys_ram_base;
}

uint32_t TEMU_get_physaddr_with_cr3(target_ulong cr3, target_ulong addr)
{
    CPUState *env = cpu_single_env? cpu_single_env: first_cpu;
    target_ulong saved_cr3 = env->cr[3];
	uint32_t phys_addr;

 	env->cr[3] = cr3;
	phys_addr = cpu_get_phys_page_debug(env, addr&TARGET_PAGE_MASK);

    env->cr[3] = saved_cr3;
    return phys_addr;
}



int TEMU_memory_rw(uint32_t addr, void *buf, int len, int is_write)
{
  int l;
  target_ulong page, phys_addr;

  while (len > 0) {
    page = addr & TARGET_PAGE_MASK;
    phys_addr = TEMU_get_phys_addr(page);
    if(phys_addr == -1)
      return -1;
    l = (page + TARGET_PAGE_SIZE) -addr;
    if (l > len) 
      l = len;
    cpu_physical_memory_rw(phys_addr + (addr & ~ TARGET_PAGE_MASK),
        buf, l, is_write);
    len -= l;
    buf += l;
    addr += l;
  }
  return 0;    
}

int TEMU_memory_rw_with_cr3(target_ulong cr3, uint32_t addr, void *buf, int len, int is_write)
{
  int l;
  target_ulong page, phys_addr;

  while (len > 0) {
    page = addr & TARGET_PAGE_MASK;
    phys_addr = TEMU_get_physaddr_with_cr3(cr3, page);
    if(phys_addr == -1)
      return -1;
    l = (page + TARGET_PAGE_SIZE) -addr;
    if (l > len) 
      l = len;
    cpu_physical_memory_rw(phys_addr + (addr & ~ TARGET_PAGE_MASK),
        buf, l, is_write);
    len -= l;
    buf += l;
    addr += l;
  }
  return 0;    
}


int TEMU_read_mem(uint32_t vaddr, int len, void *buf)
{
  return TEMU_memory_rw(vaddr, buf, len, 0);
}

int TEMU_write_mem(uint32_t vaddr, int len, void *buf)
{
  return TEMU_memory_rw(vaddr, buf, len, 1);
}

int TEMU_read_mem_with_cr3(target_ulong cr3, uint32_t vaddr, int len, void *buf)
{
  return TEMU_memory_rw_with_cr3(cr3, vaddr, buf, len, 0);
}

int TEMU_write_mem_with_cr3(target_ulong cr3, uint32_t vaddr, int len, void *buf)
{
  return TEMU_memory_rw_with_cr3(cr3, vaddr, buf, len, 1);
}



int TEMU_bdrv_pread(void *bs, int64_t offset, void *buf, int count)
{
  return bdrv_pread((BlockDriverState *)bs, offset, buf, count);
}

#ifdef DEFINE_BLOCK_BEGIN
int TEMU_block_begin()
{
  if (!TEMU_emulation_started)
    return 0;
  //block_begin needs to be called globally
  int res = temu_plugin->block_begin();
  return res;
}
#endif

#ifdef DEFINE_BLOCK_END
void TEMU_block_end()
{
  if (should_monitor && temu_plugin->block_end)
    temu_plugin->block_end();
}
#endif

#ifdef DEFINE_INSN_BEGIN
void TEMU_insn_begin(uint32_t pc_start)
{
  if (!TEMU_emulation_started || !should_monitor)
    return;
#if TAINT_ENABLED && !defined(DEFINE_INSN_END)
  insn_tainted = 0;
#endif  

  if (temu_plugin->insn_begin)
    temu_plugin->insn_begin();
}
#endif

#ifdef DEFINE_INSN_END
void TEMU_insn_end()
{
  if (!TEMU_emulation_started || !should_monitor)
    return;

  if (temu_plugin->insn_end)
    temu_plugin->insn_end();
#if TAINT_ENABLED    
  insn_tainted = 0;
#endif
}
#endif


void TEMU_update_cr3()
{
  if (!temu_plugin) 
    should_monitor = 0;
  else
    should_monitor = (temu_plugin->monitored_cr3 == 0 ||
                    temu_plugin->monitored_cr3 == cpu_single_env->cr[3]);
}

void TEMU_do_interrupt(int intno, int is_int, target_ulong next_eip)
{
#ifdef HANDLE_INTERRUPT
  if(temu_plugin) temu_plugin->do_interrupt(intno, is_int, next_eip);
#endif
}

void TEMU_after_iret_protected()
{
#ifdef HANDLE_INTERRUPT
  if(temu_plugin) temu_plugin->after_iret_protected();
#endif
}


int TEMU_get_page_access(uint32_t addr)
{
  uint32_t pde_addr, pte_addr;
  uint32_t pde, pte;
  CPUState *env = cpu_single_env? cpu_single_env: first_cpu;

  if (env->cr[4] & CR4_PAE_MASK) {
	uint32_t pdpe_addr, pde_addr, pte_addr;
	uint32_t pdpe;

	pdpe_addr = ((env->cr[3] & ~0x1f) + ((addr >> 30) << 3)) & 
	  env->a20_mask;
	pdpe = ldl_phys(pdpe_addr);
	if (!(pdpe & PG_PRESENT_MASK))
	  return -1;

	pde_addr = ((pdpe & ~0xfff) + (((addr >> 21) & 0x1ff) << 3)) &
	  env->a20_mask;
	pde = ldl_phys(pde_addr);
	if (!(pde & PG_PRESENT_MASK)) {
	  return -1;
	}
	if (pde & PG_PSE_MASK) {
	  /* 2 MB page */
	  return (pde & PG_RW_MASK);
	} 

	/* 4 KB page */
	pte_addr = ((pde & ~0xfff) + (((addr >> 12) & 0x1ff) << 3)) &
	  env->a20_mask;
	pte = ldl_phys(pte_addr);
	if(!(pte & PG_PRESENT_MASK))
	  return -1;
	return (pte & PG_RW_MASK);
  } 

  if (!(env->cr[0] & CR0_PG_MASK)) {
	/* page addressing is disabled */
	return 1;
  }

  /* page directory entry */
  pde_addr = ((env->cr[3] & ~0xfff) + ((addr >> 20) & ~3)) & env->a20_mask;
  pde = ldl_phys(pde_addr);
  if (!(pde & PG_PRESENT_MASK)) 
	return -1;
  if ((pde & PG_PSE_MASK) && (env->cr[4] & CR4_PSE_MASK)) {
	/* page size is 4MB */
	return (pde & PG_RW_MASK);
  }

  /* page directory entry */
  pte_addr = ((pde & ~0xfff) + ((addr >> 10) & 0xffc)) & env->a20_mask;
  pte = ldl_phys(pte_addr);
  if (!(pte & PG_PRESENT_MASK))
	return -1;

  /* page size is 4K */
  return (pte & PG_RW_MASK);
}


void TEMU_stop_vm()
{
/*  CPUState *env = cpu_single_env? cpu_single_env: mon_get_cpu();
  env->exception_index = EXCP_HLT;
  longjmp(env->jmp_env, 1); */
  vm_stop(EXCP_INTERRUPT);
}

void TEMU_loadvm(void *opaque)
{
  char **loadvm_args = opaque;
  if(loadvm_args[0]) {
    do_loadvm(loadvm_args[0]);
    free(loadvm_args[0]);
    loadvm_args[0] = NULL;
  }

  if(loadvm_args[1]) {
    do_load_plugin(loadvm_args[1]);
    free(loadvm_args[1]);
    loadvm_args[1] = NULL;
  }

  if(loadvm_args[2]) {
    TEMU_after_loadvm(loadvm_args[2]);
    free(loadvm_args[2]);
    loadvm_args[2] = NULL;
  }
}

#ifdef CALLSTRING_ANALYSIS
void TEMU_call_analysis(uint32_t next_eip)
{
  if (!TEMU_emulation_started || !should_monitor)
    return;

  if(temu_plugin->call_analysis != NULL){
  	temu_plugin->call_analysis(next_eip);
  }
}

#endif

#ifdef RET_ANALYSIS
void TEMU_ret_analysis(uint32_t next_eip){
  if (!TEMU_emulation_started || !should_monitor)
    return;
	
  if(temu_plugin->ret_analysis != NULL){
 	 temu_plugin->ret_analysis(next_eip);
  }
}
#endif

static void TEMU_save(QEMUFile *f, void *opaque)
{
  uint32_t len = strlen(temu_plugin_path) + 1;
  qemu_put_be32(f, len);
  qemu_put_buffer(f, temu_plugin_path, len);
  
  //save guest.log 
  //we only save guest.log when no plugin is loaded
  if(len == 1) { 
	  FILE *fp = fopen("guest.log", "r");
	  uint32_t size;
	  if(!fp) {
	    fprintf(stderr, "cannot open guest.log!\n");
	    return;
	  }

	  fseek(fp, 0, SEEK_END);
	  size = ftell(fp);
	  qemu_put_be32(f, size);
	  rewind(fp);
	  if(size > 0) {
	    TEMU_CompressState_t state;
	    if(TEMU_compress_open(&state, f) < 0)
	      return;
	    
	    while(!feof(fp)) {
	      uint8_t buf[4096];
	      size_t res = fread(buf, 1, sizeof(buf), fp);
	      TEMU_compress_buf(&state, buf, res);
	    }
	  
	    TEMU_compress_close(&state);
	  }
	  fclose(fp);
  }
  
  qemu_put_be32(f, TEMU_emulation_started); 
  qemu_put_be32(f, 0x12345678); //terminator
}

static int TEMU_load(QEMUFile *f, void *opaque, int version_id)
{
  uint32_t len = qemu_get_be32(f);
  char tmp_plugin_path[PATH_MAX];
  
  if(plugin_handle) 
    do_unload_plugin();
  qemu_get_buffer(f, tmp_plugin_path, len);
  if(tmp_plugin_path[len - 1] != 0)
    return -EINVAL;
  
  //load guest.log
  if(len == 1) {
    fclose(guestlog);
    if (!(guestlog = fopen("guest.log", "w"))) {
      fprintf(stderr, "cannot open guest.log for write!\n");
      return -EINVAL;
    }
    
    uint32_t file_size = qemu_get_be32(f);
    uint8_t buf[4096];
    uint32_t i;
    TEMU_CompressState_t state;
    if(TEMU_decompress_open(&state, f) < 0) 
      return -EINVAL;
    
    for(i=0; i<file_size; ) {
      uint32_t len = (sizeof(buf) < file_size-i)? sizeof(buf): file_size - i;
      if(TEMU_decompress_buf(&state, buf, len) < 0)
        return -EINVAL;
        
      fwrite(buf, 1, len, guestlog);
      i += len;
    }
    TEMU_decompress_close(&state);
    fflush(guestlog);
  }  
     
  if(len > 1)	
    do_load_plugin(tmp_plugin_path);
    
  uint32_t emul_started = qemu_get_be32(f);
  if(emul_started) 
    do_enable_emulation();
  else
    do_disable_emulation();

  uint32_t terminator = qemu_get_be32(f);
  if(terminator != 0x12345678)
    return -EINVAL;
    
  return 0;
}

void TEMU_syscall_monitor(){
  uint32_t sysidx;
  if(temu_plugin){
  	if(temu_plugin->syscall_monitor){
  		TEMU_read_register(eax_reg,&sysidx);
  		temu_plugin->syscall_monitor(sysidx);
  	}
  }
}

void TEMU_init()
{
  register_savevm("TEMU", 0, 1, TEMU_save, TEMU_load, NULL);
  TEMU_vm_compress_init();
#if TAINT_ENABLED
  taintcheck_init();
#endif
}


