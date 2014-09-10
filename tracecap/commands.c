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
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "TEMU_lib.h"
#include "tracecap.h"
#include "conf.h"
#include "procmod.h"
#include "libfstools.h"
#include "slirp.h"
#include "read_linux.h"
#include "reg_ids.h"
#include "shared/procmod.h"
#include "conditions.h"
#include "readwrite.h"
#include "network.h"
#include "errdet.h"
#include "state.h"

/* plugin loading */
//#include <dlfcn.h>
//#include <assert.h>
#include "hookapi.h"
#include "function_map.h"
#include "hook_plugin_loader.h"
#include "hook_helpers.h"


static plugin_interface_t tracing_interface;

char current_mod[32] = "";
char current_proc[32] = "";

#if TAINT_ENABLED
static int taint_sendkey_id = 0;
int keystroke_offset = 0; // Global counter for keystrokes, used for offset
#endif

uint32_t current_tid = 0; // Current thread id
static char tracefile[256];

/* Loop induction variable variables */
#define MAX_LOOP_IVS 5
size_t num_loop_ivs = 0;
uint32_t loop_ivs_sarray[MAX_LOOP_IVS];

#ifdef MEM_CHECK
/* Module's mem_read tainting info */
int taint_module_is_set = 0;
uint32_t taint_module_base = 0;
uint32_t taint_module_size = 0;
#endif /* #ifdef MEM_CHECK */

static term_cmd_t tracing_info_cmds[] = {
  {NULL, NULL},
};


typedef struct {
  FS_INFO *fs;
  IMG_INFO *img;
  void *bs;
} disk_info_t;

static disk_info_t disk_info[5];

#if TAINT_ENABLED
typedef struct {
  uint64_t cluster;
  taint_record_t rec;
  int count;
  FS_INFO *fs;
} taintcluster_t;

static void tracing_taint_disk (uint64_t addr, uint8_t * record, void *opaque) {
        return;
}

static void taint_disk_block(char filename[], uint64_t block, int size,
  uint32_t origin, int disk_index, uint32_t offset)
{
  int i;
  int j;
  int count;
  taint_record_t records[64];

  printf("%" PRIx64 ":%d[%d] ", block, size, origin);

  bzero(records, sizeof(records));
  for (i = 0; i < 64; i++) {
    records[i].numRecords = 1;
    records[i].taintBytes[0].source = TAINT_SOURCE_FILE_IN;
    records[i].taintBytes[0].origin = origin;
    memset(&(records[i].taintBytes[1]), 0,
      (MAX_NUM_TAINTBYTE_RECORDS-1)*sizeof(TaintByteRecord));
  }
  
  for (i = 0, count = 0; i < size; i += 64, count++) {
    for(j = 0; j < 64; j++) {
      records[j].taintBytes[0].offset = offset + 64 * count + j;
    }
   
    taintcheck_taint_disk((block * disk_info[disk_index].fs->block_size +
                           i + 0x7e00) / 64,
                          (uint64_t) - 1,
                          0, 64, (uint8_t *) records,
                          disk_info[disk_index].bs);
  }
}

void do_taint_file(char *filename, int dev_index, uint32_t taint_id)
{

  FS_INFO *fs;
  int i;
  uint32_t offset;
  extern uint32_t tsk_errno;

  tsk_errno = 0;

  term_printf("Tainting disk %d file %s\n", dev_index, filename);

  if (!(fs = disk_info[dev_index].fs)) {
    term_printf("Could not find disk_info\n");
    return;
  }

  char *path = strdup(filename);
  if (!path) {
    term_printf("Empty path\n");
    return;
  }
  if (!fs_ifind_path(fs, IFIND_PATH | IFIND_PATH, path) &&
      !fs_icat(fs, 0, found_path_inode, 0, 0, 1 << 5))
  {
    for (i = 0, offset=0; i < found_icat_nblock; i++) {
      if (taint_id == 0)        //it means we are tainting a directory
        taint_disk_block(filename, found_icat_blocks[i].addr,
          found_icat_blocks[i].size,
          //we generate an ID in [400, 1000)
          (found_icat_blocks[i].addr % 600) + 400, dev_index, offset);
      else
        taint_disk_block(filename, found_icat_blocks[i].addr,
                         found_icat_blocks[i].size, taint_id, dev_index, offset);

    offset += found_icat_blocks[i].size;
    }
    term_printf("Tainted file %s\n", filename);
  }
  else {
    term_printf("Could not find file\n");
  }
  printf("\n");
  free(path);

}

void do_taint_sendkey(const char *string, int id)
{
  taint_sendkey_id = id;
  do_send_key(string);
}

#endif //TAINT_ENABLED


#ifdef MEM_CHECK
void do_taint_module(uint32_t pid, const char *name)
{
  tmodinfo_t *modinfo = locate_module_byname(name, pid);
  if (modinfo == NULL) {
    taint_module_is_set = 0;
    term_printf("Module '%s' not found in PID=%u. Won't taint any module.\n", 
		name, pid);
  } else {
    taint_module_is_set = 1;
    taint_module_base = modinfo->base;
    taint_module_size = modinfo->size;
    term_printf("Memory inside module '%s' will be tainted on read.\n",
		name);
  }
}
#endif /* #ifdef MEM_CHECK */

int is_kernel_instruction()
{
    return ((*TEMU_cpu_hflags & HF_CPL_MASK) != 3); 
}


#if TAINT_ENABLED
static void tracing_taint_propagate(int nr_src,
                            taint_operand_t * src_oprnds,
                            taint_operand_t * dst_oprnd,
                            int mode)
{
  if (0==tracing_table_lookup && 2==nr_src && PROP_MODE_MOVE==mode) {
    /* if first is untainted, clear taint info of second arg */
    if (src_oprnds[0].taint==0) {
    /* clear taint info of destination */
    if (0==dst_oprnd->type) /* register */
      taintcheck_taint_register(
        dst_oprnd->addr>>2, dst_oprnd->addr&3,
        dst_oprnd->size,
        0, NULL);
    else /* memory */
      taintcheck_taint_memory(
        dst_oprnd->addr,
        dst_oprnd->size,
        0, NULL);
    eh.tp = TP_MEMREAD_INDEX;
    return;
    } else
    nr_src = 1;
  }

  /* Propagate taint, this needs to be done for all instructions */
  default_taint_propagate(nr_src, src_oprnds, dst_oprnd, mode);

  /* No need to set tp in entry header if not tracing */
  if ((!tracing_start_condition) || (tracepid == 0))
    return;

  /* No need to set tp in entry header if not 
   * tracing kernel and kernel instruction */
  if ( is_kernel_instruction() && !tracing_kernel() )
    return;

  /* Instruction propagated taint. Set tp in entry header */
  if (eh.tp == TP_NONE) eh.tp = TP_SRC;

  if(mode == PROP_MODE_MOVE) {
     /* Check if it is a memory write with tainted index */
    if ((dst_oprnd->type == 1)) {
      uint64_t a0_tainted;
      a0_tainted = taintcheck_register_check(R_A0, 0, 4, NULL);
      if (a0_tainted != 0)
        eh.tp = TP_MEMWRITE_INDEX;
    }

    if(nr_src > 1) {
      if (src_oprnds[0].taint == 0) {
        eh.tp = TP_MEMREAD_INDEX;
      }
      else {
        eh.tp = TP_SRC;
      }
    }
  }
}

#endif

static void tracing_guest_message(char *message)
{
  handle_message(message);
  switch (message[0]) {
  case 'P':
    parse_process(message);
    break;
  case 'M':
    parse_module(message);
    break;
  }
}

static int tracing_block_begin()
{
  hookapi_check_call(temu_plugin->monitored_cr3 == TEMU_cpu_cr[3] && 
                    !TEMU_is_in_kernel());

  /* If not tracing kernel and kernel instruction , return */
    if ( is_kernel_instruction() && !tracing_kernel() )
      return 0;

/*
if (*TEMU_cpu_eip == 0x71ab4a07) {
    uint32_t pid;
    char temp[64];
    find_process(TEMU_cpu_cr[3], temp, &pid);
    term_printf("Process %u uses connect function\n", pid);
}
*/

  /* If not tracing by pid or by name, return */
  if  ((tracepid == 0) && (!procname_is_set()))
    return 0;

  /* Get thread id */
  current_tid = get_current_tid();

  tmodinfo_t *mi;
  mi = locate_module(*TEMU_cpu_eip, TEMU_cpu_cr[3],
                     current_proc);
  strncpy(current_mod, mi ? mi->name : "unknown",31);
  current_mod[31] = '\0';

  if (procname_is_set()) {
    char temp[64];
    uint32_t pid;


    find_process(TEMU_cpu_cr[3], temp, &pid);
    if (procname_match(temp)) {
      do_tracing(pid, tracefile);
      term_printf("Tracing %s\n", procname_get());
      procname_clear();
    }
  }

  if (modname_is_set()) {
      if (modname_match(current_mod) &&
	  (temu_plugin->monitored_cr3 == TEMU_cpu_cr[3]))
      {
	  tracing_start_condition = 1;
	  modname_clear();
      }
  }

  return 0;
}

static void tracing_send_keystroke(int reg)
{
  /* If not tracing, return */
  if  (tracepid == 0)
    return;

  //term_printf ("Keystroke received: %d\n",taint_sendkey_id);
#if TAINT_ENABLED
  taint_record_t record;

  if (taint_sendkey_id) {
    uint32_t keystroke = TEMU_cpu_regs[reg];
    term_printf ("Tainting keystroke: %d %08X\n", reg,keystroke);
    record.numRecords = 1;
    record.taintBytes[0].source = TAINT_SOURCE_KEYBOARD_IN;
    record.taintBytes[0].origin = taint_sendkey_id;
    record.taintBytes[0].offset = keystroke_offset;
    memset(&(record.taintBytes[1]), 0,
      (MAX_NUM_TAINTBYTE_RECORDS-1)*sizeof(TaintByteRecord));

    taintcheck_taint_register(reg, 0, 1, 1, (uint8_t *) &record);
    taint_sendkey_id = 0;
    keystroke_offset++;
  }
#endif 
}

static void tracing_bdrv_open(int index, void *opaque)
{
  if ((disk_info[index].img =
       img_open("qemu", 1, (const char **) &opaque)) == NULL) {
    tsk_error_print(stderr);
    return;
  }
  if (!(disk_info[index].fs = fs_open(disk_info[index].img, 0x7e00, NULL))
      && !(disk_info[index].fs =
           fs_open(disk_info[index].img, 0x00, NULL))) {
    tsk_error_print(stderr);
    if (tsk_errno == TSK_ERR_FS_UNSUPTYPE)
      fs_print_types(stderr);
    disk_info[index].img->close(disk_info[index].img);
    disk_info[index].img = NULL;
    return;
  }
  disk_info[index].bs = opaque;
}


static void tracing_bdrv_cleanup()
{
  int i;
  for(i=0; i<sizeof(disk_info)/sizeof(disk_info_t); i++) {
    disk_info_t *di = &disk_info[i];
    if(di->img == NULL) continue;
    if(di->fs != NULL) {
      di->fs->close(di->fs);
      di->fs = NULL;
    }
    di->img->close(di->img);
    di->img = NULL;
  }
}

static void stoptracing()
{
  term_printf("Received Signal: STOP\n");
  tracing_stop();
}

static void killtemu()
{
  term_printf("Received Signal: KILL\n");
  exit(EXIT_KILL_SIGNAL);
}


void do_load_hooks (const char *hooks_dirname, const char *plugins_filename)
{
  if (strcmp(plugins_filename, "") != 0)
    strncpy(hook_plugins_filename, plugins_filename, 256);
  if (strcmp(hooks_dirname, "") != 0)
    strncpy(hook_dirname, hooks_dirname, 256);

  // Load hooks if requested via TEMU monitor
  load_hook_plugins(&(temu_plugin->monitored_cr3),
    hook_plugins_filename,
    hook_dirname,
    &g_plugin_info,
    ini);
}

void do_load_config (const char *config_filepath)
{
  int err = 0;

  // Parse configuration file
  err = check_ini(config_filepath);
  if (err) {
    term_printf ("Could not find INI file: %s\nTry again.\n", config_filepath);
  }
}


int uint32_compare(const void* u1, const void* u2) {
  return *((uint32_t *) u1) - *((uint32_t *) u2);
}

void do_add_iv_eip(uint32_t eip)
{
  if (num_loop_ivs >= MAX_LOOP_IVS) {
    term_printf("max no. eips allowed (%d) is reached.\n", MAX_LOOP_IVS);
  }
  else {
    loop_ivs_sarray[num_loop_ivs++] = eip;
    qsort(&(loop_ivs_sarray[0]), num_loop_ivs, sizeof(uint32_t),
      uint32_compare);
  }
}

static int tracing_init()
{
  int err = 0;

  /* local hook API for instrumentation at certain EIP */
  hook_insn_begin = NULL;

  bzero(disk_info, sizeof(disk_info));

  function_map_init();
  init_hookapi();
  procmod_init();

  // setup signal handler to stop tracing
  signal(SIGUSR1, stoptracing);

  // SIGUSR2 is used by QEMU

  // setup signal handler to exit TEMU
  signal(SIGTERM, killtemu);

  procname_clear(); 

  // this is needed for file tainting
  qemu_pread = (qemu_pread_t)TEMU_bdrv_pread;

  // Parse configuration file
  err = check_ini(ini_main_default_filename);
  if (err) {
    term_printf ("Could not find INI file: %s\n"
                 "Use the command 'load_config <filename> to provide it.\n", 
                 ini_main_default_filename);
  }

  return 0;
}

static void tracing_cleanup()
{
  //TODO: other cleanup stuff, like function hooks, log files
    unload_hook_plugins();
    procmod_cleanup();
    hookapi_cleanup();
    function_map_cleanup();
    tracing_bdrv_cleanup();
}

void do_tracing_stop()
{
  tracing_stop();
}

void do_tracing(uint32_t pid, const char *filename)
{
  /* if pid = 0, stop trace */
  if (0 == pid)
    tracing_stop();
  else {
    int retval = tracing_start(pid, filename);
    if (retval < 0)
      term_printf("Unable to open log file '%s'\n", filename);
  }

  /* Print configuration variables */
  //print_conf_vars(); 
}

void do_tracing_by_name(const char *progname, const char *filename)
{
  /* If process already running, start tracing */
  uint32_t pid = find_pid_by_name(progname);
  uint32_t minus_one = (uint32_t)(-1);
  if (pid != minus_one) {
    do_tracing(pid,filename);
    return;
  }

  /* Otherwise, start monitoring for process start */
  procname_set(progname); 
  strncpy(tracefile, filename, 256);
  term_printf ("Waiting for process %s to start\n", progname);

#if 0
  /* Print configuration variables */
  print_conf_vars(); 
#endif
}

void do_save_state(uint32_t pid, uint32_t address, const char *filename)
{
  int err;
  err = save_state_at_addr(pid, address, filename);
  if (err)
    term_printf("Invalid pid or unable to open log file '%s'\n", filename);
}

void do_guest_modules(uint32_t pid)
{
  list_guest_modules(pid);
}


void do_clean_iv_eips()
{
  num_loop_ivs = (size_t) 0;
}

#if TAINT_ENABLED
void taint_loop_ivs()
{
    uint64_t mask = 0;
    taint_record_t taintrec[MAX_OPERAND_LEN]; /* taint_rec[] to write */
    int regnum = -1;
    int offset = 0;
    int length = 0;
    int index_itr = 0;
    int i=0;

    if (!bsearch(&(eh.address), &(loop_ivs_sarray[0]), num_loop_ivs,
     sizeof(uint32_t), uint32_compare))
  return;      /* skip if the current eip is not in loop_ivs_sarray[] */

    i = 0;                               /* only care about dest operand */
    if (eh.operand[i].type != TRegister)  /* ignore if it's not register */
  return;                 /* replace with continue; if it's a loop */

    /* get original taint recs */
    //regnum = regmapping[eh.operand[i].addr - 100];
    regnum = get_regnum(eh.operand[i]);
    offset = getOperandOffset(&eh.operand[i]);
    length = eh.operand[i].length;
    taintcheck_register_check(regnum, offset, length,
            (uint8_t *) taintrec);

    term_printf("logic reached\n");
    for (index_itr =0; index_itr < length; ++index_itr) {
  /* we're overwriting any existing taint records in the register */
  /* except loop_iv record from the same eip origin */
  /* in such case, we increment the counter (e.g. offset field) */
  if (taintrec[index_itr].taintBytes[0].source==TAINT_SOURCE_LOOP_IV
      && taintrec[index_itr].taintBytes[0].origin == eh.address) {
      ++(taintrec[index_itr].taintBytes[0].offset);
  } else {
      taintrec[index_itr].taintBytes[0].source =
    TAINT_SOURCE_LOOP_IV;
      taintrec[index_itr].taintBytes[0].origin = eh.address;
      taintrec[index_itr].taintBytes[0].offset = 1;
  }
  taintrec[index_itr].numRecords = 1;
  term_printf("IV tainted is %5s, EIP = 0x%8x, count = %5d\n",
        reg_name_from_id(eh.operand[i].addr),
        eh.address, taintrec[index_itr].taintBytes[0].offset);
    }

    mask = (1ULL<<eh.operand[i].length)-1;
    taintcheck_taint_register(regnum, offset, length, mask,
          (uint8_t *) taintrec);
}
#endif //TAINT_ENABLED

void tracing_insn_begin()
{
  /* If tracing start condition not satisified, or not tracing return */
  if ((!tracing_start_condition) || (tracepid == 0))
    return ;

  /* If not tracing kernel and kernel instruction , return */
  if ( is_kernel_instruction() && !tracing_kernel() )
    return;

  /* Clear flags before processing instruction */

  // Flag to be set if the instruction is written
  insn_already_written = 0;

  // Flag to be set if instruction encounters a page fault
  // NOTE: currently not being used. Tracing uses it to avoid logging twice
  // these instructions, but was missing some
  has_page_fault = 0;

  // Flag to be set if instruction accesses user memory
  access_user_mem = 0;

  /* Call the local hook, if needed */
  if (hook_insn_begin != NULL) {
    uint32_t eip = *TEMU_cpu_eip;
    (*hook_insn_begin)(eip);
  }

  /* Check if this is a system call */
  if (conf_log_external_calls) {
    uint32_t eip = *TEMU_cpu_eip;
    struct names_t *names = query_name(eip);
    uint32_t curr_tid = get_current_tid();
    if ((names != NULL) && (calllog)) {
      if ((names->fun_name != NULL) && (names->mod_name != NULL)) {
	fprintf(calllog,"Process %d TID: %d -> %s::%s @ EIP: 0x%08x\n",
	  tracepid,curr_tid,names->mod_name,names->fun_name,eip);
      }
      else {
	fprintf(calllog,"Process %d TID: %d -> ?::? @ EIP: 0x%08x\n", 
	  tracepid,curr_tid,eip);
      }
    }
  }

  /* Disassemble the instruction */
  if (skip_decode_address == 0) {
    decode_address(*TEMU_cpu_eip, &eh, skip_taint_info);
  }

#if TAINT_ENABLED && defined(TAINT_LOOP_IVS)
  /* If not tracing, skip */
  if (tracepid != 0)
      taint_loop_ivs();
#endif

#ifdef INSN_INFO
  savedeip = *TEMU_cpu_eip;
#endif

}

void tracing_insn_end()
{
  /* If tracing start condition not satisified, or not tracing return */
  if ((!tracing_start_condition) || (tracepid == 0))
    return ;

  /* If not tracing kernel and kernel instruction , return */
  if ( is_kernel_instruction() && !tracing_kernel())
    return;

  /* If partially tracing kernel but did not access user memory, return */
  if (is_kernel_instruction()) {
      if (tracing_kernel_partial() && (!access_user_mem))
	  return;
#if TAINT_ENABLED	  
      if (tracing_kernel_tainted() && (!insn_tainted))
	  return;
#endif	  
  }

  /* If instruction already written, return */
  if (insn_already_written == 1)
    return;

  /* Update the eflags */
  eh.eflags = *TEMU_cpu_eflags;
  eh.df = *TEMU_cpu_df;

  /* Update the thread id */
  eh.tid = current_tid;

  /* Clear eh.tp if inside a function hook */
  if (skip_taint_info > 0) eh.tp = TP_NONE;
  else {
    /* Update eh.tp if rep instruction */
    if ((eh.operand[2].usage == counter) && (eh.operand[2].tainted != 0))
      eh.tp = TP_REP_COUNTER;

    /* Updated eh.tp if sysenter */
    else if ((eh.rawbytes[0] == 0x0f) && (eh.rawbytes[1] == 0x34))
      eh.tp = TP_SYSENTER;
  }

  /* Split written operands if requested */
  if (conf_write_ops_at_insn_end) {
    update_written_operands (&eh);
  }

  /* Write the disassembled instruction to the trace */
  if (tracing_tainted_only()) {
#if TAINT_ENABLED
    if (insn_tainted)
      write_insn(tracelog,&eh);
#endif      
  }
  else {
    if (conf_trace_only_after_first_taint) {
      if ((received_tainted_data == 1) && (has_page_fault == 0)) {
	write_insn(tracelog,&eh);
      }
    }
    else {
      if (has_page_fault == 0) write_insn(tracelog,&eh);
    }
  }

  /* Record the thread ID of the first instruction in the trace, if needed */
  if (tracing_single_thread_only()) {
    if (tid_to_trace == -1 && insn_already_written == 1) {
      // If tid_to_trace is not -1, we record trace only the given thread id.
      tid_to_trace = get_current_tid();
    }
  }

}

int tracing_cjmp(uint32_t t0)
{
  /* No need to set tp in entry header if not tracing */
  if ((!tracing_start_condition) || (tracepid == 0))
    return 0;

  /* No need to set tp in entry header if not 
   * tracing kernel and kernel instruction */
  if ( is_kernel_instruction() && !tracing_kernel() )
    return 0;

  /* Set entry header flag for tainted cjmp */
  eh.tp = TP_CJMP;

  return 0;
}


void set_table_lookup(int state)
{
  if (state) {
    tracing_table_lookup = 1;
    term_printf("Table lookup on.\n");
  }
  else {
    tracing_table_lookup = 0;
    term_printf("Table lookup off.\n");
  }
}


/* Param format
<pid>:<traceFilename>:<detectMask>::<pidToSignal>:<processName>
*/
void tracing_after_loadvm(const char*param)
{
  char buf[256];
  strncpy(buf, param, sizeof(buf) - 1);
  buf[255] = '\0';
  int pid_to_signal = 0;

  char *pid_str = strtok(buf, ":");
  if (!pid_str)
    return;

  char *trace_filename = strtok(0, ":");
  if (!trace_filename)
    return;

  char *detect_mask_str = strtok(0, ":");
  if (!detect_mask_str)
    return;

  char *pid_to_signal_str = strtok(0, ":");

  char *process_name = strtok(0, ":");

  char *end = pid_str;
  int pid = (int) strtol (pid_str, &end, 10);
  if (end == pid_str) {
    pid = -1;
  }

  /* If no PID or Process_name, return */
  if ((process_name == NULL) && (pid == -1)) {
    term_printf("PARAM: %s\n", param);
    term_printf("START: %p END: %p\n", pid_str, end);
    term_printf("No PID or Process_name provided\n");
    return;
  }

  end = detect_mask_str;
  unsigned int detect_mask =
    (unsigned int) strtol (detect_mask_str, &end, 16);
  if (end == detect_mask_str) {
    term_printf("PARAM: %s\n", param);
    term_printf("START: %p END: %p\n", detect_mask_str, end);
    term_printf ("No detect mask provided\n");
    return;
  }

  if (pid_to_signal_str) {
    end = pid_to_signal_str;
    pid_to_signal = (int) strtol (pid_to_signal_str, &end, 10);
    if (end == pid_to_signal_str) {
      pid_to_signal = 0;
    }
  }

  term_printf ("PID: %d MASK: 0x%08x PID2SIGNAL: %d PROCESS_NAME: %s\n",
    pid, detect_mask, pid_to_signal, process_name);

  /* Enable emulation */
  do_enable_emulation();

#if TAINT_ENABLED
  /* Taint the network */
  do_taint_nic(1);

  /* Filter traffic (read from ini configuration file) */
  print_nic_filter();

  /* Enable detection */
  enable_detection(detect_mask);
#endif  


  /* OS dependant initialization */
  if (0 == taskaddr)
    init_kernel_offsets();
  if (0xC0000000 == kernel_mem_start) /* linux */
    update_proc(0);

  /* Load hooks */
  do_load_hooks("","");

  /* Start trace */
  if (process_name == NULL)
    do_tracing(pid, trace_filename);
  else
    do_tracing_by_name(process_name,trace_filename);

  /* Send signal to notify that trace is ready */
  //if (pid_to_signal != 0) kill(pid_to_signal,SIGUSR1);
  int pipe_fd = open("/tmp/temu.pipe",O_WRONLY);
  size_t num_written = write(pipe_fd,"OK",2);
  if (num_written != 2) {
    term_printf ("Error writing to /tmp/temu.pipe\n");
  }
  close(pipe_fd);

}

#ifdef MEM_CHECK
void tracing_mem_read(uint32_t virt_addr, uint32_t phys_addr, int size) {
  int offset = virt_addr - taint_module_base;

  if (taint_module_is_set && 
      virt_addr >= taint_module_base && 
      offset < taint_module_size) {
#if TAINT_ENABLED
    taint_record_t records[MAX_OPERAND_LEN];
    bzero(records, sizeof(records));
    int i;
    for(i=0;i<size;i++) {
      records[i].numRecords = 1;
      records[i].taintBytes[0].source = TAINT_SOURCE_MODULE;
      records[i].taintBytes[0].origin = TAINT_ORIGIN_MODULE;
      records[i].taintBytes[0].offset = offset + i;
    }
    taintcheck_taint_memory(phys_addr, size, (1<<size)-1, (uint8_t*)records);
#endif    
  } else {
    // do nothing
  }
}

void tracing_mem_write(uint32_t virt_addr, uint32_t phys_addr, int size) {
  // do nothing
}
#endif /* #ifdef MEMCHECK */

static term_cmd_t tracing_term_cmds[] = {
  /* operations to set taint source */
#if TAINT_ENABLED  
  {"taint_sendkey", "si", do_taint_sendkey,
   "key id", "send a tainted key to the guest system"},
  {"taint_nic", "i", do_taint_nic,
   "state", "set the network input to be tainted or not"},
  {"taint_file", "sii", do_taint_file,
   "filepath disk_index first_offset", "taint the content of a file on disk"},
   
#ifdef MEM_CHECK
  {"taint_module", "is", do_taint_module,
   "pid module_name", "taint the module on the process memory map"},
#endif /* #ifdef MEM_CHECK */

#endif

  /* operating system information */
  {"guest_ps", "", list_procs,
   "", "list the processes on guest system"},
  {"guest_modules", "i", do_guest_modules,
   "pid", "list the modules of the process with <pid>"},
  {"linux_ps", "", do_linux_ps,
   "", "list the processes on linux guest system"},

#if TAINT_ENABLED
  /* operations for attack detection */
  { "detect", "ss", do_detect,
    "type <on|off>", "turn on/off the detection for the following "
    "type attacks: "
    "tainteip, nullptr, exception, processexit, all. all are off "
    "by default." },
  { "action", "s", do_action,
    "type", "launch one of the following actions after attack detection: "
    "none, terminate(default), stopvm, stoptracing"},
#endif    

  /* operations to record instruction trace */
  { "trace", "iF", do_tracing,
    "pid filepath",
    "save the execution trace of a process into the specified file"},
  { "tracebyname", "sF", do_tracing_by_name,
    "name filepath",
    "save the execution trace of a process into the specified file"},
  { "trace_stop", "", do_tracing_stop,
    "", "stop tracing current process(es)"},
  { "tc_modname", "s", tc_modname,
    "modulename", "start saving execution trace upon entering the "
    "specified module"},
  { "tc_address", "i", tc_address,
    "codeaddress", "start saving execution trace upon reaching the "
    "specified virtual address"},
  { "tc_address_start", "ii", tc_address_start,
    "codeaddress timehit", "start saving execution trace upon reaching "
    "the specified virtual address for the (timehit+1)th times since "
    "the call of this tc_address_start command"},
  { "tc_address_stop", "ii", tc_address_stop,
    "codeaddress timehit", "stop saving execution trace upon reaching the "
    "specified virtual address for the (timehit+1)th times since the "
    "storing of execution trace"},

  /* set taint or tracing filters */
  { "table_lookup", "i", set_table_lookup,
      "state", "set flag to propagate tainted memory index"},
  { "ignore_dns", "i", set_ignore_dns,
      "state", "set flag to ignore received DNS packets"},
#if TAINT_ENABLED      
  { "taint_nic_filter", "ss", (void (*)())update_nic_filter,
      "<clear|proto|sport|dport|src|dst> value", 
      "Update filter for tainting NIC"},
  { "filter_tainted_only", "i", set_tainted_only,
    "state", "set flag to trace only tainted instructions"},
  { "filter_single_thread_only", "i", set_single_thread_only,
    "state", "set flag to trace only instructions from the same thread as the first instruction"},
  { "filter_kernel_tainted", "i", set_kernel_tainted,
    "state", "set flag to trace tainted kernel instructions in addition to "
    "user instructions"},
#endif    
  { "filter_kernel_all", "i", set_kernel_all,
    "state", "set flag to trace all kernel instructions in addition to "
    "user instructions"},
  { "filter_kernel_partial", "i", set_kernel_partial,
    "state", "set flag to trace kernel instructions that modify user "
    "space memory"},

  /* operations to record memory state */
  {"save_state", "iis", do_save_state,
   "pid address filepath",
   "save the state (register and memory) of a process when its execution "
   "hits the specified address "
   "(address needs to be the first address in a basic block)"},

  /* operations for induction variables */
  { "add_iv_eip", "i", do_add_iv_eip,
    "eip", "add a new eip to a list of know induction variable eips"},
  { "clean_iv_eips", "", do_clean_iv_eips,
    "", "clean up a list of induction variable eips"},

  /* operations for hooks */
  { "load_hooks", "FF", do_load_hooks,
    "hooks_dirname  plugins_filepath",
    "change hooks paths (hook directory and plugins.active)"},

  /* load a configuration file */
  { "load_config", "F", do_load_config,
    "configuration_filepath", "load configuration info from given file"},

  {NULL, NULL},
};

plugin_interface_t * init_plugin()
{
  if (0x80000000 == kernel_mem_start)
    comparestring = strcasecmp;
  else
    comparestring = strcmp;

  tracing_interface.plugin_cleanup = tracing_cleanup;
#if TAINT_ENABLED  
  tracing_interface.taint_record_size = sizeof(taint_record_t);
  tracing_interface.taint_propagate = tracing_taint_propagate;
  tracing_interface.taint_disk = tracing_taint_disk;
  tracing_interface.eip_tainted = tainteip_detection;
  tracing_interface.cjmp = tracing_cjmp;
  tracing_interface.nic_recv = tracing_nic_recv;
  tracing_interface.nic_send = tracing_nic_send;
  tracing_interface.send_keystroke = tracing_send_keystroke;
#endif  

  tracing_interface.guest_message = tracing_guest_message;
  tracing_interface.block_begin = tracing_block_begin;
  tracing_interface.insn_begin = tracing_insn_begin;
  tracing_interface.insn_end = tracing_insn_end;
  tracing_interface.term_cmds = tracing_term_cmds;
  tracing_interface.info_cmds = tracing_info_cmds;
  tracing_interface.bdrv_open = tracing_bdrv_open;
  tracing_interface.after_loadvm = tracing_after_loadvm;
#ifdef MEM_CHECK
  tracing_interface.mem_read = tracing_mem_read;
  tracing_interface.mem_write = tracing_mem_write;
#endif /* #ifdef MEM_CHECK */
  removeproc_notify = procexit_detection;

  tracing_init ();
  return &tracing_interface;
}
