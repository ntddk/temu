/*
TEMU is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.
*/

#include <inttypes.h>
#include <string>
#include <list>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

extern "C" {
#include "config.h"
#include "TEMU_lib.h"
#include "procmod.h"
#include "hookapi.h"
#include "read_linux.h"
#include "hooks/function_map.h"
};

using namespace std;

typedef struct {
  string name;
  uint32_t base;
  uint32_t size;
}module_info_t;

typedef struct {
  uint32_t cr3;
  uint32_t pid;
  string name;
  list<module_info_t *> module_list; //we make sure the list is sorted
}process_info_t;

static list<process_info_t *> process_list;

createproc_notify_t createproc_notify=NULL;
removeproc_notify_t removeproc_notify=NULL;
loadmodule_notify_t loadmodule_notify=NULL;

// MIN: process tracking...
loadmainmodule_notify_t loadmainmodule_notify = NULL;

int insert_module_info(list<module_info_t *> &module_list, const char *name, 
					uint32_t base, uint32_t size)
{
  module_info_t *mod = new module_info_t();
  module_info_t *mod2;
  if (mod == NULL)
    return -1;

  mod->name = name;
  mod->base = base;
  mod->size = size;

  list<module_info_t *>::iterator iter;
  for (iter = module_list.begin(); iter != module_list.end(); iter++) {
    mod2 = *iter;
    if (mod2->base > base)
      break;

    if (mod2->base + mod2->size > base) {
      //there is overlapped region
      iter = module_list.erase(iter);
      iter--; 
      delete mod2;
    }
  }
  module_list.insert(iter, mod);
  return 0;
}

int remove_module_info(list<module_info_t *> &module_list, uint32_t base)
{
  module_info_t *mod;
  list<module_info_t *>::iterator iter;
  for (iter = module_list.begin(); iter != module_list.end(); iter++) {
    mod = *iter;
    if (mod->base == base) {
      module_list.erase(iter);
      delete mod;
      break;
    }
  }
  return 0;
}

int procmod_insert_modinfo(uint32_t pid, uint32_t cr3, const char *name,
                           uint32_t base, uint32_t size)
{
  list<process_info_t *>::iterator iter;
  process_info_t *proc;

  for (iter = process_list.begin(); iter!=process_list.end(); iter++) {
    proc = *iter;
    if (proc->pid == pid) {
      if (proc->name.length() == 0) {
        //first loaded module is the main executable
        proc->cr3 = cr3;
        proc->name = name;

		// MIN: process tracking...
		// the main moduled is being loaded.
		if (loadmainmodule_notify != NULL)
          loadmainmodule_notify(pid, (char*)name);
      }
      break;
    }
  }

  if (iter == process_list.end()) //pid not found
    return -1;

  insert_module_info(proc->module_list, name, base, size);
  return 0;
}

int procmod_remove_modinfo(uint32_t pid, uint32_t base)
{
  list<process_info_t *>::iterator iter;
  process_info_t *proc;

  for (iter = process_list.begin(); iter!=process_list.end(); iter++) {
    proc = *iter;
    if (proc->pid == pid)
      break;
  }

  if (iter == process_list.end()) //pid not found
    return -1;

  remove_module_info(proc->module_list, base);
  return 0;
}


int procmod_createproc(uint32_t pid, uint32_t cr3, const char *name)
{
  list<process_info_t *>::iterator iter;
  process_info_t *proc = new process_info_t();
  if (proc == NULL)
    return -1;

  proc->pid = pid;
  proc->cr3 = cr3;
  proc->name = name;

  for (iter = process_list.begin(); iter != process_list.end(); iter++) {
    process_info_t *aproc = *iter;
    if (aproc->pid > pid)
      break;
  }

  process_list.insert(iter, proc);
  if(createproc_notify) createproc_notify(pid, cr3);

  return 0;
}

int procmod_removeproc(uint32_t pid)
{
  if(removeproc_notify) removeproc_notify(pid);

  list<process_info_t *>::iterator iter;
  process_info_t *proc;
  module_info_t *mod;

  for (iter = process_list.begin(); iter != process_list.end(); iter++) {
    proc = *iter;
    if (proc->pid == pid) {

      while (!proc->module_list.empty()) {
        mod = proc->module_list.front();
        proc->module_list.pop_front();
        delete mod;
      }
  
      process_list.erase(iter);
//      remove_threads_by_cr3(cr3);
      delete proc;
      break;
    }
  }
  return 0;
}


static int procmod_remove_all()
{
  process_info_t *proc;
  module_info_t *mod;

  while (!process_list.empty()) {
    proc = process_list.front();
    while (!proc->module_list.empty()) {
      mod = proc->module_list.front();
      proc->module_list.pop_front();
      delete mod;
    }

    process_list.pop_front();
    delete proc;
  }
  return 0;
}


int update_proc(void *opaque)
{
//    long taskaddr = 0xC033C300; 
  int pid;
  uint32_t cr3, pgd, mmap;
  uint32_t nextaddr = 0;

  char comm[512];

  procmod_remove_all();

  nextaddr = taskaddr;
  do {
    pid = get_pid(nextaddr);
    pgd = get_pgd(nextaddr); 
    cr3 = pgd - 0xc0000000;  //subtract a page offset 
    if (pid != 0) { // Skip the Linux idle process ("swapper")
      get_name(nextaddr, comm, 512);
      procmod_createproc(pid, cr3, comm);

      mmap = get_first_mmap(nextaddr);
      while (0 != mmap) {
	get_mod_name(mmap, comm, 512);
	//term_printf("0x%08lX -- 0x%08lX %s\n", get_vmstart(env, mmap),
	//            get_vmend(env, mmap), comm); 
	int base = get_vmstart(mmap); 
	int size = get_vmend(mmap) - get_vmstart(mmap);
	procmod_insert_modinfo(pid, pgd, comm, base, size);
      
	char message[612]; 
	snprintf(message, sizeof(message), "M %d %x \"%s\" %x %d", pid, pgd, comm, base, size); 
	handle_message(message); 

	char funcfile[128]; 
	snprintf(funcfile, 128, "/tmp/%s.func", comm); 
	FILE *fp = fopen(funcfile, "r");
	if (fp) {
	  while (!feof(fp)) {
	    int offset; 
	    char fname[128]; 
	    if (fscanf(fp, "%x %128s", &offset, fname) == 2) {
	      snprintf(message, 128, "F %s %s %x ", comm, 
		       fname, offset); 
		  handle_message(message); 
	    }
	  }
	  fclose(fp); 
	}
	
	mmap = get_next_mmap(mmap);

      }
    }

    nextaddr = next_task_struct(nextaddr);

  } while (nextaddr != taskaddr);

  return 0;
}


void procmod_cleanup()
{
  procmod_remove_all();
//  remove_all_threads();
  deregister_savevm("procmod", 0);
}



static tmodinfo_t *find_module_byeip(uint32_t eip, list<module_info_t *> &module_list)
{
  static tmodinfo_t mi;

  list<module_info_t *>::iterator iter;
  for (iter = module_list.begin(); iter != module_list.end(); iter ++) {
    module_info_t *mod = *iter;
    if (mod->base <= eip && mod->size + mod->base > eip) {
      strncpy(mi.name, mod->name.c_str(), sizeof(mi.name)-1);
      mi.base = mod->base;
      mi.size = mod->size;
      return &mi;
    }
 
    if (mod->base > eip)
      break;
  }

  return NULL;
}


static tmodinfo_t *find_module_byname(const char *name, list<module_info_t *> &module_list)
{
  static tmodinfo_t mi;

  list<module_info_t *>::iterator iter;
  for (iter = module_list.begin(); iter != module_list.end(); iter ++) {
    module_info_t *mod = *iter;
    if (strcasecmp(mod->name.c_str(), name) == 0) {
      strncpy(mi.name, mod->name.c_str(), sizeof(mi.name)-1);
      mi.base = mod->base;
      mi.size = mod->size;
      return &mi;
    }
  }

  return NULL;
}



tmodinfo_t *locate_module(uint32_t eip, uint32_t cr3, char *proc_name)
{
  list<process_info_t *>::iterator iter;
  for (iter = process_list.begin(); iter != process_list.end(); iter++) {
    process_info_t *proc = *iter;

    //FIXME: here we hardcode the boundary of kernel memory space.
    //we need better solution.
    if(eip > 0x80000000 && proc->cr3 == 0) {
      strcpy(proc_name, proc->name.c_str());
      return find_module_byeip(eip, proc->module_list);
    }

    if (proc->cr3 == cr3) {
      strcpy(proc_name, proc->name.c_str());
      return find_module_byeip(eip, proc->module_list);
    }
  }

  strcpy(proc_name, "<UNKNOWN>");
  return NULL;
}

tmodinfo_t *locate_module_byname(const char *name, uint32_t pid)
{
  list<process_info_t *>::iterator iter;
  for (iter = process_list.begin(); iter != process_list.end(); iter++) {
    process_info_t *proc = *iter;

    if(proc->pid == pid) {
      return find_module_byname(name, proc->module_list);
    }
  }
  return NULL;
}

uint32_t find_pid(uint32_t cr3) 
{
  list<process_info_t *>::iterator iter;
  
  for (iter = process_list.begin(); iter != process_list.end(); iter++) {
    process_info_t * proc = *iter;
    if (proc->cr3 == cr3) {
      return proc->pid;
    }
  }
  return -1;
}

uint32_t find_pid_by_name(const char* proc_name)
{
  list<process_info_t *>::iterator iter;

  for (iter = process_list.begin(); iter != process_list.end(); iter++) {
    process_info_t * proc = *iter;
    if (strcmp(proc_name,proc->name.c_str()) == 0) {
      return proc->pid;
    }
  }
  return -1;
}



int find_process(uint32_t cr3, char proc_name[], uint32_t * pid)
{
  process_info_t *proc;
  list<process_info_t *>::iterator iter;

  for(iter = process_list.begin(); iter!=process_list.end(); iter++) {
    proc = *iter;
    if (proc->cr3 == cr3) {
      strcpy(proc_name, proc->name.c_str());
      *pid = proc->pid;

      return proc->module_list.size();
    }
  }

  strcpy(proc_name, "<UNKNOWN>");
  *pid = -1;
  return 0;
}


void list_procs()
{
  process_info_t *proc;
  list<process_info_t *>::iterator iter;
   
  for (iter = process_list.begin(); iter!=process_list.end(); iter++) {
    proc = *iter;
    term_printf("%d\tcr3=0x%08x\t%s\n", proc->pid, proc->cr3,
                proc->name.c_str());
  }
}


void do_linux_ps()
{
    int pid;
    uint32_t pgd, mmap; 
    uint32_t nextaddr = 0; 

    char comm[512]; 
    
    if (0 == taskaddr) {
      if(init_kernel_offsets() == -1) {
        term_printf("No supported linux kernel has been idientified!\n");
        return ;
      }
      hookapi_hook_function(1, hookingpoint, update_proc, NULL, 0);
    }  

    update_proc(0);

    nextaddr = taskaddr; 
    do {
	pid = get_pid(nextaddr); 
	pgd = get_pgd(nextaddr); 
	if (pid != 0) { // Skip the Linux idle process ("swapper")
	  get_name(nextaddr, comm, 512); 
	
	  term_printf("%10d  CR3=0x%08lX  %s\n", pid, pgd-0xC0000000, comm); 
	  mmap = get_first_mmap(nextaddr); 
	  while (0 != mmap) {
	    get_mod_name(mmap, comm, 512); 
	    term_printf("              0x%08lX -- 0x%08lX %s\n", 
			get_vmstart(mmap),
			get_vmend(mmap), comm); 
	    mmap = get_next_mmap(mmap); 
	  }
	}
	
	nextaddr = next_task_struct(nextaddr); 

    } while (nextaddr != taskaddr) ;
}


uint32_t find_cr3(uint32_t pid)
{
  process_info_t *proc;
  list<process_info_t *>::iterator iter;

  for(iter=process_list.begin(); iter!=process_list.end(); iter++) {
    proc = *iter;
    if (proc->pid == pid)
      return proc->cr3;
  }

  return 0;
}


void get_proc_modules(uint32_t pid, old_modinfo_t mi_array[], int size)
{
  process_info_t *proc;
  module_info_t *mod;
  list<process_info_t *>::iterator iter;
  list<module_info_t *>::iterator iter2;
  int counter = 0;

  for(iter=process_list.begin(); iter!=process_list.end(); iter++) {
    proc = *iter;
    if (proc->pid == pid) {
      for(iter2=proc->module_list.begin(), counter = 0; 
          iter2!=proc->module_list.end(); iter2++, counter++) {
        mod = *iter2;
        strncpy(mi_array[counter].name, mod->name.c_str(), sizeof(mi_array[0].name)-1);
        mi_array[counter].base = mod->base;
        mi_array[counter].size = mod->size;
      }
    }
  }
}


void list_guest_modules(uint32_t pid)
{
  process_info_t *proc;
  module_info_t *mod;
  list<process_info_t *>::iterator iter;

  for(iter=process_list.begin(); iter!=process_list.end(); iter++) {
    proc = *iter;
    if (proc->pid == pid || proc->cr3 == 0) { //we use cr3=0 for the OS kernel modules
      list<module_info_t *>::iterator iter2;
      for(iter2=proc->module_list.begin(); iter2!=proc->module_list.end(); iter2++) {
        mod = *iter2;
        term_printf("%20s\t0x%08x\t0x%08x\n", mod->name.c_str(), mod->base, mod->size);
      }
    }    
  }
}


/* return 1 if the process needs to be dumped */
int checkcr3(uint32_t cr3, uint32_t eip, uint32_t tracepid, char *name,
             int len, uint32_t * offset)
{
  process_info_t *proc;
  list<process_info_t *>::iterator iter;
  module_info_t *mod;
  list<module_info_t *>::iterator iter2;

  for(iter=process_list.begin(); iter!=process_list.end(); iter++) {
    proc = *iter;
    if (proc->cr3 == cr3 && proc->pid == (uint32_t)tracepid) {
      for(iter2 =proc->module_list.begin(); iter2!=proc->module_list.end(); iter2++) {
        mod = *iter2;
        if (mod->base <= eip && mod->size + mod->base > eip) {
          strncpy(name, mod->name.c_str(), len);
          *offset = eip - mod->base;
          return 1;
        }
      }
    }
  }

  //not found
  strcpy(name, "");
  *offset = 0;
  return 0;
}



uint32_t get_current_tid()
{
  uint32_t val;
  uint32_t tid;

  //This may only work with Windows XP

  if(!is_guest_windows())
    return -1;
 
  if (!TEMU_is_in_kernel()) {     // user module
    if (TEMU_read_mem(TEMU_cpu_segs[R_FS].base+0x18, 4, &val) != -1
        && TEMU_read_mem(val + 0x24, 4, &tid) != -1) 
      return tid;
  }
  else if (TEMU_read_mem(TEMU_cpu_segs[R_FS].base+0x124, 4, &val) != -1
           && TEMU_read_mem(val + 0x1F0, 4, &tid) != -1)
    return tid;

  return -1;
}



static void procmod_save(QEMUFile * f, void *opaque)
{
  uint32_t len;
  process_info_t *proc;
  module_info_t *mod;
  list<process_info_t *>::iterator iter;
  list<module_info_t *>::iterator iter2;

  //save process information
  qemu_put_be32(f, process_list.size());
  for(iter=process_list.begin(); iter!=process_list.end(); iter++) {
    proc = *iter;
    qemu_put_be32(f, proc->pid);
    qemu_put_be32(f, proc->cr3);
    len = proc->name.length() + 1;
    qemu_put_be32(f, len);
    qemu_put_buffer(f, (uint8_t *)proc->name.c_str(), len);

    //save module information
    qemu_put_be32(f, proc->module_list.size());
    for(iter2=proc->module_list.begin();
        iter2!=proc->module_list.end(); iter2++) {
      mod = *iter2;
      len = mod->name.length() + 1;
      qemu_put_be32(f, len);
      qemu_put_buffer(f, (uint8_t*)mod->name.c_str(), len);
      qemu_put_be32(f, mod->base);
      qemu_put_be32(f, mod->size);
    }
  }

  qemu_put_be32(f, -1); //terminator
}


static int procmod_load(QEMUFile * f, void *opaque, int version_id)
{
  uint32_t i, j, nproc, nmod, len;
  uint32_t base, size;
  char name[512];
  process_info_t *proc;

  //load process and module information
  procmod_remove_all();

  nproc = qemu_get_be32(f);
  for (i = 0; i < nproc; i++) {
    proc = new process_info_t();
    if (proc == NULL)
      return -1;

    proc->pid = qemu_get_be32(f);
    proc->cr3 = qemu_get_be32(f);
    len = qemu_get_be32(f);
    assert(len <= 512);
    qemu_get_buffer(f, (uint8_t*)name, len);
    if(name[len-1] != 0) 
      return -EINVAL; //last character must be zero
    proc->name = name;
    process_list.push_back(proc);

    nmod = qemu_get_be32(f);
    for (j = 0; j < nmod; j++) {
      len = qemu_get_be32(f);
      assert(len <= 512);
      qemu_get_buffer(f, (uint8_t *)name, len);
      if(name[len-1] != 0) 
        return -EINVAL;
      base = qemu_get_be32(f);
      size = qemu_get_be32(f);
      insert_module_info(proc->module_list, name, base, size);
    }
  }


  uint32_t terminator = qemu_get_be32(f);
  if(terminator != (-1UL))
    return -EINVAL;

  return 0;
}


int procmod_init()
{
  procmod_createproc(0, 0, "<kernel>"); //create a virutal process for the kernel

  FILE *guestlog = fopen("guest.log", "r");
  char syslogline[512];
  int pos = 0;
  if(guestlog) {
    int ch;
    while((ch = fgetc(guestlog)) != EOF) {
      syslogline[pos++] = (char)ch;
      if(pos > 510) pos = 510;
      if(ch == 0xa) {
        syslogline[pos] = 0;
        handle_message(syslogline); //add entries into function map
        parse_process(syslogline);
        parse_module(syslogline);
        pos = 0;
      }
    }
    fclose(guestlog);
  }


  //TODO: save and load thread information

  if(init_kernel_offsets() >= 0) 
    hookapi_hook_function(1, hookingpoint, update_proc, NULL, 0);
    
  register_savevm("procmod", 0, 1, procmod_save, procmod_load, NULL);
  return 0;
}


void parse_process(char *log)
{
  char c;
  uint32_t pid;
  uint32_t cr3 = 0;
  static char name[512];
  name[0] = 0;
  if (sscanf(log, "P %c %d %x %s \n", &c, &pid, &cr3, name) < 2)
    return;
  switch (c) {
  case '-':
    procmod_removeproc(pid);
    break;
  case '+':
    procmod_createproc(pid, cr3, name);
    break;
  }
}


void parse_module(char *log)
{
  uint32_t pid, cr3, base, size;
  char mod[512];
  char c = '+';

  //We try to parse a long name with spaces first. If failed, we parse in the old way, 
  //for backward compatibility. -Heng
  if (sscanf(log, "M %d %x \"%[^\"]\" %x %x %c", &pid, &cr3, mod, &base, &size, &c) < 5) {
    if (sscanf(log, "M %d %x %s %x %x %c", &pid, &cr3, mod, &base, &size, &c) < 5)
      return;
  }
  if(!strcmp(mod, "[]"))
    mod[0] = 0;
  mod[511] = 0;
  switch (c) {
  case '-':
    procmod_remove_modinfo(pid, base);
    break;
  case '+':
    procmod_insert_modinfo(pid, cr3, mod, base, size);
    break;
  }
  if(loadmodule_notify) 
    loadmodule_notify(pid, cr3, mod, base, size);
}


int is_guest_windows()
{
  //FIXME: we use a very simple hack here. Windows uses FS segment register to store 
  // the current process context, while Linux does not. We may need better heuristics 
  // when we need to support more guest systems.
  return (TEMU_cpu_segs[R_FS].selector != 0);
}
