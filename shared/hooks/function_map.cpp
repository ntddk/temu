/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

/********************************************************************
** function_map.cpp
** Author: Cody Hartwig <chartwig@cs.cmu.edu>
**         Heng Yin <hyin@ece.cmu.edu> 
**
**
** used to map eip to function name.  this file uses the fact
** that TEMU knows module information for loaded modules.
** using this, and the print_funcs_on command, we can print
** every library call that is made within the program.
**
*/

#include <inttypes.h>
#include <map>
#include <vector>
#include <list>
#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cassert>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "function_map.h"
extern "C" {
#include "../hookapi.h"
#include "TEMU_lib.h"
};

using namespace std;

struct function_t {
  function_t(string _name, string _module, uint32_t _offset)
            :name(_name), module(_module), offset(_offset) 
  { } 
  function_t(){};

  string name;
  string module;
  uint32_t offset;
  operator  std::string() {
    return name;
  }
  operator  uint32_t() {
    return offset;
  }
};

/* this file supports two ways of getting function information.
 * the first method was to read and parse a guest.log file.
 * however, this seemed silly when i could just grab the information
 * directly.  this way we should always have the interesting information
 * available
 *
 * things that are removed with #if 0 represent the old way of doing things.
 * i hate to delete all the parsing code...
 */

/* Maps EIP to corresponding function_t structure that includes module name, 
		function name and offest in module */
map<uint32_t, function_t > g_function_map;

/* Maps <module_name,function_name> to EIP */
map <string, map <string, uint32_t > *>g_eip_map;


/* Map that stores functions that need to be hooked as soon as we see the 
		corresponding message. Functions identified by module name and 
		function name */
typedef pair<string, string> mod_fun_t;

typedef struct {
  string module;
  string function;
  uint32_t hook;
  int is_global;
}fnhook_info_t;

list<fnhook_info_t> fun_to_hook;
//map <string, map<string, fnhook_info_t>*> fun_to_hook;


const char *function_map_search(uint32_t eip)
{
  map< uint32_t, function_t >::iterator fmap_iter =
      g_function_map.find(eip);
  if (fmap_iter != g_function_map.end())
    return fmap_iter->second.name.c_str();
  return NULL;
}

struct names_t *query_name(unsigned long eip)
{
  static names_t names;
  map < uint32_t, function_t >::iterator fmap_iter =
      g_function_map.find(eip);
  if (fmap_iter != g_function_map.end()) {
    names.fun_name = fmap_iter->second.name.c_str();
    names.mod_name = fmap_iter->second.module.c_str();
    return &names;
  }
  return NULL;
}

void map_to_file(const char * filename)
{
  FILE *pFile;
  term_printf("Generating file: %s\n", filename);
  pFile = fopen(filename, "w");

  if (pFile) {
    map < uint32_t, function_t >::iterator fun_iter =
        g_function_map.begin();
    for (; fun_iter != g_function_map.end(); fun_iter++) {
      fprintf(pFile, "0x%08x %s %s 0x%04x\n",
              fun_iter->first,
              fun_iter->second.module.c_str(),
              fun_iter->second.name.c_str(), fun_iter->second.offset);
    }

    fclose(pFile);
  }
}


void add_fun_to_hook(const char *module_name,
                     const char *function_name, 
                     uint32_t hookfn,
                     int is_global)
{
  fnhook_info_t info;
  info.module = module_name;
  info.function = function_name;
  info.hook = hookfn;
  info.is_global = is_global;
  fun_to_hook.push_back(info);
}

static void 
resolve_fun_to_hook(const char *module, const char *function, uint32_t eip)
{
  list<fnhook_info_t>::iterator iter;
  for(iter=fun_to_hook.begin(); iter!=fun_to_hook.end(); iter++) {
    if(strcasecmp(iter->module.c_str(), module) ||
      strcasecmp(iter->function.c_str(), function)) 
      continue;

    hookapi_hook_function(iter->is_global, eip, (hook_proc_t)iter->hook, 
				NULL, 0);
    term_printf("Hooking %s::%s @ 0x%x with 0x%x\n", module, function, eip,
               iter->hook);
    iter = fun_to_hook.erase(iter);
    iter--;
  }
}

#if 0
uint32_t remove_fun_to_hook(const char *module_name,
                            const char *function_name)
{
  map<string, map<string, uint32_t > *>::iterator iter1 =
      fun_to_hook.find(module_name);

  if (iter1 == fun_to_hook.end())
    return 0;

  map<string, uint32_t >::iterator iter2 =
      iter1->second->find(function_name);

  if (iter2 == iter1->second->end())
    return 0;

  uint32_t hookfn = iter2->second;

  // Found function, remove it and check if need to remove module
  iter1->second->erase(iter2);
  if (iter1->second->size() == 0)
    fun_to_hook.erase(iter1);

  return hookfn;
}

int query_fun_to_hook(const char *module_name,
                      const char *function_name)
{
  map <string, map <string, uint32_t > *>::iterator iter1 =
      fun_to_hook.find(module_name);

  if (iter1 == fun_to_hook.end())
    return 0;

  map <string, uint32_t >::iterator iter2 =
      iter1->second->find(function_name);

  if (iter2 == iter1->second->end())
    return 0;

  return 1;
}
#endif

uint32_t query_eip(const char *module_name, const char *function_name)
{
  map<string, map<string, uint32_t > *>::iterator iter1 =
      g_eip_map.find(string(module_name));

  if (iter1 == g_eip_map.end())
    return 0;

  map <string, uint32_t >::iterator iter2 =
      iter1->second->find(string(function_name));

  if (iter2 == iter1->second->end())
    return 0;

  return iter2->second;
}



static void
add_rev_lookup(const char *module_name, const char *function_name, uint32_t eip)
{
  map<string, map <string, uint32_t > *>::iterator iter1 =
      g_eip_map.find(module_name);

  map<string, uint32_t > *inner_map = NULL;

  if (iter1 == g_eip_map.end()) {
    inner_map = new map <string, uint32_t >;
    g_eip_map[module_name] = inner_map;
  }
  else {
    inner_map = iter1->second;
  }

  map<string, uint32_t >::iterator iter2 = inner_map->find(function_name);

  if (iter2 == inner_map->end()) {
    (*inner_map)[function_name] = eip;
  }
}

/* g_function_map */
void handle_message(char *message)
{
  static map<string, vector<function_t> *>orphan_funcs;
  static map<string, uint32_t > module_map;

  if (message[0] == 'F') {
    char module[512];
    char fname[512];
    uint32_t offset;

    if (sscanf(message, " F %s %s %x ", module, fname, &offset) != 3)
      return;

    map<string, uint32_t >::iterator module_map_it =
        module_map.find(module);

    if (module_map_it == module_map.end()) {
      /* we have an orphan function */
      function_t func((string)fname, (string)module, offset);
      map<string, vector<function_t> *>::iterator it =
          orphan_funcs.find(module);

      if (it == orphan_funcs.end()) {
        orphan_funcs[module] = new vector<function_t>;
      }
      orphan_funcs[module]->push_back(func);
    }
    else {
      /* we have a function that is associated with a known module */
      uint32_t base = module_map_it->second;
      uint32_t entry = base + offset;

      function_t func((string)fname, (string)module, offset);
      g_function_map[entry] = func;

      /* insert reverse lookup */
      add_rev_lookup(module, fname, entry);

      resolve_fun_to_hook(module, fname, entry);
    }
  }
  else if (message[0] == 'M') {
    uint32_t blah1, blah2;
    char module[512];
    uint32_t base;

    //We try to parse a long name with spaces first. If failed, we parse in the old way, 
    //for backward compatibility. -Heng
    if (sscanf(message, "M %d %x \"%[^\"]\" %x ", &blah1, &blah2, module, &base) < 4) {
      if (sscanf(message, "M %x %x %s %x ", &blah1, &blah2, module, &base) < 4)
      return;
    }

    module_map.insert(std::pair < std::string, uint32_t > (module, base));

    /* look for orphan functions */
    std::map < std::string, std::vector < function_t > *>::iterator it =
        orphan_funcs.find(module);
    if (it == orphan_funcs.end())
      return;

    std::vector < function_t > *pf = it->second;

    for (unsigned int i = 0; i < pf->size(); ++i) {
      uint32_t eip = (*pf)[i].offset + base;
      g_function_map.insert(std::pair < uint32_t,
                            function_t > (eip, (*pf)[i]));
      /*
       ** LOG("fcn_load", "Adding %s @ %08x+%x\n", (*pf)[i].name.c_str(),
       **     base, (*pf)[i].offset);
       */

      /* insert reverse lookup */
      add_rev_lookup((*pf)[i].module.c_str(), (*pf)[i].name.c_str(), eip);

      resolve_fun_to_hook((*pf)[i].module.c_str(), (*pf)[i].name.c_str(), eip);
    }

    delete pf;

    orphan_funcs.erase(it);

  }
  else {
    /* empty: unsupported message */
  }
}


/* Serialize function information by creating module/function messages 
		Writes a maximum of buf_size bytes into buf 
		Returns the number of bytes written into buf
*/
static int serialize_maps(char *buf, int buf_size)
{
  std::map < std::string, uint32_t > module_map;

  char *first_empty_pos = buf;
  int remaining_size = buf_size;
  char msg_buf[512] = "";
  int num_bytes = 0;
  uint32_t base = 0;

  /* Iterate over function map */
  map < uint32_t, function_t >::iterator fun_iter = g_function_map.begin();
  for (; fun_iter != g_function_map.end(); fun_iter++) {

    /* Check if the module has already been seen */
    std::map < std::string, uint32_t >::iterator module_map_it =
        module_map.find(fun_iter->second.module.c_str());

    /* If module has never been seen, add it and create message */
    if (module_map_it == module_map.end()) {
      base = fun_iter->first - fun_iter->second.offset;
      module_map.insert(std::pair < std::string, uint32_t >
                        (fun_iter->second.module.c_str(), base));

      num_bytes = snprintf(msg_buf, 512,
                           "M %x %x %s %x&", 0, 0,
                           fun_iter->second.module.c_str(), base);
      if (num_bytes > 512)
        num_bytes = 512;
      // msg_buf should not be null-terminated

      if (num_bytes <= remaining_size) {
        strncpy(first_empty_pos, msg_buf, num_bytes);
        first_empty_pos += num_bytes;
        remaining_size -= num_bytes;
      }
      else
        break;
    }

    /* Create function message */
    num_bytes = snprintf(msg_buf, 512,
                         "F %s %s %x&",
                         fun_iter->second.module.c_str(),
                         fun_iter->second.name.c_str(),
                         fun_iter->second.offset);
    if (num_bytes > 512)
      num_bytes = 512;
    // msg_buf should not be null-terminated

    if (num_bytes <= remaining_size) {
      strncpy(first_empty_pos, msg_buf, num_bytes);
      first_empty_pos += num_bytes;
      remaining_size -= num_bytes;
    }
    else
      break;

  }

  return buf_size - remaining_size;

}

/* Unserialize function information by calling handle_message */
static void unserialize_maps(const char *buf, int buf_size)
{
  char *msg = NULL;
  const char *delim = "&";

  char *parsing_buf = (char *) malloc(buf_size + 1);
  strncpy(parsing_buf, buf, buf_size);
  parsing_buf[buf_size] = '\0';

  /* Get first message */
  msg = strtok(parsing_buf, delim);
  if (msg) {
    handle_message(msg);

    /* Get remaining messages */
    while ((msg = strtok(NULL, delim)) != NULL) {
      handle_message(msg);
    }
  }

}

static void function_map_save(QEMUFile * f, void *opaque)
{
  char buf[5 * 1024 * 1024];
  uint32_t len = serialize_maps(buf, sizeof(buf));
  assert(len < sizeof(buf));

  TEMU_CompressState_t state;
  uint32_t ending = 0;
  if (TEMU_compress_open(&state, f) < 0)
    return;

  //FIXME: need to save maps too.

  qemu_put_be32(f, len);
  TEMU_compress_buf(&state, (uint8_t *) buf, len);
  TEMU_compress_buf(&state, (uint8_t *) & ending, 4);   //ending
  TEMU_compress_close(&state);
}

static int function_map_load(QEMUFile * f, void *opaque, int version_id)
{
  char buf[5 * 1024 * 1024];
  uint32_t len = qemu_get_be32(f);
  uint32_t ending;

  //FIXME: need to load maps too.

  if (len >= sizeof(buf))
    return -EINVAL;

  TEMU_CompressState_t state;
  if (TEMU_decompress_open(&state, f) < 0)
    return -EINVAL;

  TEMU_decompress_buf(&state, (uint8_t *) buf, len);
  TEMU_decompress_buf(&state, (uint8_t *) & ending, 4);
  if (ending != 0)
    return -EINVAL;

  unserialize_maps(buf, len);
  return 0;
}


void function_map_init()
{
  register_savevm("funmap", 0, 1, function_map_save, function_map_load,
                  NULL);
}

void function_map_cleanup()
{
  g_function_map.clear();
  map<string, map <string, uint32_t > *>::iterator g_eip_iter =
    g_eip_map.begin();
  for (; g_eip_iter != g_eip_map.end(); g_eip_iter++) {
    map<string, uint32_t > *inner_map = g_eip_iter->second;
    if (inner_map != NULL) {
      (*inner_map).clear();
      delete inner_map;
      inner_map = NULL;
    }
  }
  g_eip_map.clear();
  fun_to_hook.clear();
  deregister_savevm("funmap", 0);
}
