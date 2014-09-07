/*************************************************************************
** sample_hook.c
** Author: Juan Caballero <jcaballero@cmu.edu>
**
** This file contains a sample hook for the getsockname function
**
*/

#include "config.h"
#include "plugin.h"
#include "group_hook_helper.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#ifdef PLUGIN_TRACECAP
  #include "../../../tracecap/my_stub_def.h"
  #include "../../../tracecap/tracecap.h"
#endif


#define LOCAL_DEBUG 1
#define WRITE if (LOCAL_DEBUG) write_log

/* Taint origin used when tainting output of the function */ 
#define GETSOCKNAME_ORIGIN 1105

/* Function prototypes */
static int getsockname_call(void *opaque);
static int getsockname_ret(void *opaque);

/* Add here the functions to hook by name 
 * The same hook can be reused for different functions */
hook_t hooks[] =
{
  /* getsockname */
  {"ws2_32.dll", "getsockname", getsockname_call, 0},
  {"wsock32.dll", "getsockname", getsockname_call, 0},
};

int local_num_funs = (sizeof(hooks)/sizeof(hook_t));


/* Initialization function */
void internal_init_plugin()
{
  initialize_plugin(hooks,local_num_funs);
}

/* Structure that is passed between the call and return hook */
typedef struct {
  uint32_t eip;
  uint32_t hook_handle;
  uint32_t sd;
  uint32_t bufStart;
  uint32_t bufMaxLen;
  uint32_t bufLenPtr;
} getsockname_t;

/* Call hook (executed before any instruction in the function) */
static int getsockname_call(void *opaque)
{
  uint32_t esp;
  uint32_t eip;
  uint32_t buf[7]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
      BUF INDEX -> PARAMETER
      ws2_32.dll getsockname
      int getsockname(SOCKET s,struct sockaddr* name,int* namelen);
      0 -> return address
      1 -> IN socket descriptor
      2 -> OUT Address structure with socket information
      3 -> IN-OUT On call, size of the name buffer, in bytes.
        On return, size in bytes of the name parameter
  */

  /* Check which function we are jumping to */
  read_reg(eip_reg, &eip);
  char mod_name[512];
  char fun_name[512];
  get_function_name(eip,(char *)&mod_name,(char *)&fun_name);

  /* Print some information to monitor */
  WRITE("tracenetlog","Getting socket info using function %s::%s\n"
    "\tFD: %u BufStart: 0x%08x BufMaxLen: %d\n",
    mod_name, fun_name,buf[1],buf[2],(int)buf[3]);

  /* Store parameters so that they can be used by return hook */
  getsockname_t *s = malloc(sizeof(getsockname_t));
  if (s == NULL) return 0;
  s->eip = eip;
  s->sd = buf[1];
  s->bufStart = buf[2];
  s->bufMaxLen = buf[3];
  s->bufLenPtr = esp+12;

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], getsockname_ret, s,
    sizeof(getsockname_t));

  return 0;
}

/* Return hook (executed after the return instruction) */
static int getsockname_ret(void *opaque)
{
  static int offset  = 0;
  int read_err = 0;
  uint32_t bufRealLen = 0;
  getsockname_t *s = (getsockname_t *)opaque;
  struct sockaddr_in addrData;
  char addrStr[INET_ADDRSTRLEN];

  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  uint32_t eax = 0;
  read_reg(eax_reg, &eax);
  if (eax != 0) return 0;

  /* Read size of address structure */
  read_err = read_mem(s->bufLenPtr, 4, (unsigned char*)&bufRealLen);
  if (!read_err) {
    WRITE ("tracenetlog","\tNumBytesWritten: %u\n",bufRealLen);
  }
  else {
    WRITE ("tracenetlog","\tCould not get number of bytes written\n");
    return 0;
  }

  /* Read the address structure */
  read_err = read_mem(s->bufStart, 16, (unsigned char*)&addrData);
  if (read_err) return 0;

  /* Print the address structure */
  inet_ntop(AF_INET, &addrData.sin_addr, addrStr, sizeof(addrStr));
  WRITE ("tracenetlog","\tFamily: %d Port: %u Address: %s\n",
   addrData.sin_family,ntohs(addrData.sin_port),addrStr);

  /* Taint address structure */
  if (bufRealLen > 0) {
    hook_taint_record_t tr;
    tr.source = TAINT_SOURCE_API_SOCK_INFO_IN;
    tr.origin = GETSOCKNAME_ORIGIN;
    tr.offset = offset;

    taint_mem(s->bufStart+2, 6, (void *)&tr);
  }

  /* Increment the taint offset */
  offset += 6;

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}

