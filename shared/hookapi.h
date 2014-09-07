/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

/**********************************************************************
 * hookapi.h
 * Author: Heng Yin <hyin@ece.cmu.edu>
 *
 * This file is responsible for registering and calling function hooks.
 * 
 */ 
////////////////////////////////////
/// @defgroup hookapi hookapi: Function Hooking Facility
///

#ifndef HOOKAPI_H_INCLUDED
#define HOOKAPI_H_INCLUDED

typedef int (*hook_proc_t)(void *opaque);

void init_hookapi();
void hookapi_cleanup();

/// @ingroup hookapi
/// install a hook at the function entry
/// @param is_global flag specifies if this hook should be invoked globally or only in certain execution context
/// @param eip address of function to be hooked (has to be the start of a basic block
/// @param fnhook address of function hook
/// @param opaque address of an opaque structure provided by caller (has to be globally allocated)
//  @param sizeof_opaque size of the opaque structure (if opaque is an integer, not a pointer to a structure, sizeof_opaque must be zero) 
/// @return a handle that uniquely specifies this hook 
uintptr_t
hookapi_hook_function(
               int is_global,
               uint32_t eip, 
               hook_proc_t fnhook, 
               void *opaque, 
               uint32_t sizeof_opaque
               );

/// @ingroup hookapi
/// install a hook at the function exit
/// @param eip function return address 
/// @param fnhook address of function hook
/// @param opaque address of an opaque structure provided by caller (has to be globally allocated)
//  @param sizeof_opaque size of the opaque structure (if opaque is an integer, not a pointer to a structure, sizeof_opaque must be zero) 
/// @return a handle that uniquely specifies this hook 
/// The implementation of this function handles multi-threading. It means, when
/// multple threads call the same function and register the same return address, 
/// we can distinguish different hooks, and invoke them correctly.
uintptr_t 
hookapi_hook_return(
               uint32_t eip, 
               hook_proc_t fnhook, 
               void *opaque, 
               uint32_t sizeof_opaque
               );

/// @ingroup hookapi
/// remove a hook
/// @param handle hook handle returned by hookapi_hook_function or hookapi_hook_return  
/// This function will not free the opaque structure provided by the caller 
/// when installing a hook. The caller is responsible for freeing it.
/// The exception is when the user's plugin is unloaded, the opaque structure is
/// freed automatically to avoid memory leakage. Likewise, when a vm state 
/// (i.e. snapshot) is loaded, the opaque structure is allocated and 
/// restored automatically.  
void hookapi_remove_hook(uintptr_t handle);


/// @ingroup hookapi
/// install a hook at the function entry by specifying module name and function name
/// @param mod module name that this function is located in
/// @param func function name
/// @param  flag specifies if this hook should be invoked globally or only in certain execution context
/// @param eip address of function to be hooked (has to be the start of a basic block
/// @param fnhook address of function hook
/// @param opaque address of an opaque structure provided by caller (has to be globally allocated)
//  @param sizeof_opaque size of the opaque structure (if opaque is an integer, not a pointer to a structure, sizeof_opaque must be zero) 
void hookapi_hook_function_byname(const char *mod, const char *func, 
	int is_global, hook_proc_t fnhook, void *opaque, uint32_t sizeof_opaque);


/// @ingroup hookapi
/// search and invoke the corresponding hooks at the current eip
/// @param in_context flag that specifies if the current execution is in the analysis context
/// This function is usually called in plugin's block_begin callback, to check 
/// and invoke hooks. This function deals with the situation that multiple hooks 
/// are installed on the same function entry or exit. It is able to distinguish 
/// different hooks and invoke them correctly.
void hookapi_check_call(int in_context);

#endif

