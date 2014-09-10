/*
TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

As an additional exception, the XED and Sleuthkit libraries, including
updated or modified versions, are excluded from the requirements of
the LGPL as if they were standard operating system libraries.
*/

#ifndef _ERRDET_H_
#define _ERRDET_H_

/* Error detection
 * TEMU has some support for detecting errors in programs
 * The function enable_detection takes as input a mask in which each bit 
 *   represents a different technique being used to detect errors.
 * The following techniques are defined:
 *   1) DETECT_COND_TAINTEIP
 *     Instruction counter (EIP) is tainted
 *     Usually gives too many false positives
 *   2) DETECT_COND_EXCEPTION
 *     Invalid memory access exception (Windows only)
 *   3) DETECT_COND_NULLPTR 
 *     Program is dereferencing a null pointer
 *   4) DETECT_COND_PROCESSEXIT 
 *     Process being traced exits
 *     Useful with programs that should not exit like network servers
 *
 * The default action for all detection methods is to stop the trace and
 *   exit TEMU with a return value specific to the condition that was met
 *
 * Multiple techniques can be used simultaneously by constructing a mask 
 *   that AND's different macros 
 *
 * There is also to macros to activate or deactivate all techniques:
 *   DETECT_COND_NONE, DETECT_COND_ALL
 *
 */
#define DETECT_COND_TAINTEIP 1U  // Instruction counter (EIP) is tainted
#define DETECT_COND_EXCEPTION 2U // Invalid memory access exception (Windows)
#define DETECT_COND_NULLPTR 4U   // Program is dereferencing a null pointer
#define DETECT_COND_PROCESSEXIT 8U  // Process being traced exits
                                    // (servers that should not exit)

/* Detect condition shortcuts */
#define DETECT_COND_NONE 0U
#define DETECT_COND_ALL ~0U


void enable_detection(unsigned detectionmask);
void do_detect(const char *condition, const char* on_off);
void do_action(const char *act);
void tainteip_detection(uint8_t *record);
void procexit_detection(uint32_t pid);

#endif // _ERRDET_H_

