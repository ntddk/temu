/*
 * The Sleuth Kit
 *
 * $Date: 2005/09/02 23:34:04 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 *
 * 
 */

#ifndef _MM_TYPES_H
#define _MM_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

    extern char mm_parse_type(const char *);
    extern char *mm_get_type(char);

#define MM_UNSUPP	0x00
#define	MM_DOS		0x01
#define MM_BSD		0x02
#define MM_SUN		0x03
#define	MM_MAC		0x04
#define MM_GPT		0x05

#ifdef __cplusplus
}
#endif
#endif
