/*
 * The Sleuth Kit - Add on for EWF image support
 * Eye Witness Compression Format Support
 *
 * $Date: 2006/04/12 22:18:20 $
 *
 * Joachim Metz <metz@studenten.net>
 * Copyright (c) 2006 Joachim Metz.  All rights reserved 
 *
 * Based on raw image support of the Sleuth Kit from
 * Brian Carrier.
 */
#ifndef _EWF_H
#define _EWF_H

#include "libewf.h"

#ifdef __cplusplus
extern "C" {
#endif

    extern IMG_INFO *ewf_open(int, const char **, IMG_INFO *);

    typedef struct IMG_EWF_INFO IMG_EWF_INFO;
    struct IMG_EWF_INFO {
	IMG_INFO img_info;
	LIBEWF_HANDLE *handle;
	char *md5hash;
    };

#ifdef __cplusplus
}
#endif
#endif
