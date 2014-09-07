/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#ifndef _TEMU_VM_COMPRESS_H_
#define _TEMU_VM_COMPRESS_H_
#include <zlib.h>
#define IOBUF_SIZE 4096

typedef struct{
    z_stream zstream;
    void *f;
    uint8_t buf[IOBUF_SIZE];
} TEMU_CompressState_t;

int TEMU_compress_open(TEMU_CompressState_t *s, void *f);
int TEMU_compress_buf(TEMU_CompressState_t *s, const uint8_t *buf, int len);
void TEMU_compress_close(TEMU_CompressState_t *s);
int TEMU_decompress_open(TEMU_CompressState_t *s, void *f);
int TEMU_decompress_buf(TEMU_CompressState_t *s, uint8_t *buf, int len);
void TEMU_decompress_close(TEMU_CompressState_t *s);
void TEMU_vm_compress_init(void); //dummy init

#endif //_TEMU_VM_COMPRESS_H_
