static DATA_TYPE glue(glue(TD_slow_ld, SUFFIX),
                      MMUSUFFIX) (target_ulong addr, int is_user,
                                  void *retaddr);

DATA_TYPE REGPARM(1) glue(glue(__TD_ld, SUFFIX),
                          MMUSUFFIX) (target_ulong addr, int is_user)
{
  DATA_TYPE res;
  int index;
  target_ulong tlb_addr;
  target_phys_addr_t physaddr;
  void *retaddr;

  /* test if there is match for unaligned or IO access */
  /* XXX: could done more in memory macro in a non portable way */
  index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
  tlb_addr = env->tlb_table[is_user][index].ADDR_READ;
  if ((addr & TARGET_PAGE_MASK) ==
      (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
    physaddr = addr + env->tlb_table[is_user][index].addend;
    if (tlb_addr & ~TARGET_PAGE_MASK) {
      /* IO access */
      if ((addr & (DATA_SIZE - 1)) != 0)
        goto do_unaligned_access;
      res = glue(io_read, SUFFIX) (physaddr, tlb_addr);
    }
    else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >=
             TARGET_PAGE_SIZE) {
      /* slow unaligned access (it spans two pages or IO) */
    do_unaligned_access:
      retaddr = GETPC();
#ifdef ALIGNED_ONLY
      do_unaligned_access(addr, READ_ACCESS_TYPE, is_user, retaddr);
#endif
      res =
          glue(glue(TD_slow_ld, SUFFIX), MMUSUFFIX) (addr, is_user,
                                                     retaddr);
    }
    else {
      /* unaligned/aligned access in the same page */
#ifdef ALIGNED_ONLY
      if ((addr & (DATA_SIZE - 1)) != 0) {
        retaddr = GETPC();
        do_unaligned_access(addr, READ_ACCESS_TYPE, is_user, retaddr);
      }
#endif
      res = glue(glue(TD_ld, USUFFIX), _raw) ((long) physaddr);
#if 0
      if (remove_will_taint_page(addr & TARGET_PAGE_MASK)) {
        taint_phys_page(addr & TARGET_PAGE_MASK,
                        physaddr & TARGET_PAGE_MASK);
      }
#endif
    }
  }
  else {
    /* the page is not in the TLB : fill it */
    retaddr = GETPC();
#ifdef ALIGNED_ONLY
    if ((addr & (DATA_SIZE - 1)) != 0)
      do_unaligned_access(addr, READ_ACCESS_TYPE, is_user, retaddr);
#endif
    tlb_fill(addr, READ_ACCESS_TYPE, is_user, retaddr);
    goto redo;
  }
  return res;
}


/* handle all unaligned cases */
static DATA_TYPE glue(glue(TD_slow_ld, SUFFIX),
                      MMUSUFFIX) (target_ulong addr, int is_user,
                                  void *retaddr) {
  DATA_TYPE res, res1;
  int index, i;
  target_phys_addr_t physaddr;
  target_ulong tlb_addr;

  index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
  tlb_addr = env->tlb_table[is_user][index].ADDR_READ;
  if ((addr & TARGET_PAGE_MASK) ==
      (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
    physaddr = addr + env->tlb_table[is_user][index].addend;
    if (tlb_addr & ~TARGET_PAGE_MASK) {
      /* IO access */
      if ((addr & (DATA_SIZE - 1)) != 0)
        goto do_unaligned_access;
      res = glue(io_read, SUFFIX) (physaddr, tlb_addr);
    }
    else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >=
             TARGET_PAGE_SIZE) {
    do_unaligned_access:
      /* slow unaligned access (it spans two pages) */
      for (i = 0, res = 0; i < DATA_SIZE; i++) {
        res1 = glue(TD_slow_ldb, MMUSUFFIX) (addr + i, is_user, retaddr);
        res |= (res1 << (i * 8));
      }
      res = (DATA_TYPE) res;
    }
    else {
      /* unaligned/aligned access in the same page */
      res = glue(glue(TD_ld, USUFFIX), _raw) ((long) physaddr);
#if 0
      if (remove_will_taint_page(addr & TARGET_PAGE_MASK)) {
        taint_phys_page(addr & TARGET_PAGE_MASK,
                        physaddr & TARGET_PAGE_MASK);
      }
#endif
    }
  }
  else {
    /* the page is not in the TLB : fill it */
    tlb_fill(addr, READ_ACCESS_TYPE, is_user, retaddr);
    goto redo;
  }
  return res;
}

#ifndef SOFTMMU_CODE_ACCESS

static void glue(glue(TD_slow_st, SUFFIX), MMUSUFFIX) (target_ulong addr,
                                                       DATA_TYPE val,
                                                       int is_user,
                                                       void *retaddr);

void REGPARM(2) glue(glue(__TD_st, SUFFIX), MMUSUFFIX) (target_ulong addr,
                                                        DATA_TYPE val,
                                                        int is_user)
{
  target_phys_addr_t physaddr;
  target_ulong tlb_addr;
  void *retaddr;
  int index;

  index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
  tlb_addr = env->tlb_table[is_user][index].addr_write;
  if ((addr & TARGET_PAGE_MASK) ==
      (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
    physaddr = addr + env->tlb_table[is_user][index].addend;
    if (tlb_addr & ~TARGET_PAGE_MASK) {
      /* IO access */
      if ((addr & (DATA_SIZE - 1)) != 0)
        goto do_unaligned_access;
      retaddr = GETPC();
      glue(io_write, SUFFIX) (physaddr, val, tlb_addr, retaddr);
      if (((tlb_addr >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1)) == 4) {        //notdirty_mem_write
        dump_physaddr_info(DATA_SIZE, (uint8_t*)physaddr);
      }
    }
    else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >=
             TARGET_PAGE_SIZE) {
    do_unaligned_access:
      retaddr = GETPC();
#ifdef ALIGNED_ONLY
      do_unaligned_access(addr, 1, is_user, retaddr);
#endif
      glue(glue(TD_slow_st, SUFFIX), MMUSUFFIX) (addr, val, is_user,
                                                 retaddr);
    }
    else {
      /* aligned/unaligned access in the same page */
#ifdef ALIGNED_ONLY
      if ((addr & (DATA_SIZE - 1)) != 0) {
        retaddr = GETPC();
        do_unaligned_access(addr, 1, is_user, retaddr);
      }
#endif
      glue(glue(TD_st, SUFFIX), _raw) ((long) physaddr, val);
    }
  }
  else {
    /* the page is not in the TLB : fill it */
    retaddr = GETPC();
#ifdef ALIGNED_ONLY
    if ((addr & (DATA_SIZE - 1)) != 0)
      do_unaligned_access(addr, 1, is_user, retaddr);
#endif
    tlb_fill(addr, 1, is_user, retaddr);
    goto redo;
  }
}


/* handles all unaligned cases */
static void glue(glue(TD_slow_st, SUFFIX), MMUSUFFIX) (target_ulong addr,
                                                       DATA_TYPE val,
                                                       int is_user,
                                                       void *retaddr) {
  target_phys_addr_t physaddr;
  target_ulong tlb_addr;
  int index, i;

  index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
  tlb_addr = env->tlb_table[is_user][index].addr_write;
  if ((addr & TARGET_PAGE_MASK) ==
      (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
    physaddr = addr + env->tlb_table[is_user][index].addend;
    if (tlb_addr & ~TARGET_PAGE_MASK) {
      /* IO access */
      if ((addr & (DATA_SIZE - 1)) != 0)
        goto do_unaligned_access;
      glue(io_write, SUFFIX) (physaddr, val, tlb_addr, retaddr);
      if (((tlb_addr >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1)) == 4) {
        //notdirty_mem_write
        dump_physaddr_info(DATA_SIZE, (uint8_t*)physaddr);
      }
    }
    else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >=
             TARGET_PAGE_SIZE) {
    do_unaligned_access:
      /* XXX: not efficient, but simple */
      for (i = 0; i < DATA_SIZE; i++) {
#ifdef TARGET_WORDS_BIGENDIAN
        glue(TD_slow_stb, MMUSUFFIX) (addr + i,
                                      val >> (((DATA_SIZE - 1) * 8) -
                                              (i * 8)), is_user, retaddr);
#else
        glue(TD_slow_stb, MMUSUFFIX) (addr + i, val >> (i * 8),
                                      is_user, retaddr);
#endif
      }
    }
    else {
      /* aligned/unaligned access in the same page */
      glue(glue(TD_st, SUFFIX), _raw) (physaddr, val);
    }
  }
  else {
    /* the page is not in the TLB : fill it */
    tlb_fill(addr, 1, is_user, retaddr);
    goto redo;
  }
}


#endif
