DATA_TYPE REGPARM(1) glue(glue(__TD_ld, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                         int mmu_idx);


static inline RES_TYPE glue(glue(TD_ld, USUFFIX), MEMSUFFIX)(target_ulong ptr)
{
    int index;
    RES_TYPE res;
    target_ulong addr;
    unsigned long physaddr;
    int mmu_idx;

    addr = ptr;
    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    mmu_idx = CPU_MMU_INDEX;
    if (__builtin_expect(env->tlb_table[mmu_idx][index].ADDR_READ !=
                         (addr & (TARGET_PAGE_MASK | (DATA_SIZE - 1))), 0)) {
        res = glue(glue(__TD_ld, SUFFIX), MMUSUFFIX)(addr, mmu_idx);
    } else {
        physaddr = addr + env->tlb_table[mmu_idx][index].addend;
        res = glue(glue(TD_ld, USUFFIX), _raw)((uint8_t *)physaddr);
    }
    return res;
}


#if DATA_SIZE <= 2
static inline int glue(glue(TD_lds, SUFFIX), MEMSUFFIX)(target_ulong ptr)
{
    int res, index;
    target_ulong addr;
    unsigned long physaddr;
    int mmu_idx;

    addr = ptr;
    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    mmu_idx = CPU_MMU_INDEX;
    if (__builtin_expect(env->tlb_table[mmu_idx][index].ADDR_READ !=
                         (addr & (TARGET_PAGE_MASK | (DATA_SIZE - 1))), 0)) {
        res = (DATA_STYPE)glue(glue(__TD_ld, SUFFIX), MMUSUFFIX)(addr, mmu_idx);
    } else {
        physaddr = addr + env->tlb_table[mmu_idx][index].addend;
        res = glue(glue(TD_lds, SUFFIX), _raw)((uint8_t *)physaddr);
    }
    return res;
}
#endif

void REGPARM(2) glue(glue(__TD_st, SUFFIX), MMUSUFFIX)(target_ulong addr, DATA_TYPE v, int mmu_idx);

static inline void glue(glue(TD_st, SUFFIX), MEMSUFFIX)(target_ulong ptr, RES_TYPE v)
{
    int index;
    target_ulong addr;
    unsigned long physaddr;
    int mmu_idx;

    addr = ptr;
    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    mmu_idx = CPU_MMU_INDEX;
    if (__builtin_expect(env->tlb_table[mmu_idx][index].addr_write !=
                         (addr & (TARGET_PAGE_MASK | (DATA_SIZE - 1))), 0)) {
        glue(glue(__TD_st, SUFFIX), MMUSUFFIX)(addr, v, mmu_idx);
    } else {
        physaddr = addr + env->tlb_table[mmu_idx][index].addend;
        glue(glue(TD_st, SUFFIX), _raw)((uint8_t *)physaddr, v);
    }
}


