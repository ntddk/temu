#ifndef CPU_SPARC_H
#define CPU_SPARC_H

#include "config.h"

#if !defined(TARGET_SPARC64)
#define TARGET_LONG_BITS 32
#define TARGET_FPREGS 32
#define TARGET_PAGE_BITS 12 /* 4k */
#else
#define TARGET_LONG_BITS 64
#define TARGET_FPREGS 64
#define TARGET_PAGE_BITS 12 /* XXX */
#endif

#include "cpu-defs.h"

#include "softfloat.h"

#define TARGET_HAS_ICE 1

/*#define EXCP_INTERRUPT 0x100*/

/* trap definitions */
#ifndef TARGET_SPARC64
#define TT_TFAULT   0x01
#define TT_ILL_INSN 0x02
#define TT_PRIV_INSN 0x03
#define TT_NFPU_INSN 0x04
#define TT_WIN_OVF  0x05
#define TT_WIN_UNF  0x06 
#define TT_FP_EXCP  0x08
#define TT_DFAULT   0x09
#define TT_EXTINT   0x10
#define TT_DIV_ZERO 0x2a
#define TT_TRAP     0x80
#else
#define TT_TFAULT   0x08
#define TT_TMISS    0x09
#define TT_ILL_INSN 0x10
#define TT_PRIV_INSN 0x11
#define TT_NFPU_INSN 0x20
#define TT_FP_EXCP  0x21
#define TT_CLRWIN   0x24
#define TT_DIV_ZERO 0x28
#define TT_DFAULT   0x30
#define TT_DMISS    0x31
#define TT_DPROT    0x32
#define TT_PRIV_ACT 0x37
#define TT_EXTINT   0x40
#define TT_SPILL    0x80
#define TT_FILL     0xc0
#define TT_WOTHER   0x10
#define TT_TRAP     0x100
#endif

#define PSR_NEG   (1<<23)
#define PSR_ZERO  (1<<22)
#define PSR_OVF   (1<<21)
#define PSR_CARRY (1<<20)
#define PSR_ICC   (PSR_NEG|PSR_ZERO|PSR_OVF|PSR_CARRY)
#define PSR_EF    (1<<12)
#define PSR_PIL   0xf00
#define PSR_S     (1<<7)
#define PSR_PS    (1<<6)
#define PSR_ET    (1<<5)
#define PSR_CWP   0x1f

/* Trap base register */
#define TBR_BASE_MASK 0xfffff000

#if defined(TARGET_SPARC64)
#define PS_IG    (1<<11)
#define PS_MG    (1<<10)
#define PS_RED   (1<<5)
#define PS_PEF   (1<<4)
#define PS_AM    (1<<3)
#define PS_PRIV  (1<<2)
#define PS_IE    (1<<1)
#define PS_AG    (1<<0)

#define FPRS_FEF (1<<2)
#endif

/* Fcc */
#define FSR_RD1        (1<<31)
#define FSR_RD0        (1<<30)
#define FSR_RD_MASK    (FSR_RD1 | FSR_RD0)
#define FSR_RD_NEAREST 0
#define FSR_RD_ZERO    FSR_RD0
#define FSR_RD_POS     FSR_RD1
#define FSR_RD_NEG     (FSR_RD1 | FSR_RD0)

#define FSR_NVM   (1<<27)
#define FSR_OFM   (1<<26)
#define FSR_UFM   (1<<25)
#define FSR_DZM   (1<<24)
#define FSR_NXM   (1<<23)
#define FSR_TEM_MASK (FSR_NVM | FSR_OFM | FSR_UFM | FSR_DZM | FSR_NXM)

#define FSR_NVA   (1<<9)
#define FSR_OFA   (1<<8)
#define FSR_UFA   (1<<7)
#define FSR_DZA   (1<<6)
#define FSR_NXA   (1<<5)
#define FSR_AEXC_MASK (FSR_NVA | FSR_OFA | FSR_UFA | FSR_DZA | FSR_NXA)

#define FSR_NVC   (1<<4)
#define FSR_OFC   (1<<3)
#define FSR_UFC   (1<<2)
#define FSR_DZC   (1<<1)
#define FSR_NXC   (1<<0)
#define FSR_CEXC_MASK (FSR_NVC | FSR_OFC | FSR_UFC | FSR_DZC | FSR_NXC)

#define FSR_FTT2   (1<<16)
#define FSR_FTT1   (1<<15)
#define FSR_FTT0   (1<<14)
#define FSR_FTT_MASK (FSR_FTT2 | FSR_FTT1 | FSR_FTT0)
#define FSR_FTT_IEEE_EXCP (1 << 14)
#define FSR_FTT_UNIMPFPOP (3 << 14)
#define FSR_FTT_INVAL_FPR (6 << 14)

#define FSR_FCC1  (1<<11)
#define FSR_FCC0  (1<<10)

/* MMU */
#define MMU_E	  (1<<0)
#define MMU_NF	  (1<<1)

#define PTE_ENTRYTYPE_MASK 3
#define PTE_ACCESS_MASK    0x1c
#define PTE_ACCESS_SHIFT   2
#define PTE_PPN_SHIFT      7
#define PTE_ADDR_MASK      0xffffff00

#define PG_ACCESSED_BIT	5
#define PG_MODIFIED_BIT	6
#define PG_CACHE_BIT    7

#define PG_ACCESSED_MASK (1 << PG_ACCESSED_BIT)
#define PG_MODIFIED_MASK (1 << PG_MODIFIED_BIT)
#define PG_CACHE_MASK    (1 << PG_CACHE_BIT)

/* 2 <= NWINDOWS <= 32. In QEMU it must also be a power of two. */
#define NWINDOWS  8

typedef struct CPUSPARCState {
    target_ulong gregs[8]; /* general registers */
    target_ulong *regwptr; /* pointer to current register window */
    float32 fpr[TARGET_FPREGS];  /* floating point registers */
    target_ulong pc;       /* program counter */
    target_ulong npc;      /* next program counter */
    target_ulong y;        /* multiply/divide register */
    uint32_t psr;      /* processor state register */
    target_ulong fsr;      /* FPU state register */
    uint32_t cwp;      /* index of current register window (extracted
                          from PSR) */
    uint32_t wim;      /* window invalid mask */
    target_ulong tbr;  /* trap base register */
    int      psrs;     /* supervisor mode (extracted from PSR) */
    int      psrps;    /* previous supervisor mode */
    int      psret;    /* enable traps */
    uint32_t psrpil;   /* interrupt level */
    int      psref;    /* enable fpu */
    jmp_buf  jmp_env;
    int user_mode_only;
    int exception_index;
    int interrupt_index;
    int interrupt_request;
    int halted;
    /* NOTE: we allow 8 more registers to handle wrapping */
    target_ulong regbase[NWINDOWS * 16 + 8];

    CPU_COMMON

    /* MMU regs */
#if defined(TARGET_SPARC64)
    uint64_t lsu;
#define DMMU_E 0x8
#define IMMU_E 0x4
    uint64_t immuregs[16];
    uint64_t dmmuregs[16];
    uint64_t itlb_tag[64];
    uint64_t itlb_tte[64];
    uint64_t dtlb_tag[64];
    uint64_t dtlb_tte[64];
#else
    uint32_t mmuregs[16];
#endif
    /* temporary float registers */
    float32 ft0, ft1;
    float64 dt0, dt1;
    float_status fp_status;
#if defined(TARGET_SPARC64)
#define MAXTL 4
    uint64_t t0, t1, t2;
    uint64_t tpc[MAXTL];
    uint64_t tnpc[MAXTL];
    uint64_t tstate[MAXTL];
    uint32_t tt[MAXTL];
    uint32_t xcc;		/* Extended integer condition codes */
    uint32_t asi;
    uint32_t pstate;
    uint32_t tl;
    uint32_t cansave, canrestore, otherwin, wstate, cleanwin;
    uint64_t agregs[8]; /* alternate general registers */
    uint64_t bgregs[8]; /* backup for normal global registers */
    uint64_t igregs[8]; /* interrupt general registers */
    uint64_t mgregs[8]; /* mmu general registers */
    uint64_t version;
    uint64_t fprs;
    uint64_t tick_cmpr, stick_cmpr;
    uint64_t gsr;
#endif
#if !defined(TARGET_SPARC64) && !defined(reg_T2)
    target_ulong t2;
#endif
} CPUSPARCState;
#if defined(TARGET_SPARC64)
#define GET_FSR32(env) (env->fsr & 0xcfc1ffff)
#define PUT_FSR32(env, val) do { uint32_t _tmp = val;			\
	env->fsr = (_tmp & 0xcfc1c3ff) | (env->fsr & 0x3f00000000ULL);	\
    } while (0)
#define GET_FSR64(env) (env->fsr & 0x3fcfc1ffffULL)
#define PUT_FSR64(env, val) do { uint64_t _tmp = val;	\
	env->fsr = _tmp & 0x3fcfc1c3ffULL;		\
    } while (0)
// Manuf 0x17, version 0x11, mask 0 (UltraSparc-II)
#define GET_VER(env) ((0x17ULL << 48) | (0x11ULL << 32) |		\
		      (0 << 24) | (MAXTL << 8) | (NWINDOWS - 1))
#else
#define GET_FSR32(env) (env->fsr)
#define PUT_FSR32(env, val) do { uint32_t _tmp = val;	\
	env->fsr = _tmp & 0xcfc1ffff;			\
    } while (0)
#endif

CPUSPARCState *cpu_sparc_init(void);
int cpu_sparc_exec(CPUSPARCState *s);
int cpu_sparc_close(CPUSPARCState *s);

/* Fake impl 0, version 4 */
#define GET_PSR(env) ((0 << 28) | (4 << 24) | (env->psr & PSR_ICC) |	\
		      (env->psref? PSR_EF : 0) |			\
		      (env->psrpil << 8) |				\
		      (env->psrs? PSR_S : 0) |				\
		      (env->psrps? PSR_PS : 0) |			\
		      (env->psret? PSR_ET : 0) | env->cwp)

#ifndef NO_CPU_IO_DEFS
void cpu_set_cwp(CPUSPARCState *env1, int new_cwp);
#endif

#define PUT_PSR(env, val) do { int _tmp = val;				\
	env->psr = _tmp & PSR_ICC;					\
	env->psref = (_tmp & PSR_EF)? 1 : 0;				\
	env->psrpil = (_tmp & PSR_PIL) >> 8;				\
	env->psrs = (_tmp & PSR_S)? 1 : 0;				\
	env->psrps = (_tmp & PSR_PS)? 1 : 0;				\
	env->psret = (_tmp & PSR_ET)? 1 : 0;				\
	cpu_set_cwp(env, _tmp & PSR_CWP & (NWINDOWS - 1));		\
    } while (0)

#ifdef TARGET_SPARC64
#define GET_CCR(env) ((env->xcc << 4) | (env->psr & PSR_ICC))
#define PUT_CCR(env, val) do { int _tmp = val;				\
	env->xcc = _tmp >> 4;						\
	env->psr = (_tmp & 0xf) << 20;					\
    } while (0)
#endif

struct siginfo;
int cpu_sparc_signal_handler(int hostsignum, struct siginfo *info, void *puc);

#include "cpu-all.h"

#endif
