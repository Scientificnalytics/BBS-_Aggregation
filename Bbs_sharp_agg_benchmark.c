Bbs_sharp_agg_benchmark.c aplikacijos programinis kodas
// bbs_sharp_agg_benchmark.c Agreguotos vs neagreguotos BBS# tipo matavimų versijos 
// Dvi VC (po 5 atributus), skirtingi leidėjai; įskaičiuojama maskuojančio RNG kaina lygybės įsipareigojimams.
// Kompiliuoti be libsecp256k1 Windows sistemoje:  cl /O2 /W4 /DNO_SECP256K1 bbs_sharp_agg_benchmark.c

#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#ifdef _WIN32
  #include <windows.h>
#endif

#ifndef NO_SECP256K1
  #include <secp256k1.h>
#endif

/* -- Parametrai (secp256k1: 33B suspausti taškai, 32B skaliarės) -- */
#define GE_BYTES                 33
#define SCALAR_BYTES             32

#define CHALLENGE_BYTES          32
#define HOLDER_SIG_BYTES         64

static const uint8_t FIXED_CHALLENGE[CHALLENGE_BYTES] = {
  0x3f,0x90,0x75,0x76,0x3a,0x3d,0x90,0x2c,0x7b,0x3a,0xd8,0x6f,0x6a,0x73,0x6c,0x7b,
  0x7f,0x19,0x9d,0x1a,0x4e,0x6d,0x45,0xfb,0x8a,0x97,0x2d,0x9f,0x64,0x9a,0x29,0x8b
};
static const uint8_t FIXED_HOLDER_SIG[HOLDER_SIG_BYTES] = {
  0x4e,0xd0,0x8f,0x8a,0x72,0x47,0x3a,0x4d,0x7d,0x53,0x2a,0x67,0x1a,0x92,0x43,0x0c,
  0x76,0x21,0x1b,0x9f,0x6b,0xf3,0x33,0xa9,0x15,0x5e,0xb1,0x08,0x5d,0x7b,0x2a,0x61,
  0x0f,0x2a,0x9d,0x3c,0x89,0x7a,0x11,0x6b,0x41,0x44,0x18,0x7c,0xce,0x9f,0x55,0x33,
  0x63,0x9f,0xa8,0x10,0x3a,0x8f,0x17,0x5e,0x1c,0x2f,0x5b,0x91,0x7e,0x27,0xc2,0x4d
};
#define IGNORE_UNUSED() do{ (void)FIXED_CHALLENGE; (void)FIXED_HOLDER_SIG; }while(0)

/* Leidėjo PoK-of-signature „branduolio“ dydžiai (per VC) — pritaikykite pagal savo BBS# 3-ąjį variantą */
#define POK_CORE_GE              3
#define POK_CORE_SCALARS         6

/* Skaičiai kiekvienam režimui */
#define CHALLENGE_COUNT_AGGREGATED   1
#define HOLDER_SIG_COUNT_AGGREGATED  1
static inline int challenge_count_separate(int k_eq) { return 2 + k_eq; }
#define HOLDER_SIG_COUNT_SEPARATE    2

/* Atributai vienai VC ir pakartojimų skaičius */
#define N_ATTR   5
#define REPEATS  100

/* Ar į laiką įtraukti RNG (maskavimo) kainą? */
#define INCLUDE_RNG_COST  1

/* --- Didelės raiškos laikas (ns) --- */
static inline uint64_t now_ns(void) {
#ifdef _WIN32
    static LARGE_INTEGER freq = {0};
    LARGE_INTEGER ctr;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&ctr);
    long double sec = (long double)ctr.QuadPart / (long double)freq.QuadPart;
    return (uint64_t)(sec * 1e9L);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec) * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

/* --- xorshift128+ PRNG maskuojančioms skaliarėms --- */
typedef struct { uint64_t a, b; } xs128p_t;
static inline xs128p_t xs128p_seed(uint64_t s1, uint64_t s2){ xs128p_t st={s1? s1:1, s2? s2:0x9e3779b97f4a7c15ull}; return st; }
static inline uint64_t xs128p_next(xs128p_t* s){
    uint64_t x = s->a, y = s->b;
    s->a = y; x ^= x << 23; s->b = x ^ y ^ (x >> 17) ^ (y >> 26);
    return s->b + y;
}
static inline void prng_bytes(xs128p_t* st, uint8_t* out, size_t n){
    for(size_t i=0;i<n;i+=8){
        uint64_t w = xs128p_next(st);
        size_t left = (n - i) < 8 ? (n - i) : 8;
        memcpy(out + i, &w, left);
    }
}
static inline void rng_burn_scalars(int count, xs128p_t* st){
#if INCLUDE_RNG_COST
    uint8_t buf[32];
    for(int i=0;i<count;++i){ prng_bytes(st, buf, sizeof(buf)); }
#else
    (void)count; (void)st;
#endif
}

/* --- Pasirinktinai tikras EC darbas per libsecp256k1 --- */
#ifndef NO_SECP256K1
static secp256k1_context *g_ctx = NULL;
#endif

static void do_gen_mults_from_rng(int count, xs128p_t* st){
#ifndef NO_SECP256K1
    for(int i=0;i<count;++i){
        uint8_t seckey[32];
        prng_bytes(st, seckey, sizeof(seckey));
        seckey[0] |= 1;
        secp256k1_pubkey pub;
        (void)secp256k1_ec_pubkey_create(g_ctx, &pub, seckey);
    }
#else
    volatile uint64_t s = st->a ^ st->b;
    for (int i = 0; i < count * 20000; ++i) s = (s * 11400714819323198485ull) ^ (uint64_t)i;
    (void)s;
#endif
}

/* --- Dydžio modelis --- */
static inline size_t issuer_pok_core_bytes(void){
    return (size_t)POK_CORE_GE * GE_BYTES + (size_t)POK_CORE_SCALARS * SCALAR_BYTES;
}
static inline size_t equality_bytes_separate(int k){
    return (k<=0)?0:(size_t)k * (GE_BYTES + SCALAR_BYTES);           /* k × (1 GE + 1 S) */
}
static inline size_t equality_bytes_aggregated(int k){
    return (k<=0)?0:(size_t)(GE_BYTES + (size_t)k * SCALAR_BYTES);   /* 1 GE + k S */
}
static inline size_t revealed_attr_bytes(int r1,int r2){ return (size_t)(r1+r2)*32; }
static inline size_t challenge_bytes_separate(int k){ return (size_t)challenge_count_separate(k)*CHALLENGE_BYTES; }
static inline size_t challenge_bytes_aggregated(void){ return (size_t)CHALLENGE_COUNT_AGGREGATED*CHALLENGE_BYTES; }

/* --- Scenarijaus aprašas --- */
typedef struct {
    int combo;
    int r1,h1,r2,h2;
    int total_reveal,total_hidden;
    int m_rev,m_hid;
    int k_eq;   /* paslėptų lygybių, kurioms reikia ZK, skaičius */
} scenario_t;

/* CSV antraštės */
static void headers(FILE* a, FILE* b, FILE* c, FILE* ta, FILE* tb, FILE* tc){
    fprintf(a,"combo,r1,h1,r2,h2,total_reveal,total_hidden,m_rev,m_hid,k_eq,challenges,holder_sigs,bytes_total\n");
    fprintf(b,"combo,r1,h1,r2,h2,total_reveal,total_hidden,m_rev,m_hid,k_eq,challenges,holder_sigs,bytes_total\n");
    fprintf(c,"combo,r1,h1,r2,h2,total_reveal,total_hidden,m_rev,m_hid,k_eq,bytes_agg,bytes_sep,bytes_delta\n");
    fprintf(ta,"combo,k_eq,ns_mean\n");
    fprintf(tb,"combo,k_eq,ns_mean\n");
    fprintf(tc,"combo,k_eq,ns_agg,ns_sep,ns_delta_abs\n");
}

/* Bendra žinutės apimtis */
static size_t total_bytes_aggregated(const scenario_t* s){
    size_t issuer = 2 * issuer_pok_core_bytes();
    size_t eq     = equality_bytes_aggregated(s->k_eq);
    size_t chall  = challenge_bytes_aggregated();
    size_t rev    = revealed_attr_bytes(s->r1,s->r2);
    size_t sigs   = (size_t)HOLDER_SIG_COUNT_AGGREGATED * HOLDER_SIG_BYTES;
    return issuer + eq + chall + rev + sigs;
}
static size_t total_bytes_separate(const scenario_t* s){
    size_t issuer = 2 * issuer_pok_core_bytes();
    size_t eq     = equality_bytes_separate(s->k_eq);
    size_t chall  = challenge_bytes_separate(s->k_eq);        /* 2 + k */
    size_t rev    = revealed_attr_bytes(s->r1,s->r2);
    size_t sigs   = (size_t)HOLDER_SIG_COUNT_SEPARATE * HOLDER_SIG_BYTES; /* du vokai */
    return issuer + eq + chall + rev + sigs;
}

/* Lygybės laiko matavimas (su maskuojančio RNG kaina) */
static uint64_t t_ns_eq_agg(const scenario_t* s){
    xs128p_t st = xs128p_seed(0xA9B4C3D2ull + s->combo, 0x1d3f5b79a2c4e6f8ull);
    int blinding_scalars = (s->k_eq > 0) ? 1 : 0;
    rng_burn_scalars(blinding_scalars, &st);
    uint64_t t0 = now_ns();
    for(int r=0;r<REPEATS;++r){ do_gen_mults_from_rng((s->k_eq>0)?1:0, &st); }
    uint64_t t1 = now_ns();
    return (t1 - t0) / (REPEATS ? REPEATS : 1);
}
static uint64_t t_ns_eq_sep(const scenario_t* s){
    xs128p_t st = xs128p_seed(0x13579BDFull + s->combo, 0x0123456789abcdefull);
    int blinding_scalars = s->k_eq;
    rng_burn_scalars(blinding_scalars, &st);
    uint64_t t0 = now_ns();
    for(int r=0;r<REPEATS;++r){ do_gen_mults_from_rng(s->k_eq, &st); }
    uint64_t t1 = now_ns();
    return (t1 - t0) / (REPEATS ? REPEATS : 1);
}

int main(void){
#ifndef NO_SECP256K1
    secp256k1_context *g_ctx_local = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if(!g_ctx_local){ fprintf(stderr,"secp256k1 konteksto inicijavimas nepavyko\n"); return 1; }
    /* padarome matomą funkcijai do_gen_mults_from_rng */
    extern secp256k1_context *g_ctx;
    g_ctx = g_ctx_local;
#endif
    IGNORE_UNUSED();

    FILE* fA=fopen("sizes_aggregated.csv","w");
    FILE* fB=fopen("sizes_separate.csv","w");
    FILE* fC=fopen("sizes_compare.csv","w");
    FILE* tA=fopen("times_aggregated.csv","w");
    FILE* tB=fopen("times_separate.csv","w");
    FILE* tC=fopen("times_compare.csv","w");
    if(!fA||!fB||!fC||!tA||!tB||!tC){ fprintf(stderr,"nepavyko atidaryti CSV failų\n"); return 2; }
    headers(fA,fB,fC,tA,tB,tC);

    int combo=0;
    for(int r1=N_ATTR;r1>=0;--r1){
        int h1=N_ATTR-r1;
        for(int r2=N_ATTR;r2>=0;--r2){
            int h2=N_ATTR-r2;
            int tr=r1+r2, th=h1+h2;
            int kmin = (r1+r2 - N_ATTR > 0) ? (r1+r2 - N_ATTR) : 0;
            int kmax = (r1<r2)?r1:r2;

            ++combo;
            int seen[(N_ATTR+1)*(N_ATTR+1)]; memset(seen,0,sizeof(seen));
            for(int k=kmin;k<=kmax;++k){
                for(int mrev=0;mrev<=k;++mrev){
                    for(int mhid=0; mhid<= (N_ATTR - k); ++mhid){
                        int idx = mrev*(N_ATTR+1)+mhid;
                        if(seen[idx]) continue; seen[idx]=1;

                        scenario_t s = {combo,r1,h1,r2,h2,tr,th,mrev,mhid,mhid};

                        size_t bAgg = total_bytes_aggregated(&s);
                        size_t bSep = total_bytes_separate(&s);

                        fprintf(fA,"%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%zu\n",
                            combo,r1,h1,r2,h2,tr,th,mrev,mhid,s.k_eq,
                            CHALLENGE_COUNT_AGGREGATED,HOLDER_SIG_COUNT_AGGREGATED,bAgg);
                        fprintf(fB,"%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%zu\n",
                            combo,r1,h1,r2,h2,tr,th,mrev,mhid,s.k_eq,
                            challenge_count_separate(s.k_eq),HOLDER_SIG_COUNT_SEPARATE,bSep);

                        /* Skirtumui naudojame long long, kad išvengtume size_t/%zd problemų */
                        long long delta = (long long)bAgg - (long long)bSep;
                        fprintf(fC,"%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%zu,%zu,%lld\n",
                            combo,r1,h1,r2,h2,tr,th,mrev,mhid,s.k_eq,bAgg,bSep,delta);

                        uint64_t tAgg = t_ns_eq_agg(&s);
                        uint64_t tSep = t_ns_eq_sep(&s);
                        uint64_t d    = (tAgg>tSep)?(tAgg-tSep):(tSep-tAgg);
                        fprintf(tA,"%d,%d,%" PRIu64 "\n",combo,s.k_eq,tAgg);
                        fprintf(tB,"%d,%d,%" PRIu64 "\n",combo,s.k_eq,tSep);
                        fprintf(tC,"%d,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",combo,s.k_eq,tAgg,tSep,d);
                    }
                }
            }
        }
    }

    fclose(fA); fclose(fB); fclose(fC);
    fclose(tA); fclose(tB); fclose(tC);
#ifndef NO_SECP256K1
    secp256k1_context_destroy(g_ctx);
#endif
    fprintf(stderr,"Vykdymas baigtas. Įrašyta į sizes_*.csv ir times_*.csv\n");
    return 0;
}
