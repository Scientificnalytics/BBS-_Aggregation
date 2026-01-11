// bbs_hashlink_benchmark_progress.c
// Suporų nenaudojantis BBS# stiliaus nesusiejamumo (unlinkability) Monte Karlo testas su eigos rodymu (libsecp256k1).
// Dabar visai kriptografinei medžiagai naudoja Windows CSPRNG (BCryptGenRandom).
// Išveda failus:
//   unlinkability_compare.csv  – kiekvieno scenarijaus „kolizijų panašumo“ ir tolygumo diagnostika
//   coalition_compare.csv – kiekvieno scenarijaus koalicijų susiejimo tikimybės (AGG/SEP + teorija)
//   sameprover_compare.csv – kiekvieno scenarijaus to paties įrodančiojo nesusiejamumas (adversarinis testas)
//   agg_sep_test.csv – kiekvieno scenarijaus porinis permutacijų testas + Holm ir BH koreguotos p reikšmės
//
// Kompiliavimas (MSVC + vcpkg, x64 Native Tools Prompt):
//   cl /O2 /MD /W4 "C:\\Users\\user\\bbs_hashlink_benchmark_progress.c" ^
//     /I"C:\\vcpkg\\installed\\x64-windows\\include" ^
//     /DTRIALS_PER_SCENARIO=200 /DCOALITION_ROUNDS=2000 ^
//     /Fe"C:\\Users\\user\\Desktop\\bbs_hashlink_benchmark.exe" ^
//     /link /LIBPATH:"C:\\vcpkg\\installed\\x64-windows\\lib" ^
//           secp256k1.lib secp256k1_precomputed.lib
//
// Pastabos:
// - CSPRNG: BCryptGenRandom (sistemos pageidautinas RNG).
// - xorshift128+ paliktas tik ne paslaptims – simuliacijos valdymo keliams.
// - Tag = SHA256(ser_compressed(x * B_s))[:FPR_BYTES]; FPR yra maždaug 2^(-8*FPR_BYTES).
// - „AGG“ vs „SEP“ = dvi skirtingos „scope“ koduotės; testuojamos poriniu permutacijų testu.
// - Empirinės kolizijos ties 128 bitų atmetamos kaip beprasmės; pranešama tik teorinė „birthday bound“ riba.

#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include <secp256k1.h>

/* ---------- Derinami parametrai (tunables) ---------- */
#ifndef N_ATTR
#define N_ATTR 5
#endif

#ifndef FPR_BYTES
#define FPR_BYTES 16 /* 128 bitų žymė */
#endif

#ifndef TRIALS_PER_SCENARIO
#define TRIALS_PER_SCENARIO  20000
#endif

#ifndef COALITION_ROUNDS
#define COALITION_ROUNDS      5000
#endif

/* Koalicijų dydžiai testavimui */
static const int COALITION_SIZES[] = {2, 4, 8, 16};
#define NUM_COALITIONS (int)(sizeof(COALITION_SIZES)/sizeof(COALITION_SIZES[0]))

/* Permutacijų testo iteracijos (laikykite mažą dėl spartos; didinkite dėl griežtumo) */
#ifndef PERM_ITERS
#define PERM_ITERS 1000
#endif

/* To paties įrodančiojo scenarijus: tikrintojų skaičius viename raunde */
#ifndef SAMEPROVER_V
#define SAMEPROVER_V 16
#endif

/* Adversorius: prefikso bitai naudojami kaip grubus papildomas euristinis kriterijus (be pilno sutapimo) */
#ifndef ADV_PREFIX_BITS
#define ADV_PREFIX_BITS 8
#endif

/* Vienodumo (uniformity) testas – pavyzdžių skaičius vienam scenarijui/žymai (AGG/SEP) */
#ifndef UNIF_SAMPLES
#define UNIF_SAMPLES 2048
#endif

/* ---------- OS CSPRNG ---------- */
static inline int csprng(void* buf, size_t len){
    NTSTATUS s = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return s == 0 ? 1 : 0; /* sėkmės atveju grąžina 1 – simetrijai su kitomis pagalbinėmis funkcijomis */
}

/* ---------- xorshift128+ RNG (naudojamas tik ne paslaptims) ---------- */
typedef struct { uint64_t a, b; } xs128p_t;
static inline xs128p_t xs128p_seed(uint64_t s1, uint64_t s2){
    xs128p_t st = { s1 ? s1 : 1, s2 ? s2 : 0x9e3779b97f4a7c15ull };
    return st;
}
static inline uint64_t xs128p_next(xs128p_t* s){
    uint64_t x = s->a, y = s->b;
    s->a = y;
    x ^= x << 23;
    s->b = x ^ y ^ (x >> 17) ^ (y >> 26);
    return s->b + y;
}
static inline uint32_t prng_u32(xs128p_t* st){
    uint64_t w = xs128p_next(st);
    return (uint32_t)(w ^ (w>>32));
}

/* ---------- Minimalus SHA-256 įgyvendinimas ---------- */
typedef struct {
    uint32_t s[8];
    uint64_t bits;
    uint8_t  buf[64];
    size_t   idx;
} sha256_t;

static inline uint32_t ROR(uint32_t x, uint32_t n){ return (x>>n)|(x<<(32-n)); }
static inline uint32_t Ch(uint32_t x,uint32_t y,uint32_t z){ return (x & y) ^ (~x & z); }
static inline uint32_t Maj(uint32_t x,uint32_t y,uint32_t z){ return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t BSIG0(uint32_t x){ return ROR(x,2) ^ ROR(x,13) ^ ROR(x,22); }
static inline uint32_t BSIG1(uint32_t x){ return ROR(x,6) ^ ROR(x,11) ^ ROR(x,25); }
static inline uint32_t SSIG0(uint32_t x){ return ROR(x,7) ^ ROR(x,18) ^ (x>>3); }
static inline uint32_t SSIG1(uint32_t x){ return ROR(x,17) ^ ROR(x,19) ^ (x>>10); }

static const uint32_t K256[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_init(sha256_t* c){
    c->s[0]=0x6a09e667; c->s[1]=0xbb67ae85; c->s[2]=0x3c6ef372; c->s[3]=0xa54ff53a;
    c->s[4]=0x510e527f; c->s[5]=0x9b05688c; c->s[6]=0x1f83d9ab; c->s[7]=0x5be0cd19;
    c->bits=0; c->idx=0;
}
static void sha256_block(sha256_t* c, const uint8_t* p){
    uint32_t w[64];
    for(int i=0;i<16;++i){
        w[i]=(uint32_t)p[4*i]<<24 | (uint32_t)p[4*i+1]<<16 | (uint32_t)p[4*i+2]<<8 | (uint32_t)p[4*i+3];
    }
    for(int i=16;i<64;++i) w[i]=SSIG1(w[i-2])+w[i-7]+SSIG0(w[i-15])+w[i-16];
    uint32_t a=c->s[0],b=c->s[1],c0=c->s[2],d=c->s[3],e=c->s[4],f=c->s[5],g=c->s[6],h=c->s[7];
    for(int i=0;i<64;++i){
        uint32_t t1=h+BSIG1(e)+Ch(e,f,g)+K256[i]+w[i];
        uint32_t t2=BSIG0(a)+Maj(a,b,c0);
        h=g; g=f; f=e; e=d+t1; d=c0; c0=b; b=a; a=t1+t2;
    }
    c->s[0]+=a; c->s[1]+=b; c->s[2]+=c0; c->s[3]+=d; c->s[4]+=e; c->s[5]+=f; c->s[6]+=g; c->s[7]+=h;
}
static void sha256_update(sha256_t* c, const void* data, size_t len){
    const uint8_t* p=(const uint8_t*)data;
    c->bits += (uint64_t)len * 8;
    while(len--){
        c->buf[c->idx++]=*p++;
        if(c->idx==64){ sha256_block(c,c->buf); c->idx=0; }
    }
}
static void sha256_final(sha256_t* c, uint8_t out[32]){
    c->buf[c->idx++]=0x80;
    if(c->idx>56){ while(c->idx<64) c->buf[c->idx++]=0; sha256_block(c,c->buf); c->idx=0; }
    while(c->idx<56) c->buf[c->idx++]=0;
    for(int i=7;i>=0;--i){ c->buf[c->idx++]=(uint8_t)(c->bits>>(i*8)); }
    sha256_block(c,c->buf);
    for(int i=0;i<8;++i){
        out[4*i]=(uint8_t)(c->s[i]>>24);
        out[4*i+1]=(uint8_t)(c->s[i]>>16);
        out[4*i+2]=(uint8_t)(c->s[i]>>8);
        out[4*i+3]=(uint8_t)(c->s[i]);
    }
}

/* ---------- Scenarijaus tipas ir pagalbinės funkcijos ---------- */
typedef struct {
    int combo;
    int r1,h1,r2,h2;
    int k_eq;
} scenario_t;

/* Domeniškai atskirti „scope“ baitai iš scenarijaus + etiketės („AGG“/„SEP“) */
static void make_scope_bytes(const char* label, const scenario_t* s, uint8_t out[32]){
    const char* dom = (label && label[0]=='A') ? "BBS-HASHLINK:AGG:" : "BBS-HASHLINK:SEP:";
    sha256_t H; sha256_init(&H);
    sha256_update(&H, dom, (int)strlen(dom));
    sha256_update(&H, &s->combo, sizeof(s->combo));
    sha256_update(&H, &s->r1, sizeof(s->r1));
    sha256_update(&H, &s->h1, sizeof(s->h1));
    sha256_update(&H, &s->r2, sizeof(s->r2));
    sha256_update(&H, &s->h2, sizeof(s->h2));
    sha256_update(&H, &s->k_eq, sizeof(s->k_eq));
    sha256_final(&H, out);
}

/* 32 baitus atvaizduoja į galiojantį skaliarą intervale (0,n), perhashindamas su skaitikliu, kol gaus tinkamą */
static int bytes_to_valid_scalar(secp256k1_context* ctx,
                                 const uint8_t in32[32],
                                 uint8_t out32[32]){
    for (uint32_t ctr = 0; ctr < 100000; ++ctr) {
        sha256_t H; uint8_t h[32];
        sha256_init(&H);
        sha256_update(&H, in32, 32);
        sha256_update(&H, &ctr, sizeof(ctr));
        sha256_final(&H, h);
        h[0] |= 1; /* vengti nulio */
        if (secp256k1_ec_seckey_verify(ctx, h)) { memcpy(out32, h, 32); return 1; }
    }
    return 0;
}

/* Domeniškai atskirtas „hash-to-scalar“ -> bazinis taškas B_s = b*G */
static int ds_scope_base_pub(secp256k1_context* ctx,
                             const uint8_t scope32[32],
                             secp256k1_pubkey* B){
    uint8_t b[32];
    if(!bytes_to_valid_scalar(ctx, scope32, b)) return 0;
    return secp256k1_ec_pubkey_create(ctx, B, b);
}
/* Parenka atsitiktinę galiojančią „link secret“ x iš OS CSPRNG */
static int sample_link_secret(secp256k1_context* ctx, uint8_t x[32]){
    for(int i=0;i<1000;++i){
        if(!csprng(x, 32)) return 0;
        x[0] |= 1; /* vengti nulio */
        if(secp256k1_ec_seckey_verify(ctx, x)) return 1;
    }
    return 0;
}
/* Apskaičiuoja tag = SHA256(ser_compressed( x * B_s ))[:FPR_BYTES] */
static int bbs_scope_tag(secp256k1_context* ctx,
                         const uint8_t link_secret[32],
                         const uint8_t scope32[32],
                         uint8_t out_tag[FPR_BYTES]){
    secp256k1_pubkey B, T;
    if(!ds_scope_base_pub(ctx, scope32, &B)) return 0;

    T = B;
    if(!secp256k1_ec_pubkey_tweak_mul(ctx, &T, link_secret)) return 0;

    uint8_t ser[33]; size_t slen = 33;
    if(!secp256k1_ec_pubkey_serialize(ctx, ser, &slen, &T, SECP256K1_EC_COMPRESSED)) return 0;

    uint8_t h[32]; sha256_t H; sha256_init(&H); sha256_update(&H, ser, (size_t)slen); sha256_final(&H, h);
    memcpy(out_tag, h, FPR_BYTES);
    return 1;
}
/* ---------- Transkriptas ir adversorius ---------- */
typedef struct {
    uint8_t tag[FPR_BYTES];
    uint8_t scope_id;     /* 0 = SEP, 1 = AGG */
    uint8_t scope_lsb8;   /* greitas domeno atskyrimo efektų aproksimacijos indikatorius */
    uint8_t nonce_bits;   /* simuliuojamas per-tikrintoją nonce entropijos plotis bitais */
} transcript_t;

static int make_transcript(secp256k1_context* ctx,
                           const scenario_t* s, int aggregated,
                           const uint8_t x[32], uint8_t nonce_bits,
                           transcript_t* out){
    uint8_t scope32[32];
    make_scope_bytes(aggregated ? "AGG" : "SEP", s, scope32);
    if(!bbs_scope_tag(ctx, x, scope32, out->tag)) return 0;
    out->scope_id   = aggregated ? 1u : 0u;
    out->scope_lsb8 = scope32[31];
    out->nonce_bits = nonce_bits;
    return 1;
}

/* Paprastas adversorius, jungiantis kelias euristikas papildomai prie griežto lygybės tikrinimo */
static int link_test_transcript(const transcript_t* a, const transcript_t* b){
    if (memcmp(a->tag, b->tag, FPR_BYTES) == 0) return 1;
    if (ADV_PREFIX_BITS > 0){
        int bytes = ADV_PREFIX_BITS / 8;
        int rem   = ADV_PREFIX_BITS % 8;
        if (bytes > 0 && memcmp(a->tag, b->tag, (size_t)bytes) == 0){
            if (rem == 0) return 1;
            uint8_t ma = a->tag[bytes] >> (8 - rem);
            uint8_t mb = b->tag[bytes] >> (8 - rem);
            if (ma == mb) return 1;
        } else if (bytes == 0 && rem > 0){
            uint8_t ma = a->tag[0] >> (8 - rem);
            uint8_t mb = b->tag[0] >> (8 - rem);
            if (ma == mb) return 1;
        }
    }
    if (a->scope_id == b->scope_id &&
        a->scope_lsb8 == b->scope_lsb8 &&
        (a->nonce_bits > b->nonce_bits ? (a->nonce_bits - b->nonce_bits) : (b->nonce_bits - a->nonce_bits)) <= 1){
        return 1;
    }
    return 0;
}

/* ---------- Statistinės pagalbinės funkcijos ---------- */
static int cmp_tags(const void* a, const void* b){ return memcmp(a, b, FPR_BYTES); }

static uint64_t count_equal_pairs_sorted(const uint8_t* sorted_tags, int n){
    uint64_t pairs = 0;
    int i = 0;
    while(i < n){
        int j = i + 1;
        while(j < n && memcmp(sorted_tags + (size_t)j*FPR_BYTES, sorted_tags + (size_t)i*FPR_BYTES, FPR_BYTES)==0) ++j;
        int r = j - i;
        if (r > 1) pairs += (uint64_t)r * (uint64_t)(r - 1) / 2ull;
        i = j;
    }
    return pairs;
}

static double theory_link_prob(int V){
    double b = 8.0 * (double)FPR_BYTES;
    double denom = ldexp(1.0, (int)b); /* 2^b kaip double */
    double pairs = ((double)V * (double)(V - 1)) / 2.0;
    double p = 1.0 - exp(-pairs / denom);
    return p;
}

/* ---------- Eksperimentai ---------- */

/* (A) Empirinė „kolizijų-panaši“ diagnostika (praleidžiama, jei FPR_BYTES >= 16) */
static int run_collision_diag(secp256k1_context* ctx, const scenario_t* s, int aggregated,
                              double* out_rate, uint64_t* out_n_pairs){
    if (FPR_BYTES >= 16) { *out_rate = -1.0; *out_n_pairs = 0; return 0; }
    uint8_t scope32[32]; make_scope_bytes(aggregated ? "AGG" : "SEP", s, scope32);

    uint8_t* tags = (uint8_t*)malloc((size_t)TRIALS_PER_SCENARIO * FPR_BYTES);
    if(!tags){ *out_rate = 0.0; *out_n_pairs = 0; return 0; }

    for(int i=0;i<TRIALS_PER_SCENARIO;++i){
        uint8_t x[32];
        if(!sample_link_secret(ctx, x)){ free(tags); return 0; }
        if(!bbs_scope_tag(ctx, x, scope32, tags + (size_t)i * FPR_BYTES)){ free(tags); return 0; }
    }
    qsort(tags, (size_t)TRIALS_PER_SCENARIO, FPR_BYTES, cmp_tags);
    uint64_t dup_pairs = count_equal_pairs_sorted(tags, TRIALS_PER_SCENARIO);
    free(tags);
    uint64_t n_pairs = (uint64_t)TRIALS_PER_SCENARIO * (uint64_t)(TRIALS_PER_SCENARIO - 1) / 2ull;
    *out_rate = (n_pairs ? (double)dup_pairs / (double)n_pairs : 0.0);
    *out_n_pairs = n_pairs;
    return 1;
}

/* (B) Koalicijos susiejimo tikimybė: V turėtojų, ta pati „scope“ (nepriklausomi turėtojai) */
static double empirical_coalition_link_prob(secp256k1_context* ctx,
                                            const scenario_t* s, int aggregated, int V){
    uint8_t scope32[32]; make_scope_bytes(aggregated ? "AGG" : "SEP", s, scope32);

    uint8_t (*buf)[FPR_BYTES] = (uint8_t (*)[FPR_BYTES])malloc((size_t)V * FPR_BYTES);
    if(!buf) return 0.0;
    uint64_t linked = 0;

    for(int r=0;r<COALITION_ROUNDS;++r){
        for(int i=0;i<V;++i){
            uint8_t x[32];
            if(!sample_link_secret(ctx, x)){ free(buf); return 0.0; }
            if(!bbs_scope_tag(ctx, x, scope32, buf[i])){ free(buf); return 0.0; }
        }
        qsort(buf, (size_t)V, FPR_BYTES, cmp_tags);
        int any = 0;
        for(int i=1;i<V;++i){
            if(memcmp(buf[i-1], buf[i], FPR_BYTES)==0){ any=1; break; }
        }
        if(any) ++linked;
    }
    free(buf);
    return (double)linked / (double)COALITION_ROUNDS;
}

/* (C) To paties įrodančiojo nesusiejamumo testas */
typedef struct {
    double fp_hat;
    double tp_hat;
    int    pairs_fp;
    int    pairs_tp;
} sameprov_stats_t;

static sameprov_stats_t empirical_same_prover_stats(secp256k1_context* ctx,
                                                    const scenario_t* s, int aggregated){
    xs128p_t st = xs128p_seed(0x13579BDF2468ACE0ull + (uint64_t)s->combo,
                              aggregated ? 0xCAFEBABEDEADBEEFull : 0xFEEDFACE01234567ull);

    transcript_t T[SAMEPROVER_V];
    uint8_t x_same[32];
    sample_link_secret(ctx, x_same);

    for(int i=0;i<SAMEPROVER_V;++i){
        uint8_t nb = (uint8_t)(4 + (prng_u32(&st)%7)); /* 4..10 bitų, ne paslapčiai (tik simuliacijos parametras) */
        make_transcript(ctx, s, aggregated, x_same, nb, &T[i]);
    }
    int tp_num=0, tp_den=0;
    for(int i=0;i<SAMEPROVER_V;++i){
        for(int j=i+1;j<SAMEPROVER_V;++j){
            ++tp_den;
            if (link_test_transcript(&T[i], &T[j])) ++tp_num;
        }
    }

    int fp_num=0, fp_den=0;
    for(int i=0;i<SAMEPROVER_V;++i){
        uint8_t x_other[32];
        sample_link_secret(ctx, x_other);
        transcript_t U;
        uint8_t nb = (uint8_t)(4 + (prng_u32(&st)%7));
        make_transcript(ctx, s, aggregated, x_other, nb, &U);
        ++fp_den;
        if (link_test_transcript(&T[i], &U)) ++fp_num;
    }

    sameprov_stats_t r = {0};
    r.tp_hat = (tp_den ? (double)tp_num / (double)tp_den : 0.0);
    r.fp_hat = (fp_den ? (double)fp_num / (double)fp_den : 0.0);
    r.pairs_tp = tp_den;
    r.pairs_fp = fp_den;
    return r;
}

/* ---------- Vienodumo testas (kibiruojami žemiausi 8 bitai), MC p reikšmė ---------- */
typedef struct { double chi2; double p_mc; } unif_result_t;

static unif_result_t uniformity_test_mc(secp256k1_context* ctx, const scenario_t* s){
    xs128p_t st = xs128p_seed(0x5566778899AABBCCull + (uint64_t)s->combo, 0x1122334455667788ull);
    int countsA[256]={0}, countsS[256]={0};

    uint8_t scopeA[32], scopeS[32];
    make_scope_bytes("AGG", s, scopeA);
    make_scope_bytes("SEP", s, scopeS);

    for(int i=0;i<UNIF_SAMPLES;++i){
        uint8_t x[32], t[FPR_BYTES];
        sample_link_secret(ctx, x);
        bbs_scope_tag(ctx, x, scopeA, t);
        countsA[t[0]]++;

        sample_link_secret(ctx, x);
        bbs_scope_tag(ctx, x, scopeS, t);
        countsS[t[0]]++;
    }

    double chi2 = 0.0;
    for(int b=0;b<256;++b){
        double a = (double)countsA[b];
        double sA = a;
        double sB = (double)countsS[b];
        double e = (sA + sB) / 2.0;
        if (e > 0.0){
            double da = sA - e;
            double db = sB - e;
            chi2 += (da*da)/e + (db*db)/e;
        }
    }

    int totA = 0, totS = 0;
    for(int b=0;b<256;++b){ totA += countsA[b]; totS += countsS[b]; }
    int total = totA + totS;
    double ge = 0.0;

    for(int it=0; it<PERM_ITERS; ++it){
        double chi2p = 0.0;
        for(int b=0;b<256;++b){
            int m = countsA[b] + countsS[b];
            double p = (double)totA / (double)total;
            int k = 0;
            for(int t=0;t<m;++t){ if ((prng_u32(&st) % 1000000) < (int)(p*1000000.0)) ++k; }
            double e = m / 2.0;
            if (e > 0.0){
                double da = k - e;
                double db = (m - k) - e;
                chi2p += (da*da)/e + (db*db)/e;
            }
        }
        if (chi2p >= chi2) ge += 1.0;
    }

    unif_result_t ur;
    ur.chi2 = chi2;
    ur.p_mc = (PERM_ITERS>0) ? (ge / (double)PERM_ITERS) : 1.0;
    return ur;
}

/* ---------- Porinis permutacijų testas AGG vs SEP ---------- */
typedef struct {
    int combo, r1,h1,r2,h2,k_eq;
    double S_real;
    double p_perm;
    double p_holm;
    double q_bh;
} aggsep_stat_t;

typedef struct {
    aggsep_stat_t* a;
    int n, cap;
} vec_stats_t;

static void vec_stats_init(vec_stats_t* v){ v->a=NULL; v->n=0; v->cap=0; }
static void vec_stats_push(vec_stats_t* v, const aggsep_stat_t* x){
    if(v->n==v->cap){ v->cap = v->cap? (v->cap*2):64; v->a=(aggsep_stat_t*)realloc(v->a, (size_t)v->cap*sizeof(*v->a)); }
    v->a[v->n++] = *x;
}

static double permutation_pvalue_on_rounds(uint8_t* agg_ind, uint8_t* sep_ind, int rounds){
    int sumA=0,sumS=0;
    for(int i=0;i<rounds;++i){ sumA+=agg_ind[i]; sumS+=sep_ind[i]; }
    double S_real = (double)sumA/(double)rounds - (double)sumS/(double)rounds;

    xs128p_t st = xs128p_seed(0xFADE1234ABCDEF09ull, 0x0101010101010101ull);
    double ge=0.0;
    for(int it=0; it<PERM_ITERS; ++it){
        int sumAp=0,sumSp=0;
        for(int i=0;i<rounds;++i){
            if (prng_u32(&st) & 1u){
                sumAp += sep_ind[i];
                sumSp += agg_ind[i];
            } else {
                sumAp += agg_ind[i];
                sumSp += sep_ind[i];
            }
        }
        double S = (double)sumAp/(double)rounds - (double)sumSp/(double)rounds;
        if (fabs(S) >= fabs(S_real)) ge += 1.0;
    }
    return (PERM_ITERS>0) ? (ge/(double)PERM_ITERS) : 1.0;
}

/* ---------- Progreso rodymo pagalbinės funkcijos ---------- */
static void print_progress(uint64_t done, uint64_t total, int force){
    static int last_pct = -1;
    if(total == 0) return;
    int pct = (int)((done * 10000ULL) / (total)); /* procento šimtųjų dalių skaičius */
    if(force || pct != last_pct){
        last_pct = pct;
        fprintf(stderr, "\rProgress: %3d.%02d%%  (%llu / %llu)    ",
                pct/100, pct%100,
                (unsigned long long)done, (unsigned long long)total);
        fflush(stderr);
    }
}

static uint64_t count_total_units(void){
    uint64_t total = 0;
    for(int r1=N_ATTR; r1>=0; --r1){
        for(int r2=N_ATTR; r2>=0; --r2){
            int kmin = (r1 + r2 - N_ATTR > 0) ? (r1 + r2 - N_ATTR) : 0;
            int kmax = (r1 < r2) ? r1 : r2;
            int seen[(N_ATTR+1)*(N_ATTR+1)];
            memset(seen, 0, sizeof(seen));
            for(int k=kmin; k<=kmax; ++k){
                for(int mrev=0; mrev<=k; ++mrev){
                    for(int mhid=0; mhid<= (N_ATTR - k); ++mhid){
                        int idx = mrev*(N_ATTR+1) + mhid;
                        if(seen[idx]) continue; seen[idx]=1;
                        total += 1;
                    }
                }
            }
        }
    }
    return total;
}

/* ---------- Išvesties failai ir p reikšmių korekcijos ---------- */
typedef struct {
    FILE* unlink_csv;
    FILE* coal_csv;
    FILE* same_csv;
    FILE* test_csv;
} outputs_t;

static void write_headers(outputs_t* out){
    fprintf(out->unlink_csv,
        "combo,r1,h1,r2,h2,k_eq,trials,emp_coll_agg,emp_coll_sep,n_pairs,rule_of_three_upper,"
        "unif_chi2,unif_pmc\n");
    fprintf(out->coal_csv,
        "combo,r1,h1,r2,h2,k_eq,coalition_V,rounds,emp_link_agg,emp_link_sep,theory_link\n");
    fprintf(out->same_csv,
        "combo,r1,h1,r2,h2,k_eq,label,TP_hat,TP_pairs,FP_hat,FP_pairs\n");
    fprintf(out->test_csv,
        "combo,r1,h1,r2,h2,k_eq,S_real,p_perm,p_holm,q_bh\n");
}

/* Holm korekcija (daugkartinių hipotezių testavimui) */
static void holm_adjust(double* p, int n, double* out){
    int* idx = (int*)malloc((size_t)n*sizeof(int));
    for(int i=0;i<n;++i) idx[i]=i;
    for(int i=0;i<n;++i){
        int m=i;
        for(int j=i+1;j<n;++j) if(p[idx[j]]<p[idx[m]]) m=j;
        int t=idx[i]; idx[i]=idx[m]; idx[m]=t;
    }
    double prev=0.0;
    for(int k=0;k<n;++k){
        int i = idx[k];
        double adj = (double)(n-k) * p[i];
        if (adj<prev) adj=prev;
        if (adj>1.0) adj=1.0;
        out[i]=adj; prev=adj;
    }
    free(idx);
}

/* Benjamini–Hochberg (BH) korekcija (q reikšmėms) */
static void bh_adjust(double* p, int n, double* out){
    int* idx = (int*)malloc((size_t)n*sizeof(int));
    for(int i=0;i<n;++i) idx[i]=i;
    for(int i=0;i<n;++i){
        int m=i;
        for(int j=i+1;j<n;++j) if(p[idx[j]]<p[idx[m]]) m=j;
        int t=idx[i]; idx[i]=idx[m]; idx[m]=t;
    }
    double prev=1e9;
    for(int k=n-1;k>=0;--k){
        int i = idx[k];
        double adj = (double)n/(double)(k+1) * p[i];
        if (adj>1.0) adj=1.0;
        if (adj>prev) adj=prev;
        out[i]=adj; prev=adj;
    }
    free(idx);
}

/* ---------- Pagrindinė programa ---------- */
int main(void){
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if(!ctx){ fprintf(stderr, "secp256k1 context init failed\n"); return 1; }

    outputs_t out = {0};
    out.unlink_csv = fopen("unlinkability_compare.csv","w");
    out.coal_csv   = fopen("coalition_compare.csv","w");
    out.same_csv   = fopen("sameprover_compare.csv","w");
    out.test_csv   = fopen("agg_sep_test.csv","w");
    if(!out.unlink_csv || !out.coal_csv || !out.same_csv || !out.test_csv){
        fprintf(stderr, "cannot open CSV outputs\n");
        if(out.unlink_csv) fclose(out.unlink_csv);
        if(out.coal_csv) fclose(out.coal_csv);
        if(out.same_csv) fclose(out.same_csv);
        if(out.test_csv) fclose(out.test_csv);
        secp256k1_context_destroy(ctx);
        return 2;
    }
    write_headers(&out);

    vec_stats_t Vstats; vec_stats_init(&Vstats);

    const uint64_t TOTAL = count_total_units();
    uint64_t done = 0;
    print_progress(done, TOTAL, 1);

    int combo=0;
    for(int r1=N_ATTR; r1>=0; --r1){
        int h1 = N_ATTR - r1;
        for(int r2=N_ATTR; r2>=0; --r2){
            int h2 = N_ATTR - r2;

            int kmin = (r1 + r2 - N_ATTR > 0) ? (r1 + r2 - N_ATTR) : 0;
            int kmax = (r1 < r2) ? r1 : r2;

            ++combo;
            int seen[(N_ATTR+1)*(N_ATTR+1)];
            memset(seen, 0, sizeof(seen));

            for(int k=kmin; k<=kmax; ++k){
                for(int mrev=0; mrev<=k; ++mrev){
                    for(int mhid=0; mhid<= (N_ATTR - k); ++mhid){
                        int idx = mrev*(N_ATTR+1) + mhid;
                        if(seen[idx]) continue; seen[idx]=1;

                        scenario_t s = { combo, r1, h1, r2, h2, mhid };

                        double emp_coll_agg= -1.0, emp_coll_sep= -1.0;
                        uint64_t n_pairs = 0;
                        int ran = run_collision_diag(ctx, &s, 1, &emp_coll_agg, &n_pairs);
                        (void)ran;
                        run_collision_diag(ctx, &s, 0, &emp_coll_sep, &n_pairs);

                        double rule3 = (n_pairs ? 3.0 / (double)n_pairs : -1.0);
                        unif_result_t ur = uniformity_test_mc(ctx, &s);

                        fprintf(out.unlink_csv,
                            "%d,%d,%d,%d,%d,%d,%d,%.12g,%.12g,%llu,%.12g,%.12g,%.12g\n",
                            combo, r1, h1, r2, h2, s.k_eq, TRIALS_PER_SCENARIO,
                            emp_coll_agg, emp_coll_sep,
                            (unsigned long long)n_pairs,
                            rule3,
                            ur.chi2, ur.p_mc
                        );

                        for(int ci=0; ci<NUM_COALITIONS; ++ci){
                            int V = COALITION_SIZES[ci];
                            double emp_link_agg = empirical_coalition_link_prob(ctx, &s, 1, V);
                            double emp_link_sep = empirical_coalition_link_prob(ctx, &s, 0, V);
                            double th_link      = theory_link_prob(V);
                            fprintf(out.coal_csv,
                                "%d,%d,%d,%d,%d,%d,%d,%d,%.12g,%.12g,%.12g\n",
                                combo, r1, h1, r2, h2, s.k_eq, V, COALITION_ROUNDS,
                                emp_link_agg, emp_link_sep, th_link);
                        }

                        sameprov_stats_t SA = empirical_same_prover_stats(ctx, &s, 1);
                        sameprov_stats_t SS = empirical_same_prover_stats(ctx, &s, 0);
                        fprintf(out.same_csv,
                            "%d,%d,%d,%d,%d,%d,AGG,%.12g,%d,%.12g,%d\n",
                            combo, r1, h1, r2, h2, s.k_eq, SA.tp_hat, SA.pairs_tp, SA.fp_hat, SA.pairs_fp);
                        fprintf(out.same_csv,
                            "%d,%d,%d,%d,%d,%d,SEP,%.12g,%d,%.12g,%d\n",
                            combo, r1, h1, r2, h2, s.k_eq, SS.tp_hat, SS.pairs_tp, SS.fp_hat, SS.pairs_fp);

                        /* AGG/SEP susiejimo palyginimas per porinį permutacijų testą (V=16) */
                        {
                            int V=16;
                            uint8_t scopeA[32], scopeS[32];
                            make_scope_bytes("AGG", &s, scopeA);
                            make_scope_bytes("SEP", &s, scopeS);

                            uint8_t (*buf)[FPR_BYTES] = (uint8_t (*)[FPR_BYTES])malloc((size_t)V * FPR_BYTES);
                            if(!buf){ fprintf(stderr,"\nOOM\n"); goto done; }
                            uint8_t *indA = (uint8_t*)malloc((size_t)COALITION_ROUNDS);
                            uint8_t *indS = (uint8_t*)malloc((size_t)COALITION_ROUNDS);
                            if(!indA || !indS){ free(buf); fprintf(stderr,"\nOOM\n"); goto done; }

                            for(int r=0;r<COALITION_ROUNDS;++r){
                                for(int i=0;i<V;++i){
                                    uint8_t x[32];
                                    sample_link_secret(ctx, x);
                                    bbs_scope_tag(ctx, x, scopeA, buf[i]);
                                }
                                qsort(buf, (size_t)V, FPR_BYTES, cmp_tags);
                                int any=0; for(int i=1;i<V;++i){ if(!memcmp(buf[i-1],buf[i],FPR_BYTES)){ any=1;break; } }
                                indA[r]=(uint8_t)any;

                                for(int i=0;i<V;++i){
                                    uint8_t x[32];
                                    sample_link_secret(ctx, x);
                                    bbs_scope_tag(ctx, x, scopeS, buf[i]);
                                }
                                qsort(buf, (size_t)V, FPR_BYTES, cmp_tags);
                                any=0; for(int i=1;i<V;++i){ if(!memcmp(buf[i-1],buf[i],FPR_BYTES)){ any=1;break; } }
                                indS[r]=(uint8_t)any;
                            }
                            double p_perm = permutation_pvalue_on_rounds(indA, indS, COALITION_ROUNDS);
                            int sumA=0,sumS=0; for(int r=0;r<COALITION_ROUNDS;++r){ sumA+=indA[r]; sumS+=indS[r]; }
                            double S_real = (double)sumA/(double)COALITION_ROUNDS - (double)sumS/(double)COALITION_ROUNDS;

                            aggsep_stat_t rec;
                            rec.combo=combo; rec.r1=r1; rec.h1=h1; rec.r2=r2; rec.h2=h2; rec.k_eq=s.k_eq;
                            rec.S_real=S_real; rec.p_perm=p_perm; rec.p_holm=rec.q_bh=0.0;
                            vec_stats_push(&Vstats, &rec);

                            free(indA); free(indS); free(buf);
                        }

                        ++done;
                        print_progress(done, TOTAL, 0);
                    }
                }
            }
        }
    }

done:
    if (Vstats.n > 0){
        double* p = (double*)malloc((size_t)Vstats.n*sizeof(double));
        double* ph=(double*)malloc((size_t)Vstats.n*sizeof(double));
        double* qb=(double*)malloc((size_t)Vstats.n*sizeof(double));
        if(p && ph && qb){
            for(int i=0;i<Vstats.n;++i) p[i]=Vstats.a[i].p_perm;
            holm_adjust(p, Vstats.n, ph);
            bh_adjust(p, Vstats.n, qb);
            for(int i=0;i<Vstats.n;++i){ Vstats.a[i].p_holm=ph[i]; Vstats.a[i].q_bh=qb[i]; }
        }
        if(p) free(p); if(ph) free(ph); if(qb) free(qb);

        for(int i=0;i<Vstats.n;++i){
            const aggsep_stat_t* r = &Vstats.a[i];
            fprintf(out.test_csv, "%d,%d,%d,%d,%d,%d,%.12g,%.12g,%.12g,%.12g\n",
                r->combo, r->r1, r->h1, r->r2, r->h2, r->k_eq, r->S_real, r->p_perm, r->p_holm, r->q_bh);
        }
    }

    if(out.unlink_csv) fclose(out.unlink_csv);
    if(out.coal_csv) fclose(out.coal_csv);
    if(out.same_csv) fclose(out.same_csv);
    if(out.test_csv) fclose(out.test_csv);
    if(Vstats.a) free(Vstats.a);
    secp256k1_context_destroy(ctx);

    print_progress(TOTAL, TOTAL, 1);
    fprintf(stderr, "\nDone. Wrote unlinkability_compare.csv, coalition_compare.csv, sameprover_compare.csv, agg_sep_test.csv\n");
    return 0;
}
