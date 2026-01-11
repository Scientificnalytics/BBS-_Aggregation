// bbs_sharp_verify_benchmark.c — patikros laiko matavimai su Issuer PoK 
// Du VC (po 5 atributus), skirtingi leidėjai.
// Atskirai: (2 + k) iššūkiai, k lygybių patikros, + 2 leidėjo PoK verifikacijos
// Agreguota: 1 iššūkis, 1 bendra lygybės patikra (jei k > 0), + 2 leidėjo PoK verifikacijos
//
// Kompiliavimas (MSYS2 + libsecp256k1 realioms EC operacijoms):
//   gcc -O3 -Wall -Wextra -o verify_bench.exe bbs_sharp_verify_benchmark.c -lsecp256k1

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

/* --- Parametrai (turi sutapti su generavimo modeliu) -- */

#define GE_BYTES                 33
#define SCALAR_BYTES             32

#define CHALLENGE_BYTES          32
#define HOLDER_SIG_BYTES         64

/* Fiksuoti baitai (dėl pilnumo; laiko matavimams nenaudojama) */
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

/* Iššūkių skaičius */
#define CHALLENGE_COUNT_AGGREGATED   1
static inline int challenge_count_separate(int k_eq) { return 2 + k_eq; }

/* Scenarijaus parametrai */
#define N_ATTR   5
#define REPEATS  100

/* imituoti hash veiksmų kainą */
#define INCLUDE_HASH_COST  1

/* ---------------- Issuer PoK verifikacijos kainos modelis ----------------
   Imituojame EC daugiklių (EC scalar mult) skaičių.
   - Viena Issuer PoK verifikacija ≈ POK_VERIFY_EC_MULTS daugiklių.
   - Du leidėjai → 2 * POK_VERIFY_EC_MULTS.
   - Neprivaloma: POK_VERIFY_BATCH_SAVING (0 pagal nutylėjimą).
*/
#define INCLUDE_ISSUER_POK_VERIFY   1
#define POK_VERIFY_EC_MULTS         12
#define POK_VERIFY_BATCH_SAVING     0

/* ---------------- Laiko matavimo funkcija ---------------- */
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

/* ---------------- Maža “hash apkrova” imituojanti iššūkio darbą ---------------- */
static void hash_burn(int count) {
#if INCLUDE_HASH_COST
    volatile uint64_t s = 0x9e3779b97f4a7c15ull;
    for (int i = 0; i < count * 20000; ++i) {
        // Paprastas XOR ir shift – tik CPU apkrovai
        s ^= (s << 7) ^ (s >> 3) ^ (uint64_t)i;
    }
    (void)s;
#else
    (void)count;
#endif
}

/* ---------------- Tikros EC operacijos per libsecp256k1 ---------------- */
#ifndef NO_SECP256K1
static secp256k1_context *g_ctx = NULL;
#endif

/* Deterministinis skalaro ciklas EC daugiklių generacijai */
static void do_gen_mults(int count, uint64_t seed) {
#ifndef NO_SECP256K1
    for (int i = 0; i < count; ++i) {
        uint8_t sk[32];

        // Pseudo-deterministinis skaliaro generavimas
        uint64_t x = seed + (uint64_t)i * 0x9e3779b97f4a7c15ull;
        for (int j = 0; j < 32; j += 8) {
            memcpy(sk + j, &x, 8);
            x ^= (x << 13) ^ (x >> 7) ^ (x << 17);
        }
        sk[0] |= 1; // užtikrinti, kad skaliaras ≠ 0

        secp256k1_pubkey pub;
        (void)secp256k1_ec_pubkey_create(g_ctx, &pub, sk); // EC mult
    }
#else
    // Jei secp256k1 nėra – darome pseudo-CPU apkrovą
    volatile uint64_t s = seed;
    for (int i = 0; i < count * 20000; ++i) {
        s = (s * 11400714819323198485ull) ^ (uint64_t)i;
    }
    (void)s;
#endif
}

/* ---------------- Scenarijaus struktūra ---------------- */
typedef struct {
    int combo;
    int r1,h1,r2,h2;
    int total_reveal,total_hidden;
    int m_rev,m_hid;
    int k_eq;  // paslėptų lygybių kiekis, reikalaujantis ZK patikros
} scenario_t;

/* CSV antraštės */
static void headers(FILE* va, FILE* vs, FILE* vc) {
    fprintf(va, "combo,k_eq,ns_verify_mean\n");
    fprintf(vs, "combo,k_eq,ns_verify_mean\n");
    fprintf(vc, "combo,k_eq,ns_agg,ns_sep,ns_delta_abs\n");
}

/* EC daugiklių skaičius agreguotai Issuer PoK patikrai */
static inline int issuer_pok_verify_mults_aggregated(void) {
#if INCLUDE_ISSUER_POK_VERIFY
    int base = 2 * POK_VERIFY_EC_MULTS;
    int save = POK_VERIFY_BATCH_SAVING;
    if (save > base) save = base;
    return base - save;
#else
    return 0;
#endif
}

/* EC daugiklių skaičius atskirai Issuer PoK patikrai */
static inline int issuer_pok_verify_mults_separate(void) {
#if INCLUDE_ISSUER_POK_VERIFY
    return 2 * POK_VERIFY_EC_MULTS;
#else
    return 0;
#endif
}

/* ---------------- Agreguotos patikros laiko matavimas ---------------- */
static uint64_t verify_ns_aggregated(const scenario_t* s) {
    // Tik 1 iššūkis
    hash_burn(CHALLENGE_COUNT_AGGREGATED);

    // EC darbas: 2 issuer PoK, +1 equality jei k>0
    int mults = issuer_pok_verify_mults_aggregated();
    if (s->k_eq > 0) mults += 1;

    uint64_t t0 = now_ns();
    for (int r = 0; r < REPEATS; ++r)
        do_gen_mults(mults, 0xA1B2C3D4ull + (uint64_t)s->combo + r);
    uint64_t t1 = now_ns();
    return (t1 - t0) / REPEATS;
}

/* ---------------- Atskirtos patikros laiko matavimas ---------------- */
static uint64_t verify_ns_separate(const scenario_t* s) {
    // (2 + k) iššūkiai
    hash_burn(challenge_count_separate(s->k_eq));

    // EC darbas: 2 issuer PoK + k equality tikrinimų
    int mults = issuer_pok_verify_mults_separate() + s->k_eq;

    uint64_t t0 = now_ns();
    for (int r = 0; r < REPEATS; ++r)
        do_gen_mults(mults, 0x5A6B7C8Dull + (uint64_t)s->combo + r);
    uint64_t t1 = now_ns();
    return (t1 - t0) / REPEATS;
}

int main(void) {
#ifndef NO_SECP256K1
    // Sukuriame secp256k1 kontekstą
    g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!g_ctx) {
        fprintf(stderr, "secp256k1 context init failed\n");
        return 1;
    }
#endif

    IGNORE_UNUSED();

    // Atidarome CSV failus
    FILE* f_va = fopen("verify_aggregated.csv", "w");
    FILE* f_vs = fopen("verify_separate.csv", "w");
    FILE* f_vc = fopen("verify_compare.csv", "w");
    if (!f_va || !f_vs || !f_vc) {
        fprintf(stderr, "cannot open CSVs\n");
        return 2;
    }

    headers(f_va, f_vs, f_vc);

    int combo = 0;

    // Generuojame visus scenarijus (atributų atskleidimo kombinacijas)
    for (int r1 = N_ATTR; r1 >= 0; --r1) {
        int h1 = N_ATTR - r1;
        for (int r2 = N_ATTR; r2 >= 0; --r2) {
            int h2 = N_ATTR - r2;
            int tr = r1 + r2, th = h1 + h2;

            // Lygybių verifikacijos ribos
            int kmin = (r1 + r2 - N_ATTR > 0) ? (r1 + r2 - N_ATTR) : 0;
            int kmax = (r1 < r2) ? r1 : r2;

            ++combo;
            int seen[(N_ATTR+1)*(N_ATTR+1)];
            memset(seen, 0, sizeof(seen));

            for (int k = kmin; k <= kmax; ++k) {
                for (int mrev = 0; mrev <= k; ++mrev) {
                    for (int mhid = 0; mhid <= (N_ATTR - k); ++mhid) {

                        int idx = mrev * (N_ATTR+1) + mhid;
                        if (seen[idx]) continue;
                        seen[idx] = 1;

                        scenario_t s = {
                            combo, r1, h1, r2, h2,
                            tr, th,
                            mrev, mhid,
                            mhid
                        };

                        uint64_t ns_agg = verify_ns_aggregated(&s);
                        uint64_t ns_sep = verify_ns_separate(&s);
                        uint64_t delta  = (ns_agg > ns_sep ? ns_agg - ns_sep : ns_sep - ns_agg);

                        fprintf(f_va, "%d,%d,%" PRIu64 "\n", s.combo, s.k_eq, ns_agg);
                        fprintf(f_vs, "%d,%d,%" PRIu64 "\n", s.combo, s.k_eq, ns_sep);
                        fprintf(f_vc, "%d,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
                                s.combo, s.k_eq, ns_agg, ns_sep, delta);
                    }
                }
            }
        }
    }

    fclose(f_va);
    fclose(f_vs);
    fclose(f_vc);

#ifndef NO_SECP256K1
    secp256k1_context_destroy(g_ctx);
#endif

    fprintf(stderr, "Baigta. Failai verify_*.csv sugeneruoti.\n");
    return 0;
}
