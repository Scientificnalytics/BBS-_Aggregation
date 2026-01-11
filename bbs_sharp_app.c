/* bbs_sharp_app.c  BBS# puslapiavimo imitacija (HSIM-saugi, Idemix stiliaus)
   - CLA 0x70
   - INS 0x30 → SIG puslapiai (case-2)
   - INS 0x44 → ATTR puslapiai (case-2)
   - Puslapio dydis = 60 baitų; hostas nustato Le ≤ 0x3C; OS nukerpa paskutinį puslapį
   - Failo pabaiga: idx >= page_count → multosExitLa(0)

   P2 selektorius (minimalus ir beveik be šakų):
     bit7 (0x80) išdėstymas : 0 = agreguotas, 1 = atskirtas
     bit6 (0x40) profilis   : 1 = maksimalus atskleidimas, 0 = minimalus atskleidimas
     bitai 2..0      k      : 0..5 (ignoruojama, kai profile=Max)

   Puslapių skaičius skaičiuojamas per mažas lenteles, kad būtų išvengta sudėtingo šakėjimosi.
*/

#pragma attribute("aid",  "f0 00 00 02")
#pragma attribute("name", "bbs_sharp")

#include <multos.h>

/* ===== CLA/INS ir SW ===== */
#define MYAPP_CLA       0x70
#define INS_SIG_PAGE    0x30
#define INS_ATTR_PAGE   0x44

#define ERR_WRONGCLASS  0x6402
#define ERR_BAD_INS     0x6404

/* ===== 60 baitų puslapio atvaizdavimas (identiškas Idemix programėlei) ===== */
typedef struct {
  char surname[20];
  char otherNames[40];
} APDU_ID; /* 60 baitų */

#pragma melpublic
union {
  APDU_ID id;          /* PB[0] atvaizdavimas */
} apdu_data;
#pragma melstatic

/* ===== Netikri ROM puslapiai (turinys nesvarbus; svarbi tik 60 B kopija) ===== */
#pragma melconst
static const APDU_ID SIG_PAGES_MAX[16] = {
  {{0},{0}},{{0},{0}},{{0},{0}},{{0},{0}},
  {{0},{0}},{{0},{0}},{{0},{0}},{{0},{0}},
  {{0},{0}},{{0},{0}},{{0},{0}},{{0},{0}},
  {{0},{0}},{{0},{0}},{{0},{0}},{{0},{0}}
};

#pragma melconst
static const APDU_ID ATTR_PAGES_MAX[6] = {
  {{0},{0}},{{0},{0}},{{0},{0}},{{0},{0}},{{0},{0}},{{0},{0}}
};

/* ===== ceil(baitai/60) su mažomis literalinėmis reikšmėmis ===== */
static unsigned short ceil_div60(unsigned short b) {
  return (b == 0u) ? 0u : (unsigned short)((b + 59u) / 60u);
}

/* ===== Fiksuoto dydžio siuntimas (identiškas Idemix imitacijai) ===== */
static void send_page_or_eof(const APDU_ID *table, unsigned short count, unsigned short idx)
{
  if (idx >= count) {
    multosExitLa(0);                      /* Failo pabaiga: 0 baitų + 9000 */
  } else {
    apdu_data.id = table[idx];            /* ROM → PB[0] */
    multosExitLa((WORD)sizeof(APDU_ID));  /* 60; hosto Le nukerpa paskutinį */
  }
}

/* === Puslapių skaičiaus paėmimas iš lentelių (be didelio šakėjimosi) ===
   Baitų modelis (santrauka):
   Agreguotas:
     SIG  = 678 B → 12 puslapių
     ATTR (Max) = 320 B → 6 puslapių
     ATTR (Min) = 0 jei k=0, kitaip 33 + 32*k → puslapiai {0,2,2,3,3,3} kai k=0..5
   Atskiras:
     SIG  = 774 + 32*k → puslapiai {13,13,14,14,15,16} kai k=0..5
     ATTR (Max) = 320 B → 6 puslapių
     ATTR (Min) = 65*k → puslapiai {0,2,3,4,5,6} kai k=0..5
*/

static unsigned short get_sig_pages(unsigned char layout, unsigned char profile, unsigned char k)
{
  (void)profile; /* SIG mūsų modelyje nepriklauso nuo profilio */
  if (layout == 0) {
    /* Agreguotas: visada 678 B → 12 puslapių */
    return (unsigned short)12u;
  } else {
    /* Atskiras: 774 + 32*k */
    static const unsigned char sig_sep_pages[6] = { 13, 13, 14, 14, 15, 16 };
    if (k > 5) k = 5;
    return (unsigned short)sig_sep_pages[k];
  }
}

static unsigned short get_attr_pages(unsigned char layout, unsigned char profile, unsigned char k)
{
  if (profile) {
    /* Maksimalus atskleidimas: 320 B → 6 puslapių */
    return (unsigned short)6u;
  }

  /* Minimalus atskleidimas: priklauso nuo išdėstymo ir k */
  if (k > 5) k = 5;

  if (layout == 0) {
    /* Agreguotas Min: 0 jei k=0, kitaip (33 + 32*k) */
    static const unsigned char attr_agg_min_pages[6] = { 0, 2, 2, 3, 3, 3 };
    return (unsigned short)attr_agg_min_pages[k];
  } else {
    /* Atskiras Min: 65*k */
    static const unsigned char attr_sep_min_pages[6] = { 0, 2, 3, 4, 5, 6 };
    return (unsigned short)attr_sep_min_pages[k];
  }
}

/* =====main ======= */
void main(void)
{
  unsigned short idx;

  if (CLA != MYAPP_CLA)
    multosExitSW(ERR_WRONGCLASS);

  switch (INS)
  {
    case INS_SIG_PAGE:
    {
      if (!multosCheckCase(2)) multosExitSW(ERR_WRONGCLASS);
      idx = (unsigned short)P1;

      /* P2 dekodavimas minimaliai (case viduje, po case tipo patikrinimo) */
      {
        unsigned char layout  = (unsigned char)((P2 & 0x80) ? 1 : 0);
        unsigned char profile = (unsigned char)((P2 & 0x40) ? 1 : 0);
        unsigned char k       = (unsigned char)(P2 & 0x07); /* 0..5 */

        unsigned short sig_pages = get_sig_pages(layout, profile, k);
        send_page_or_eof(SIG_PAGES_MAX, sig_pages, idx);
      }
      break;
    }

    case INS_ATTR_PAGE:
    {
      if (!multosCheckCase(2)) multosExitSW(ERR_WRONGCLASS);
      idx = (unsigned short)P1;

      {
        unsigned char layout  = (unsigned char)((P2 & 0x80) ? 1 : 0);
        unsigned char profile = (unsigned char)((P2 & 0x40) ? 1 : 0);
        unsigned char k       = (unsigned char)(P2 & 0x07); /* 0..5 */

        unsigned short attr_pages = get_attr_pages(layout, profile, k);
        send_page_or_eof(ATTR_PAGES_MAX, attr_pages, idx);
      }
      break;
    }

    default:
      multosExitSW(ERR_BAD_INS);
  }
}
