/* ed25519_hacl_cli.c — a thin CLI over the *vendored HACL\* Ed25519* that kroopt
 * links (the same primitive `Kroopt.Crypto.RealProvider` calls for CertificateVerify).
 * Used by scripts/ed25519-interop.sh to cross-check HACL signatures against OpenSSL.
 *
 *   pub    <seedHex>                 -> prints public key hex
 *   sign   <seedHex> <msgFile>       -> prints signature hex over the file bytes
 *   verify <pubHex>  <msgFile> <sigHex> -> exit 0 and print "OK" if valid, else exit 1
 *
 * Not part of the library build; a developer/interop tool only.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "Hacl_Ed25519.h"

static int hex2bin(const char *h, uint8_t *out, size_t outlen) {
  if (strlen(h) != outlen * 2) return -1;
  for (size_t i = 0; i < outlen; i++) {
    unsigned v; if (sscanf(h + 2*i, "%2x", &v) != 1) return -1; out[i] = (uint8_t)v;
  }
  return 0;
}
static void printhex(const uint8_t *b, size_t n) {
  for (size_t i = 0; i < n; i++) printf("%02x", b[i]); printf("\n");
}
static uint8_t *readfile(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb"); if (!f) return NULL;
  fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
  uint8_t *buf = malloc(n > 0 ? (size_t)n : 1);
  *len = fread(buf, 1, (size_t)n, f); fclose(f); return buf;
}

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: pub|sign|verify ...\n"); return 2; }

  if (!strcmp(argv[1], "pub") && argc == 3) {
    uint8_t seed[32], pub[32];
    if (hex2bin(argv[2], seed, 32)) { fprintf(stderr, "bad seed\n"); return 2; }
    Hacl_Ed25519_secret_to_public(pub, seed); printhex(pub, 32); return 0;
  }
  if (!strcmp(argv[1], "sign") && argc == 4) {
    uint8_t seed[32]; if (hex2bin(argv[2], seed, 32)) { fprintf(stderr, "bad seed\n"); return 2; }
    size_t mlen; uint8_t *msg = readfile(argv[3], &mlen); if (!msg) { fprintf(stderr, "no msg\n"); return 2; }
    uint8_t sig[64]; Hacl_Ed25519_sign(sig, seed, (uint32_t)mlen, msg); printhex(sig, 64);
    free(msg); return 0;
  }
  if (!strcmp(argv[1], "verify") && argc == 5) {
    uint8_t pub[32], sig[64];
    if (hex2bin(argv[2], pub, 32) || hex2bin(argv[4], sig, 64)) { fprintf(stderr, "bad hex\n"); return 2; }
    size_t mlen; uint8_t *msg = readfile(argv[3], &mlen); if (!msg) { fprintf(stderr, "no msg\n"); return 2; }
    bool ok = Hacl_Ed25519_verify(pub, (uint32_t)mlen, msg, sig); free(msg);
    printf(ok ? "OK\n" : "FAIL\n"); return ok ? 0 : 1;
  }
  fprintf(stderr, "usage: pub <seed> | sign <seed> <file> | verify <pub> <file> <sig>\n");
  return 2;
}
