#include <stdio.h>
#include "elligator2.h"
#include <gmp.h>
#include <stdint.h>

// TODO: make curve25519-donna.h
typedef uint8_t u8;
typedef int32_t s32;
typedef int64_t limb;

int curve25519_donna(u8 *, const u8 *, const u8 *);

size_t get_rand_str(unsigned char *randout, size_t len)
{
    FILE *f = fopen("/dev/random", "r");
    if (!f) {
        return 0;
    }
    size_t r = fread(randout, 1, len, f);
    fclose(f);
    return r;
}

int main()
{
    unsigned char base_point[32] = {9};     // G

    // ================
    // Station specific
    // ================
    unsigned char station_secret[32];   // d
    unsigned char station_public[32];   // P = dG

    printf("Reading from /dev/random...\n");
    get_rand_str(station_secret, sizeof(station_secret));
    printf("done, Generating point...\n");
    station_secret[0] &= 248;
    station_secret[31] &= 127;
    station_secret[31] |= 64;

    // compute P = dG
    curve25519_donna(station_public, station_secret, base_point);

    printf("done, writing files...\n");

    FILE *pubf = fopen("pubkey", "w");
    fwrite(station_public, sizeof(station_public), 1, pubf);
    fclose(pubf);

    FILE *secretf = fopen("privkey", "w");
    fwrite(station_secret, sizeof(station_secret), 1, secretf);
    fclose(secretf);

    printf("Wrote files pubkey and privkey\n");

}


