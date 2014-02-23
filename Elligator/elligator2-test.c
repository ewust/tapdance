#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <stdint.h>
#include "elligator2.h"


// TODO: make curve25519-donna.h
typedef uint8_t u8;
typedef int32_t s32;
typedef int64_t limb;

int curve25519_donna(u8 *, const u8 *, const u8 *);

size_t get_rand_str(unsigned char *randout, size_t len)
{
    FILE *f = fopen("/dev/urandom", "r");
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

    get_rand_str(station_secret, sizeof(station_secret));
    station_secret[0] &= 248;
    station_secret[31] &= 127;
    station_secret[31] |= 64;

    // compute P = dG
    curve25519_donna(station_public, station_secret, base_point);


    // ================
    // Client specific
    // ================
    unsigned char client_secret[32];        // e
    unsigned char client_public[32];        // Q = eG
    unsigned char client_public_encoded[32];// ElligatorEncode(Q)
    unsigned char client_shared_point[32]; // S = eP = dQ
    int r = 0;

    do {
        get_rand_str(client_secret, sizeof(client_secret));
        client_secret[0] &= 248;
        client_secret[31] &= 127;
        client_secret[31] |= 64;

        // compute Q = eG
        curve25519_donna(client_public, client_secret, base_point);

        // Encode my_public (Q) using elligator
        r = encode(client_public_encoded, client_public);

    } while (r == 0);

    // Generate client's shared secret for this secret S = eP
    curve25519_donna(client_shared_point, client_secret, station_public);

    printf("client public point: ");
    int i;
    for (i=0; i<sizeof(client_public); i++) {
        printf("%02x", client_public[i]);
    }
    printf("\n");

    // Send my_public_encoded...
    printf("Encoded as: ");
    for (i=0; i<sizeof(client_public_encoded); i++) {
        printf("%02x", client_public_encoded[i]);
    }
    printf("\n");

    printf("Shared secret: ");
    for (i=0; i<sizeof(client_shared_point); i++) {
        printf("%02x", client_shared_point[i]);
    }
    printf("\n");



    // ================
    // Station specific
    // ================
    printf("\n----------\n\n");

    // Decode
    unsigned char station_client_public[32];        // Q = ElligatorDeocde( ElligatoreEncode( Q ) )
    unsigned char station_shared_point[32]; // S = dQ = eP
    decode(station_client_public, client_public_encoded);


    // Get shared secret
    curve25519_donna(station_shared_point, station_secret, station_client_public);

    printf("Station got public point: ");
    for (i=0; i<sizeof(station_client_public); i++) {
        printf("%02x", station_client_public[i]);
    }
    printf("\n");

    printf("Station shared secret: ");
    for (i=0; i<sizeof(station_shared_point); i++) {
        printf("%02x", station_shared_point[i]);
    }
    printf("\n");

    printf("\n----------\n\n");
    if (memcmp(station_shared_point, client_shared_point, sizeof(client_shared_point)) == 0) {
        printf("Success!!\n");
    } else {
        printf("Mismatch...?\n");
    }


    return 0;
}


#if 0

    unsigned char test_string[32]; memset(test_string,0,32);
    unsigned char test[32]; memset(test,0,32);

    // Test input point
    // If already in proper form:
    unsigned char curve_point[32]={0x25,  0xe5,  0xd3,  0x6d,  0xab,  0xe9,  0xb5,  0xf0,  0xc9,
        0xbb,  0x68,  0x5e,  0x7b,  0x87,  0xec,  0xdc,  0xb9,  0x41,  0xd2,  0x67,  0x94,  0xf6,
        0x66,  0x3c,  0xcd,  0xb8,  0x67,  0xaf,  0xeb,  0x55,  0x63,  0x20
    };

    mpz_t test_xcoord;
    mpz_init(test_xcoord);
    mpz_t test_ycoord;
    mpz_init(test_ycoord);

    int sign_bit = 0;

    // Otherwise:
    //*************
    // Comment out following if using curve_point defined above:
    mpz_set_str(test_xcoord,"206355ebaf67b8cd3c66f69467d241b9dcec877b5e68bbc9f0b5e9ab6dd3e525",16);
    size_t out_len;
    mpz_export(curve_point, &out_len, -1, 1, -1, 0, test_xcoord);

    // Change most significant bit to be sign of y_coord
    if(sign_bit==1){
        curve_point[31] |= 0x80; // puts 1 for negative sign
    }
    else{
        curve_point[31] &= 0x7f; // puts 0 for positive sign
    }
    //*************

    // Import point to gmp
    unsigned char curve_point_copy[32];
    memcpy(curve_point_copy, curve_point, 32);

    // Get sign bit
    sign_bit = (curve_point_copy[31] & 0x80) == 0x80;

    // Mask out high-order bit
    // Extract x coordinate
    curve_point_copy[31] &= 0x7f;
    mpz_import(test_xcoord,32,-1,1,-1,0, curve_point_copy);
    
    // Tests whether x value corresponds to point on curve or not
    // Prints corresponding y value if yes. Takes canonical square root.
    printf("Testing if x values corresponds to point on curve and calculating y ... \n");
    calc_y(test_ycoord, test_xcoord);
    gmp_printf("Main: x coordinate is %Zd \n", test_xcoord);
    
    if(calc_y(test_ycoord, test_xcoord)==1){
        
        if (sign_bit ==1){
            mpz_neg(test_ycoord, test_ycoord);
        }
                       
        gmp_printf("Main: y coordinate is %Zd \n", test_ycoord);
    
    }
    else gmp_printf("Warning! No such point on curve (main function) \n");
    
    // Test encode function
    printf("Encoding point as string now ... \n");
    encode(test_string, curve_point);
    
    // Writes string to screen;
    printf("Point encoded as uniform-looking string is:\n");
    int count;
    for(count=0; count < 32;++count){
        gmp_printf(" %x ", test_string[count]);
        
    }
    printf(" \n");
    
    
    // Test decode function
    printf ("Testing decode function now ....\n");
    decode(test, test_string);
    
    // Writes string to screen;
    printf("Represent output of Decode in little endian 32-byte char:");
    
    for(count=0; count < 32;++count){
        gmp_printf(" 0x%x, ", test[count]);
        
    }
    printf(" \n");
    
    // Test to get point back
    // Get sign bit
    int has_sign = (test[31] & 0x80) == 0x80;
    printf("Main: Sign bit of y is %i \n", has_sign);
    
    // Mask out high-order bit
    // Extract x coordinate
    test[31] &= 0x7f;
    mpz_import(test_xcoord,32,-1,1,-1,0, test);
    gmp_printf ("Main: Decode says x coordinate is %Zd \n", test_xcoord);
    
    // Calculate y coordinate
    calc_y(test_ycoord, test_xcoord);
    if( has_sign == 1){
        mpz_neg(test_ycoord, test_ycoord);
    }
    
    gmp_printf ("Main: Corresponding y value is %Zd \n", test_ycoord);
    
    
    mpz_clear(test_xcoord);
    mpz_clear(test_ycoord);
    
    return 0;
#endif


