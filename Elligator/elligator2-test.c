#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <stdint.h>
#include "elligator2.h"
#include <sys/time.h>


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

float get_ms_diff(struct timeval *start, struct timeval *end)
{
    return (1000.0*(end->tv_sec - start->tv_sec)) + ((float)(end->tv_usec - start->tv_usec)) / 1000.0;
}


#define NUM_TRIALS (10000)

int main()
{
    unsigned char base_point[32] = {9};     // G

    // ================
    // Station specific
    // ================
    unsigned char station_secret[32];   // d
    unsigned char station_public[32];   // P = dG

    //get_rand_str(station_secret, sizeof(station_secret));
    RAND_bytes(station_secret, sizeof(station_secret));
    station_secret[0] &= 248;
    station_secret[31] &= 127;
    station_secret[31] |= 64;

    // compute P = dG
    curve25519_donna(station_public, station_secret, base_point);





    // ================
    // Point muls
    // ================
    struct timeval start, end;
    FILE *f = fopen("./points", "w");
    gettimeofday(&start, NULL);
    int i;
    for (i=0; i<NUM_TRIALS; i++ ) {
        unsigned char out[32];
        unsigned char secret[32];
        RAND_bytes(secret, 32);
        curve25519_donna(out, secret, base_point);

        if (fwrite(out, 32, 1, f) != 1) {
            printf("Fail\n");
            return -1;
        }

    }
    fclose(f);
    gettimeofday(&end, NULL);


    float diff = get_ms_diff(&start, &end);
    printf("Point multiplied %d points in %.3f ms (%.3f ms/pmul; %d pmul/sec)\n",
           NUM_TRIALS, diff, diff/((float)NUM_TRIALS), (int)(((float)(1000.0*NUM_TRIALS))/diff) );
    fflush(stdout);




    f = fopen("./client-points.out", "w");
    FILE *f2 = fopen("./client-secrest.out", "w");
    struct timeval client_start, client_end;
    gettimeofday(&client_start, NULL);
    for (i=0; i<NUM_TRIALS; i++) {
        // ================
        // Client specific
        // ================
        unsigned char client_secret[32];        // e
        unsigned char client_public[32];        // Q = eG
        unsigned char client_public_encoded[32];// ElligatorEncode(Q)
        unsigned char client_shared_point[32]; // S = eP = dQ
        int r = 0;

        do {
            //get_rand_str(client_secret, sizeof(client_secret));
            RAND_bytes(client_secret, 32);
            client_secret[0] &= 248;
            client_secret[31] &= 127;
            client_secret[31] |= 64;

            // compute Q = eG
            curve25519_donna(client_public, client_secret, base_point);

            // Encode my_public (Q) using elligator
            r = encode(client_public_encoded, client_public);

        } while (r == 0);

        // Randomize 255th and 254th bits
        char rand_bit;
        //get_rand_str(&rand_bit, 1);
        RAND_bytes(&rand_bit, 1);
        rand_bit &= 0xc0;
        client_public_encoded[31] |= rand_bit;



        // Generate client's shared secret for this secret S = eP
        curve25519_donna(client_shared_point, client_secret, station_public);

        if (r=fwrite(client_public_encoded, 32, 1, f) != 1) {
            printf("#%d fwrite client public encoded returned %d\n", i, r);
            perror("fwrite");
            return -1;
        }

        if (r=fwrite(client_shared_point, 32, 1, f2) != 1) {
            printf("#%d fwrite client shared returned %d\n", i, r);
            perror("fwrite2");
            return -1;
        }
    }
    fclose(f);
    fclose(f2);

    gettimeofday(&client_end, NULL);

    diff = get_ms_diff(&client_start, &client_end);
    printf("Client encoded %d points in %.3f ms (%.3f ms/encoding; %d encodings/sec)\n",
           NUM_TRIALS, diff, diff/((float)NUM_TRIALS), (int)(((float)(1000.0*NUM_TRIALS))/diff) );
    fflush(stdout);


    /*
    printf("client public point: ");
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
    */

    f = fopen("./client-points.out", "r");
    f2 = fopen("./station-secrets.out", "w");

    struct timeval station_start, station_end;
    gettimeofday(&station_start, NULL);
    for (i=0; i<NUM_TRIALS; i++) {
        // ================
        // Station specific
        // ================
        //printf("\n----------\n\n");

        unsigned char client_public_encoded[32];
        int r;
        if (r=fread(client_public_encoded, 32, 1, f) != 1) {
            printf("fread client public encoded returned %d\n", r);
            perror("fread");
            return -1;
        }

        // Decode
        unsigned char station_client_public[32];        // Q = ElligatorDeocde( ElligatoreEncode( Q ) )
        unsigned char station_shared_point[32]; // S = dQ = eP
        client_public_encoded[31] &= ~(0xc0);

        decode(station_client_public, client_public_encoded);
        //memcpy(station_client_public, client_public_encoded, 32);


        // Get shared secret
        curve25519_donna(station_shared_point, station_secret, station_client_public);

        if (r=fwrite(station_shared_point, 32, 1, f2) != 1) {
            printf("fwrite station shared returned %d\n", r);
            perror("fwrite");
            return -1;
        }
    }
    fclose(f);
    fclose(f2);

    gettimeofday(&station_end, NULL);

    diff = get_ms_diff(&station_start, &station_end);
    printf("Station decoded %d points in %.3f ms (%.3f ms/decoding; %d decodings/sec)\n",
           NUM_TRIALS, diff, diff/((float)NUM_TRIALS), (int)(((float)(1000*NUM_TRIALS))/diff) );



    // ==============
    // Client tags...
    // ==============
    struct timeval tag_start, tag_end;
    int r;
    f = fopen("./client-tags.out", "w");
    gettimeofday(&tag_start, NULL);
    for (i=0; i<NUM_TRIALS; i++) {

        // Client specific, generate tags
        unsigned char payload[144];
        unsigned char tag[200];
        RAND_bytes(payload, 144);
        strcpy(payload, "SPTELEX");
        get_tag_from_payload(payload, 144, station_public, tag);

        if ((r=fwrite(tag, 176, 1, f)) != 1) {
            printf("fwrite problem: %d\n", r);
            return -1;
        }
    }
    fclose(f);
    gettimeofday(&tag_end, NULL);

    diff = get_ms_diff(&tag_start, &tag_end);
    printf("Client created %d tags %.3f ms (%.3f ms/tag; %d tags/sec)\n",
           NUM_TRIALS, diff, diff/((float)NUM_TRIALS), (int)(((float)(1000*NUM_TRIALS))/diff) );





    // ==============
    // Station decrypt
    // ==============
    f = fopen("./client-tags.out", "r");
    gettimeofday(&tag_start, NULL);
    for (i=0; i<NUM_TRIALS; i++) {
        unsigned char tag[176];
        unsigned char payload[144];

        if ((r=fread(tag, 176, 1, f)) != 1) {
            printf("fread problem: %d\n", r);
            return -1;
        }

        get_payload_from_tag(station_secret, tag, payload, sizeof(payload));
        if (memcmp(payload, "SPTELEX", 7) != 0) {
            printf("Uh oh! Tag %d problem:\n", i);
            int j;
            for (j=0; j<144; j++) {
                printf("%02x", payload[j]);
            }
        }
    }
    fclose(f);
    gettimeofday(&tag_end, NULL);


    diff = get_ms_diff(&tag_start, &tag_end);
    printf("Station read %d tags %.3f ms (%.3f ms/tag; %d tags/sec)\n",
           NUM_TRIALS, diff, diff/((float)NUM_TRIALS), (int)(((float)(1000*NUM_TRIALS))/diff) );

    return 0;

    /*
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
    */

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


