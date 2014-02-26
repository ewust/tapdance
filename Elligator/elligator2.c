//
//  elligator2.c
//  
//
//  Created by CrazyMac on 2/17/14.
//
//

#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include "elligator2.h"
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

void square_root(mpz_t root, const mpz_t square);
int calc_y(mpz_t y_coord, const mpz_t x_coord);
int is_encodable(const mpz_t);

// To Do
// other code for DH?
// Clean up code ....
// Some tests

//typedef uint8_t u8;
typedef unsigned char u8;
typedef int32_t s32;
typedef int64_t limb;

int curve25519_donna(u8 *, const u8 *, const u8 *);

// Client calls this to get a random shared secret and public point,
// given the station's public key.
void get_encoded_point_and_secret(unsigned char *station_public,
                                  unsigned char *shared_secret_out,
                                  unsigned char *encoded_point_out)
{

    // First, generate an ECC point
    unsigned char base_point[32] = {9};
    unsigned char client_secret[32];        // e
    unsigned char client_public[32];        // Q = eG
    int r = 0;

    do {
        //memset(encoded_point_out, 0, 32);
        //get_rand_str(client_secret, sizeof(client_secret));
        RAND_bytes(client_secret, sizeof(client_secret));
        client_secret[0] &= 248;
        client_secret[31] &= 127;
        client_secret[31] |= 64;

        // compute Q = eG
        curve25519_donna(client_public, client_secret, base_point);

        // Encode my_public (Q) using elligator
        r = encode(encoded_point_out, client_public);

    } while (r == 0);

    // Randomize 255th and 254th bits
    unsigned char rand_bit;
    RAND_bytes(&rand_bit, 1);
    //LogDebug("encoder", "rand byte: %02x", rand_bit);
    //HexDump(LOG_DEBUG, "encoder", "encoded_point_out", encoded_point_out, 32);
    rand_bit &= 0xc0;
    encoded_point_out[31] |= rand_bit;

    curve25519_donna(shared_secret_out, client_secret, station_public);

    //HexDump(LOG_DEBUG, "encoder", "client_public", client_public, 32);
    //HexDump(LOG_DEBUG, "encoder", "client_secret", client_secret, 32);

    memset(client_secret, 0, sizeof(client_secret));
    memset(client_public, 0, sizeof(client_public));

    return;
}

// tag_out length must be at least 32 + payload_len + 15 to be safe
// For the client; given a payload and a station public key, provides
// an output. Currently, tag_out must be >= 176 byte buffer.
size_t get_tag_from_payload(unsigned char *payload, size_t payload_len,
                            unsigned char *station_pubkey,
                            unsigned char *tag_out)
{
    unsigned char shared_secret[32];
    size_t len = 0;

    get_encoded_point_and_secret(station_pubkey, shared_secret, &tag_out[0]);
    len += 32;

    // hash shared_secret to get key/IV
    unsigned char aes_key[SHA256_DIGEST_LENGTH];
    unsigned char *iv_enc = &aes_key[16];   // First 16 bytes are for AES-128, last 16 are for implicit IV

    SHA256_CTX sha256;

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, shared_secret, sizeof(shared_secret));
    SHA256_Final(aes_key, &sha256);

    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, 128, &enc_key);    // First 16 bytes of hash for AES key, last 16 for IV
    AES_cbc_encrypt(payload, &tag_out[sizeof(shared_secret)], payload_len, &enc_key, iv_enc, AES_ENCRYPT);

    len += ((payload_len + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

    return len;
}





// Decode function
// Outputs elliptic curve point as 32 byte little endian; high order bit is sign of y
// Returns 0 if it fails (and string is not in S= {0, ..., (p-1)/2}), else returns 1
int decode(unsigned char *out, const unsigned char *in){
    
    // declare curve_prime as 2^255-19
    mpz_t curve_prime;
    mpz_init(curve_prime);
    mpz_set_str(curve_prime, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",16);
    // gmp_printf("curve prime is %Zd \n", curve_prime);
    
    // declare A
    mpz_t coeff_A;
    mpz_init(coeff_A);
    mpz_set_si(coeff_A, 486662);
    
    // declare non-square u in F_p. Fixed to 2.
    mpz_t non_square_u;
    mpz_init(non_square_u);
    mpz_set_si(non_square_u, 2);
    
    //**************
    int result;
    
    // initialize out to 0
    memset(out,0,32);
    
    // import (p-1)/2.
    mpz_t upper_bound;
    mpz_init(upper_bound);
    mpz_set_str(upper_bound,"3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6",16);
    // gmp_printf("upper bound is %Zd \n", upper_bound);
    
    // import "in" as field element r in mpz_t type
    mpz_t field_element_r;
    mpz_init(field_element_r);
    mpz_import(field_element_r, 32, -1, 1, -1, 0, in);
    
    // check that r values is in {0, ..., (p-1)/2}
    if(mpz_cmp(upper_bound,field_element_r)>=0){
        result = 1;
    }
    else{
        result = 0;
    }

    // Print field element out
    // gmp_printf("\t Decode says point corresponds to r = %Zd in F_p \n", field_element_r);
    
    // Declare variables for computation of curve point
    mpz_t vee;
    mpz_init(vee);
    
    mpz_t epsilon;
    mpz_init(epsilon);
    
    mpz_t x_coord;
    mpz_init(x_coord);
    
    mpz_t y_coord;
    mpz_init(y_coord);
    
    // Compute curve point
    mpz_mul(vee, field_element_r, field_element_r);
    mpz_mod(vee, vee, curve_prime);
    mpz_mul(vee, vee, non_square_u);
    mpz_mod(vee, vee, curve_prime);
    mpz_add_ui(vee, vee, 1);
    mpz_invert(vee, vee, curve_prime);
    mpz_mul(vee, vee, coeff_A);
    mpz_mod(vee, vee, curve_prime);
    mpz_neg(vee, vee); // v = -A/(1+u*r^2)
    
    mpz_mul(epsilon,vee,vee);
    mpz_addmul_ui(epsilon, vee,486662); //gmp_printf("v^2 + Av should be %Zd\n", y_squared);
    mpz_mod(epsilon, epsilon, curve_prime);
    mpz_add_ui(epsilon,epsilon,1); //gmp_printf("x_coord^2 + Ax + 1 should be %Zd\n", y_squared);
    mpz_mod(epsilon, epsilon, curve_prime);
    mpz_mul(epsilon, epsilon, vee); // should now be v^3 + A*v^2 + v
    mpz_mod(epsilon, epsilon, curve_prime);
    
    int chi;
    chi = mpz_legendre(epsilon, curve_prime);
    
    if(chi==1){
        mpz_set(x_coord, vee); // x = v
        mpz_mod(x_coord,x_coord,curve_prime); // make sure x is positive
    }
    
    else{
        mpz_set(x_coord, vee);
        mpz_neg(x_coord, x_coord);
        mpz_sub(x_coord, x_coord, coeff_A); // x = -v - A
        mpz_mod(x_coord,x_coord,curve_prime); // make sure x is positive
    }
    
    /* Test stuff
    // Not actually necessary to do this calculation
    calc_y(y_coord, x_coord);
    
    // Negate y_coord if needed
    mpz_mul_si(y_coord, y_coord, -chi);
    
    gmp_printf ("\t Decode says x_coord is %Zd \n", x_coord);
    gmp_printf ("\t Decode says y_coord is %Zd \n", y_coord);
    */
    
    // Export x_coord as 32-byte string in little endian
    size_t out_len; //gmp_printf("out_len is %d \n ", out_len);
    mpz_export(out, &out_len, -1, 1, -1, 0, x_coord);
    
    /* Test stuff
    printf("\t Represent output of Decode as string: ");
    
    int count;
    for(count=0; count < 32;++count){
        gmp_printf(" %x ", out[count]);
        
    }
    printf(" \n ");
    */
    
    /* Test stuff
    mpz_import(x_coord, 32, -1, 1, -1, 0, out);
    gmp_printf ("\t Decode says x_coord is %Zd \n", x_coord);
    
    gmp_printf( "\t sign of y as an integer is negation of %i \n", chi);
    */
    
    // Change most significant bit to be sign of y_coord
    if(chi==1){
        out[31] |= 0x80; // puts 1 for negative sign
    }
    else{
    
        out[31] &= 0x7f; // puts 0 for positive sign
    }
    
    mpz_clear(x_coord);
    mpz_clear(y_coord);
    mpz_clear(field_element_r);
    mpz_clear(non_square_u);
    mpz_clear(coeff_A);
    mpz_clear(curve_prime);

    return result;
}

// Tests if EC point on curve25519 is encodable
// Returns 1 if yes, 0 if no.
// old: int is_encodable(unsigned char *in){
int is_encodable(const mpz_t x_coord){
    
    //declare curve_prime as 2^255-19
    mpz_t curve_prime;
    mpz_init(curve_prime);
    mpz_set_str(curve_prime, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",16);
    
    //declare A
    mpz_t coeff_A;
    mpz_init(coeff_A);
    mpz_set_si(coeff_A, 486662);
    
    //********
    
    //Compute Legendre symbo (x(x+A)/p)
    mpz_t legendre;
    mpz_init(legendre);
    mpz_set(legendre, x_coord);
    //gmp_printf("legendre now contains %Zd\n", legendre);
    
    mpz_add(legendre, legendre, coeff_A);
    //gmp_printf("legendre now contains %Zd\n", legendre);
    
    mpz_mul(legendre,legendre,x_coord);
    //gmp_printf("legendre now contains %Zd\n", legendre);
    
    // should not need this actually
    //mpz_mul(legendre,legendre,non_square_u);
    //gmp_printf("legendre now contains %Zd\n", legendre);
    
    //gmp_printf("legendre of %Zd is %i \n", legendre, mpz_legendre(legendre, curve_prime));
    
    // Set result to be negation of legendre(x(x+A)/p)
    int result = -1*mpz_legendre(legendre, curve_prime);
    //gmp_printf("encoding calc: return value result contains %i\n", result);
    
    mpz_clear(legendre);
    mpz_clear(curve_prime);
    mpz_clear(coeff_A);
    
    return result;
}
        
// TO DO: fix inputs to not rely on gmp
// Encode function
// Assumes input point is 32 bytes in little endian. High-order bit is sign of y coordinate
int encode(unsigned char *out, const unsigned char *in){
    
    //declare curve_prime as 2^255-19
    mpz_t curve_prime;
    mpz_init(curve_prime);
    mpz_set_str(curve_prime, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",16);
    
    //declare non-square u in F_p. Fixed to 2.
    mpz_t non_square_u;
    mpz_init(non_square_u);
    mpz_set_si(non_square_u, 2);
    
    //declare A
    mpz_t coeff_A;
    mpz_init(coeff_A);
    mpz_set_si(coeff_A, 486662);
    
    //***********
    // initialize out to 0
    memset(out,0,32);
    
    mpz_t x_coord;
    mpz_init(x_coord);
    
    unsigned char in_copy[32];
    memcpy(in_copy, in, 32);
    
    // Import curve point
    // Get sign bit
    int sign_bit = (in[31] & 0x80) == 0x80;
    //printf("Encode: Sign bit of y is %i \n", sign_bit);
    
    // Mask out high-order bit
    // Extract x coordinate
    in_copy[31] &= 0x7f;
    mpz_import(x_coord,32,-1,1,-1,0, in_copy);
    // gmp_printf ("Encode: x coordinate is %Zd \n", x_coord);
    
    // declare r_hat, r_hat_squared
    mpz_t r_hat_squared;
    mpz_init(r_hat_squared);
    mpz_t r_hat;
    mpz_init(r_hat);
    
    // placeholder var
    mpz_t temp;
    mpz_init(temp);
    
    // result int
    int result;
    
    if(is_encodable(x_coord)==1){
        //gmp_printf("\t Encode says x-coord is encodable! \n");
        
        if(sign_bit==0){
            
            //gmp_printf(" canonical y \n ");
            
            mpz_set(r_hat_squared, x_coord); // r_hat is x
            mpz_add(r_hat_squared, r_hat_squared, coeff_A); //r_hat is x+A
            mpz_mul(r_hat_squared, r_hat_squared, non_square_u); //r_hat is 2(x+A)
            mpz_invert(r_hat_squared,r_hat_squared, curve_prime); //r_hat is inverse of 2(x+A)
            mpz_mul(r_hat_squared, r_hat_squared, x_coord); //r_hat is x/(2(x+A))
            mpz_mod(r_hat_squared, r_hat_squared, curve_prime); // reduce
            mpz_neg(r_hat_squared, r_hat_squared); // negate
            // gmp_printf("r_hat squared should be %Zd \n", r_hat_squared);
            square_root(r_hat, r_hat_squared); // calculate final r_hat
            // gmp_printf("\t Encode says point corresponds to r_hat = %Zd in F_p \n", r_hat);
            
        }
        
        else if(sign_bit==1){
            
            //gmp_printf(" not canonical y \n ");
            
            mpz_set(r_hat_squared, x_coord); // r_hat is x
            mpz_mul(r_hat_squared, r_hat_squared, non_square_u); // 2*x
            mpz_invert(r_hat_squared,r_hat_squared, curve_prime); //r_hat_squared is inverse of 2*x
            
            mpz_add(temp, x_coord, coeff_A); // temp is x+A
            mpz_neg(temp,temp); // temp is -(x+A)
            
            mpz_mul(r_hat_squared, r_hat_squared, temp); //r_hat is -(x+A)/(2x)
            mpz_mod(r_hat_squared, r_hat_squared, curve_prime); // reduce
            
            // gmp_printf("r_hat squared should be %Zd \n", r_hat_squared);
            square_root(r_hat, r_hat_squared); // calculate final r_hat
            // gmp_printf("\t Encode says point corresponds to r_hat = %Zd in F_p \n", r_hat);
            
            
        }
        
        else {
            // gmp_printf( "\t Warning: not correct sign bit?\n");
            result = 0; // bad sign bit?
        }
        
        size_t out_len; //gmp_printf("out_len is %d \n ", out_len);
        mpz_export(out, &out_len, -1, 1, -1, 0, r_hat);
        result = 1;
        
        
    }
    else{
        // gmp_printf ("\t Encode says x-coord is not encodable \n");
        result = 0;
        
    }
    
    
    mpz_clear(temp);
    mpz_clear(r_hat_squared);
    mpz_clear(r_hat);
    mpz_clear(non_square_u);

    return result;
    
}


//
// Helper functions
//

// Square root function mod prime p \equiv 5 (mod 8)
// Assumes you feed it an actual square
// Uses algorithm 3.37 from Handbook (Menezes et al.)

void square_root(mpz_t root, const mpz_t square){
    //gmp_printf("input square was %Zd \n", square);
    
    // imports curve_prime 2^255-19
    mpz_t curve_prime;
    mpz_init(curve_prime);
    mpz_set_str(curve_prime, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",16);
    
    // calcs # of residues mod p, (p-1)/2
    // imports (p-1)/2.
    mpz_t number_of_squares;
    mpz_init(number_of_squares);
    mpz_set_str(number_of_squares,"3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6",16);
    
    // imports exponent (p+3)/8
    mpz_t exponent_1;
    mpz_init(exponent_1);
    mpz_set_str(exponent_1,"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",16);
    //gmp_printf("exp1 value is  %Zd \n", exponent_1);
    
    // imports exponent (p-5)/8
    mpz_t exponent_2;
    mpz_init(exponent_2);
    mpz_set_str(exponent_2,"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",16);
    //gmp_printf("exp2 value is  %Zd \n", exponent_2);
    
    // calcs exponent (p-1)/4
    mpz_t exponent_3;
    mpz_init(exponent_3);
    mpz_set_str(exponent_3,"1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb",16);
    //gmp_printf("exp3 value is  %Zd \n", exponent_3);
    
    //*************
    
    // calcs intermediate b value
    mpz_t interm_b;
    mpz_init(interm_b);
    mpz_powm(interm_b, square, exponent_3, curve_prime);
    //gmp_printf("intermb value is  %Zd \n", interm_b);
    
    // gmp_printf("root contains %Zd \n", root);
    
    // calculates square root
    if (mpz_cmp_si(interm_b, 1) ==0){
        //gmp_printf("if condition contains 0 so we are in first branch of sqrt calc \n");
        mpz_powm(root, square, exponent_1, curve_prime);
        //gmp_printf("root contains %Zd \n", root);
    }
    else{
        mpz_mul_ui(root, square, 4);
        //gmp_printf("root contains %Zd \n", root);
        
        mpz_mod(root, root, curve_prime);
        //gmp_printf("root contains %Zd \n", root);
        
        mpz_powm(root, root, exponent_2, curve_prime);
        //gmp_printf("root contains %Zd \n", root);
        
        mpz_mul(root, root, square);
        //gmp_printf("root contains %Zd \n", root);
        
        mpz_mod(root, root, curve_prime);
        //gmp_printf("root contains %Zd \n", root);
        
        mpz_mul_ui(root, root, 2);
        //gmp_printf("root contains %Zd \n", root);
        
        mpz_mod(root, root, curve_prime);
        //gmp_printf("root contains %Zd \n", root);
        
    }
    
    //gmp_printf("if condition contains %i \n", mpz_cmp_si(interm_b, 1));
    //gmp_printf("root contains %Zd \n", root);
    
    // Choose canonical root
    if (mpz_cmp(number_of_squares,root) >= 0){
        //gmp_printf("we do not need to negate the root because %i is >= 0", mpz_cmp(number_of_squares,root));
        
    }
    else{
        //gmp_printf("we need negate the root because %i is < 0", mpz_cmp(number_of_squares,root));
        
        mpz_mul_si(root,root,-1);
        mpz_mod(root,root,curve_prime);
        
        //gmp_printf("new root is %Zd \n", root);
    }
        
    
    mpz_clear(interm_b);
    mpz_clear(exponent_3);
    mpz_clear(exponent_2);
    mpz_clear(exponent_1);
    mpz_clear(number_of_squares);
    mpz_clear(curve_prime);
    
}


// take field element x-coord as input
// returns 0 if x-coord does not correspond to a point on the curve
// outputs the corresponding (canonical) y-coordinate otherwise
int calc_y(mpz_t y_coord, const mpz_t x_coord){
    
    // imports curve_prime 2^255-19
    mpz_t curve_prime;
    mpz_init(curve_prime);
    mpz_set_str(curve_prime, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",16);
    
    //declare A
    mpz_t coeff_A;
    mpz_init(coeff_A);
    mpz_set_si(coeff_A, 486662);
    
    //**********************
    
    int result;
    
    // Compute y^2
    mpz_t y_squared;
    mpz_init(y_squared);
    mpz_set(y_squared, x_coord);
    //gmp_printf("x-coord should be %Zd\n", y_squared);
    
    mpz_mul(y_squared,y_squared,y_squared);
    //gmp_printf("x_coord^2 should be %Zd\n", y_squared);
    
    mpz_addmul(y_squared, x_coord,coeff_A);
    //gmp_printf("x_coord^2 + Ax should be %Zd\n", y_squared);
    
    mpz_add_ui(y_squared,y_squared,1);
    //gmp_printf("x_coord^2 + Ax + 1 should be %Zd\n", y_squared);
    
    mpz_mul(y_squared, y_squared, x_coord); // should now be y^2
    //gmp_printf ("Now %Zd\n is x_coord^3+Ax^2 + x \n", y_squared);
    
    // gmp_printf("Legendre of y_squared is %i \n ", mpz_legendre(y_squared, curve_prime));
    if(mpz_legendre(y_squared, curve_prime)==1){
        
         // compute y
         square_root(y_coord, y_squared);
         //gmp_printf("y_coord contains %Zd \n", y_coord);
        
         result = 1;
    }
    else if (mpz_legendre(y_squared, curve_prime)==-1){
        // not on curve
        // gmp_printf("point not on curve \n ");
        mpz_set_si(y_coord,0);
        result = 0;
        
    }
    else {
        mpz_set_si(y_coord,0);
        result = 1;
    }
    
    mpz_clear(y_squared);
    mpz_clear(curve_prime);
    
    return result;
   
}

