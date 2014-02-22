#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include "elligator2.h"

int main(){
    
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
    /*
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
    */
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
}


