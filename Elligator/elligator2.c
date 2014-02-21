//
//  elligator2.c
//  
//
//  Created by CrazyMac on 2/17/14.
//
//

#include <stdio.h>
#include <gmp.h>
#include "elligator2.h"
void square_root(mpz_t root, const mpz_t square);
int calc_y(mpz_t y_coord, const mpz_t x_coord);
int is_encodable(const mpz_t);

// To Do
// Fix Encode so that API does not rely on gmp
// Fix Decode so that out is a 32-byte encoding of x-coord and sign bit of y-coord
// Need to link in curve25519 and test interoperability with inputs/outputs; other code for DH?
// Clean up code ....
// Some tests

int main(){
    
    unsigned char test_string[32];
    static unsigned char test[32] = {
    };
    
    // Test square root function
    mpz_t test_square;
    mpz_init(test_square);
    mpz_set_si(test_square,-4752188672138712967);
    
    mpz_t test_root;
    mpz_init(test_root);
    
   // square_root(test_root,test_square);
    //gmp_printf("test square value is %Zd \n", test_square);
    //gmp_printf("test root value is %Zd \n", test_root);
    
    // Test input point
    // x value
    mpz_t test_xcoord;
    mpz_init(test_xcoord);
    mpz_set_str(test_xcoord,"4a0a21fd87cd5386a1091f0fb9e482f9ce3ddcee704d3d5223e08f9d252a7a4a",16);
    
    // y value (sign suffices for montgomery curves)
    mpz_t test_sign_bit;
    mpz_init(test_sign_bit);
    mpz_set_si(test_sign_bit,-1);
    
    mpz_t test_ycoord;
    mpz_init(test_ycoord);
    
    // Tests whether x value corresponds to point on curve or not
    // Prints corresponding y value if yes. Takes canonical square root.
    calc_y(test_ycoord, test_xcoord);
    gmp_printf("Main: test xcoord value is %Zd \n", test_xcoord);
    
    if(calc_y(test_ycoord, test_xcoord)==1){
        
        gmp_printf("Main: test_ycoord value is %Zd \n", test_ycoord);
    
    }
    else gmp_printf("Warning! No such point on curve (main function) \n");
    
    // Test encode function
    encode(test_string, test_xcoord, test_sign_bit);
    
    // Writes string to screen;
    printf("Point encoded as string is ");
    int count;
    for(count=0; count < 32;++count){
        gmp_printf(" %x ", test_string[count]);
        
    }
    printf(" \n ");
    
    
    // Test decode function
    
    decode(test, test_string);

    
    mpz_clear(test_sign_bit);
    mpz_clear(test_root);
    mpz_clear(test_square);
    mpz_clear(test_xcoord);
    mpz_clear(test_ycoord);
    
    return 0;
}


// TO DO: need to also export sign of y.
// Decode function
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
    gmp_printf("Decode says point corresponds to r = %Zd in F_p \n", field_element_r);
    
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
    }
    
    else{
        mpz_set(x_coord, vee);
        mpz_neg(x_coord, x_coord);
        mpz_sub(x_coord, x_coord, coeff_A); // x = -v - A
    }
    
    // Not actually necessary to do this calculation
    calc_y(y_coord, x_coord);
    
    // Negate y_coord if needed
    mpz_mul_si(y_coord, y_coord, -chi);
    
    gmp_printf ("Decode says x_coord is %Zd \n", x_coord);
    gmp_printf ("Decode says y_coord is %Zd \n", y_coord);
    
    // Export x_coord as 32-byte string
    size_t out_len; //gmp_printf("out_len is %d \n ", out_len);
    mpz_export(out, &out_len, -1, 1, -1, 0, x_coord);
    
    // Export sign bit of y-coord....?
    
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
int encode(unsigned char *out, const mpz_t in, const mpz_t in_sign_bit){
    
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
    
    if(is_encodable(in)==1){
        gmp_printf("Encode says x-coord is encodable! \n ");
        
        if(mpz_cmp_si(in_sign_bit,1)==0){
            
            //gmp_printf(" canonical y \n ");
            
            mpz_set(r_hat_squared, in); // r_hat is x
            mpz_add(r_hat_squared, r_hat_squared, coeff_A); //r_hat is x+A
            mpz_mul(r_hat_squared, r_hat_squared, non_square_u); //r_hat is 2(x+A)
            mpz_invert(r_hat_squared,r_hat_squared, curve_prime); //r_hat is inverse of 2(x+A)
            mpz_mul(r_hat_squared, r_hat_squared, in); //r_hat is x/(2(x+A))
            mpz_mod(r_hat_squared, r_hat_squared, curve_prime); // reduce
            mpz_neg(r_hat_squared, r_hat_squared); // negate
            // gmp_printf("r_hat squared should be %Zd \n", r_hat_squared);
            square_root(r_hat, r_hat_squared); // calculate final r_hat
            gmp_printf("Encode says point corresponds to r_hat = %Zd in F_p \n", r_hat);
            
        }
        
        else if(mpz_cmp_si(in_sign_bit,-1)==0){
            
            //gmp_printf(" not canonical y \n ");
            
            mpz_set(r_hat_squared, in); // r_hat is x
            mpz_mul(r_hat_squared, r_hat_squared, non_square_u); // 2*x
            mpz_invert(r_hat_squared,r_hat_squared, curve_prime); //r_hat_squared is inverse of 2*x
            
            mpz_add(temp, in, coeff_A); // temp is x+A
            mpz_neg(temp,temp); // temp is -(x+A)
            
            mpz_mul(r_hat_squared, r_hat_squared, temp); //r_hat is -(x+A)/(2x)
            mpz_mod(r_hat_squared, r_hat_squared, curve_prime); // reduce
            
            // gmp_printf("r_hat squared should be %Zd \n", r_hat_squared);
            square_root(r_hat, r_hat_squared); // calculate final r_hat
            gmp_printf("Encode says point corresponds to r_hat = %Zd in F_p \n", r_hat);
            
            
        }
        
        else {
            gmp_printf( "Warning: not correct sign bit?");
            result = 0; // bad sign bit?
        }
        
        size_t out_len; //gmp_printf("out_len is %d \n ", out_len);
        mpz_export(out, &out_len, -1, 1, -1, 0, r_hat);
        result = 1;
        
        
    }
    else{
        gmp_printf ("Encode says x-coord is not encodable \n ");
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
