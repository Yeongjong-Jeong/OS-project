/* Fixed Point Arithmetic */
/* 17.14 fixed-point number representation */

#ifndef FIXEDPOINT_H
#define FIXEDPOINT_H

#define CONVERTING_FACTOR (1<<14)

int i_to_f (int);
int f_to_i_rounding_toward_zero (int);
int f_to_i_rounding_toward_nearest (int);
int add_ff (int, int);
int add_fi (int, int);
int subtract_ff (int, int);
int subtract_fi (int, int);
int mul_ff (int, int);
int mul_fi (int, int);
int div_ff (int, int);
int div_fi (int, int);

#endif /* threads/fixedpoint.h */
