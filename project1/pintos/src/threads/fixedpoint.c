/* Fixed Point Arithmetic */
/* 17.14 fixed-point number representation */

/* Fixed Point Arithmetic */
/* 17.14 fixed-point number representation */

#include "threads/fixedpoint.h"
#include <stdio.h>

/* Returns the fixed-point representation
   of the given integer input. */
int
i_to_f (int i)
{
  return i * CONVERTING_FACTOR;
}

/* Returns the integer value of the given fixed-point input.
   Rounding is toward zero.  */
int
f_to_i_rounding_toward_zero (int f)
{
  return f / CONVERTING_FACTOR;
}

/* Returns the integer value of the given fixed-point input.
   Rounding is toward the nearest integer. */
int
f_to_i_rounding_toward_nearest (int f)
{
  if (f >= 0)
    return (f + CONVERTING_FACTOR / 2) / CONVERTING_FACTOR;
  else
    return (f - CONVERTING_FACTOR / 2) / CONVERTING_FACTOR;
}

/* Returns the result of summation (f1+f2).
   Add two fixed-point inputs f1 and f2.
   The result is represented as fixed-point. */
int
add_ff (int f1, int f2)
{
  return f1 + f2;
}

/* Returns the result of summation (f+i).
   Add fixed-point input f and integer i.
   The result is represented as fixed-point. */
int
add_fi (int f, int i)
{
  return f + (i * CONVERTING_FACTOR);
}

/* Returns the result of subtraction (f1-f2).
   Subtract fixed-point input f2 from f1.
   The result is represented as fixed-point. */
int
subtract_ff (int f1, int f2)
{
  return f1 - f2;
}

/* Returns the result of subtraction (f-i).
   Subract integer i from fixed-point f1
   The result is represented as fixed-point. */
int
subtract_fi (int f, int i)
{
  return f - (i * CONVERTING_FACTOR);
}

/* Returns the result of multiplication (f1*f2).
   Multiply two fixed-point inputs f1 by f2.
   The result is represented as fixed-point. */
int
mul_ff (int f1, int f2)
{
  return ((int64_t) f1) * f2 / CONVERTING_FACTOR;
}

/* Returns the result of multiplication (f*i).
   Multiply fixed-point input f by integer i.
   The result is represented as fixed-point. */
int
mul_fi (int f, int i)
{
  return f * i;
}

/* Returns the result of division (f1/f2)
   Divide two fixed-point inputs f1 by f2.
   The result is represented as fixed-point. */
int
div_ff (int f1, int f2)
{
  return ((int64_t) f1) * CONVERTING_FACTOR / f2;
}

/* Returns the result of division (f/i)
   Divide fixed-point input f by integer i.
   The result is represented as fixed-point. */
int
div_fi (int f, int i)
{
  return f / i;
}

