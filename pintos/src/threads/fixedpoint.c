/* Fixed Point Arithmetic */
/* 17.14 fixed-point number representation */

/* Fixed Point Arithmetic */
/* 17.14 fixed-point number representation */

#include "threads/fixedpoint.h"
#include <stdio.h>

int
i_to_f (int i)
{
  return i * CONVERTING_FACTOR;
}

int
f_to_i_rounding_toward_zero (int f)
{
  return f / CONVERTING_FACTOR;
}

int
f_to_i_rounding_toward_nearest (int f)
{
  if (f >= 0)
    return (f + CONVERTING_FACTOR / 2) / CONVERTING_FACTOR;
  else
    return (f - CONVERTING_FACTOR / 2) / CONVERTING_FACTOR;
}

int
add_ff (int f1, int f2)
{
  return f1 + f2;
}

int
add_fi (int f, int i)
{
  return f + (i * CONVERTING_FACTOR);
}

int
subtract_ff (int f1, int f2)
{
  return f1 - f2;
}

int
subtract_fi (int f, int i)
{
  return f - (i * CONVERTING_FACTOR);
}

int
mul_ff (int f1, int f2)
{
  return ((int64_t) f1) * f2 / CONVERTING_FACTOR;
}

int
mul_fi (int f, int i)
{
  return f * i;
}

int
div_ff (int f1, int f2)
{
  return ((int64_t) f1) * CONVERTING_FACTOR / f2;
}

int
div_fi (int f, int i)
{
  return f / i;
}

