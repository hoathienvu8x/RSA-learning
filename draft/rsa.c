// bignum.h - Header for BigNum library
#ifndef BIGNUM_H
#define BIGNUM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h> // For ULLONG_MAX

// Define the base for our BigNum operations.
// A 32-bit unsigned integer is used as a 'digit'.
// The maximum value for a digit is UINT_MAX.
#define BIGNUM_BASE_BITS 32
#define BIGNUM_BASE_MASK 0xFFFFFFFFUL // 2^32 - 1
#define BIGNUM_BASE_MAX (UINT_MAX) // Max value a single digit can hold

// Define maximum length in terms of digits for a practical limit.
// A larger number of digits will consume more memory.
// For a 2048-bit RSA key, you'd need 2048 / 32 = 64 digits.
#define BIGNUM_MAX_DIGITS 256 // Supports up to 256 * 32 = 8192 bits

// Error codes for BigNum functions
typedef enum {
  BN_OK = 0,
  BN_ERROR_MEMORY_ALLOC = 1,
  BN_ERROR_INVALID_INPUT = 2,
  BN_ERROR_DIV_BY_ZERO = 3,
  BN_ERROR_NEGATIVE_RESULT = 4,
  BN_ERROR_OVERFLOW = 5,
  BN_ERROR_MOD_INVERSE_FAILED = 6,
  BN_ERROR_PRIMALITY_TEST_FAILED = 7,
  BN_ERROR_INVALID_KEY_SIZE = 8
} BigNumErrorCode;

// Structure to represent a Big Number
typedef struct {
  unsigned int* digits; // Array of digits (each digit is a 32-bit unsigned int)
  int size;             // Current number of 'active' digits used
  int capacity;         // Total allocated capacity of the digits array
  int sign;             // 0 for zero, 1 for positive, -1 for negative
} BigNum;

// --- Memory Management ---
BigNum* bn_new();
void bn_free(BigNum* num);
BigNum* bn_copy(const BigNum* src);
BigNumErrorCode bn_resize(BigNum* num, int new_capacity);

// --- Initialization and Assignment ---
BigNumErrorCode bn_set_zero(BigNum* num);
BigNumErrorCode bn_set_one(BigNum* num);
BigNumErrorCode bn_from_ull(BigNum* num, unsigned long long val);
BigNumErrorCode bn_from_string(BigNum* num, const char* str);
char* bn_to_string(const BigNum* num); // Returns dynamically allocated string, must be freed
BigNumErrorCode bn_set(BigNum* dest, const BigNum* src);

// --- Utility Functions ---
void bn_normalize(BigNum* num); // Removes leading zeros, adjusts size
int bn_is_zero(const BigNum* num);
int bn_is_one(const BigNum* num);
int bn_compare(const BigNum* a, const BigNum* b); // -1 if a < b, 0 if a == b, 1 if a > b
int bn_compare_abs(const BigNum* a, const BigNum* b); // Compares absolute values
void bn_print(const char* prefix, const BigNum* num); // For debugging

// --- Arithmetic Operations ---
BigNumErrorCode bn_add(BigNum* result, const BigNum* a, const BigNum* b);
BigNumErrorCode bn_sub(BigNum* result, const BigNum* a, const BigNum* b);
BigNumErrorCode bn_mul(BigNum* result, const BigNum* a, const BigNum* b);
BigNumErrorCode bn_div_mod(BigNum* quotient, BigNum* remainder, const BigNum* a, const BigNum* b);
BigNumErrorCode bn_lshift(BigNum* result, const BigNum* num, int shift_bits); // Bitwise left shift
BigNumErrorCode bn_rshift(BigNum* result, const BigNum* num, int shift_bits); // Bitwise right shift

// --- Modular Arithmetic ---
BigNumErrorCode bn_mod_exp(BigNum* result, const BigNum* base, const BigNum* exp, const BigNum* mod);
BigNumErrorCode bn_gcd(BigNum* result, const BigNum* a, const BigNum* b);
BigNumErrorCode bn_mod_inverse(BigNum* result, const BigNum* a, const BigNum* m);

// --- Random Number Generation ---
BigNumErrorCode bn_rand(BigNum* num, int num_bits);
BigNumErrorCode bn_rand_range(BigNum* num, const BigNum* min, const BigNum* max);

// --- Primality Test (Miller-Rabin) ---
// This function is implemented in rsa.c but depends on BigNum operations
int bn_is_prime(const BigNum* num, int iterations);

#endif // BIGNUM_H

// bignum.c - Implementation of BigNum library
#include "bignum.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> // For srand, rand
#include <ctype.h> // For isdigit

// Helper function to get a random unsigned int
static unsigned int get_rand_digit() {
  // Note: rand() typically produces 15-bit numbers.
  // To get a 32-bit number, combine multiple calls.
  // For cryptographically secure random numbers, a better source is needed.
  return (((unsigned int)rand() << 16) | ((unsigned int)rand()));
}

// Helper: Trim leading zero digits
void bn_normalize(BigNum* num) {
  if (!num || !num->digits) return;

  while (num->size > 1 && num->digits[num->size - 1] == 0) {
    num->size--;
  }
  if (num->size == 1 && num->digits[0] == 0) {
    num->sign = 0; // Number is zero
  } else if (num->digits[num->size - 1] == 0) { // All digits are zero
    num->sign = 0;
    num->size = 1;
    num->digits[0] = 0;
  }
}

// Helper: Allocate and initialize a new BigNum
BigNum* bn_new() {
  BigNum* num = (BigNum*)malloc(sizeof(BigNum));
  if (!num) return NULL;

  num->digits = (unsigned int*)calloc(1, sizeof(unsigned int)); // Start with 1 digit
  if (!num->digits) {
    free(num);
    return NULL;
  }
  num->size = 1;
  num->capacity = 1;
  num->sign = 0; // Represents zero

  return num;
}

// Helper: Free a BigNum structure
void bn_free(BigNum* num) {
  if (num) {
    if (num->digits) {
      free(num->digits);
      num->digits = NULL;
    }
    free(num);
  }
}

// Helper: Copy a BigNum structure
BigNum* bn_copy(const BigNum* src) {
  if (!src) return NULL;

  BigNum* dest = bn_new();
  if (!dest) return NULL;

  if (bn_resize(dest, src->capacity) != BN_OK) {
    bn_free(dest);
    return NULL;
  }

  memcpy(dest->digits, src->digits, src->size * sizeof(unsigned int));
  dest->size = src->size;
  dest->sign = src->sign;
  bn_normalize(dest); // Ensure copied number is normalized
  return dest;
}

// Helper: Resize the digit array
BigNumErrorCode bn_resize(BigNum* num, int new_capacity) {
  if (!num || new_capacity <= 0) return BN_ERROR_INVALID_INPUT;
  if (new_capacity > BIGNUM_MAX_DIGITS) return BN_ERROR_OVERFLOW;

  if (new_capacity != num->capacity) {
    unsigned int* new_digits = (unsigned int*)realloc(num->digits, new_capacity * sizeof(unsigned int));
    if (!new_digits) {
      return BN_ERROR_MEMORY_ALLOC;
    }
    num->digits = new_digits;
    // If resized to a larger capacity, zero out the new memory
    if (new_capacity > num->capacity) {
      memset(num->digits + num->capacity, 0, (new_capacity - num->capacity) * sizeof(unsigned int));
    }
    num->capacity = new_capacity;
    if (num->size > new_capacity) {
      num->size = new_capacity; // Truncate if new capacity is smaller
      bn_normalize(num);
    }
  }
  return BN_OK;
}

// Set BigNum to zero
BigNumErrorCode bn_set_zero(BigNum* num) {
  if (!num) return BN_ERROR_INVALID_INPUT;
  num->digits[0] = 0;
  num->size = 1;
  num->sign = 0;
  return BN_OK;
}

// Set BigNum to one
BigNumErrorCode bn_set_one(BigNum* num) {
  if (!num) return BN_ERROR_INVALID_INPUT;
  num->digits[0] = 1;
  num->size = 1;
  num->sign = 1;
  return BN_OK;
}

// Set BigNum from unsigned long long
BigNumErrorCode bn_from_ull(BigNum* num, unsigned long long val) {
  if (!num) return BN_ERROR_INVALID_INPUT;

  bn_set_zero(num);
  if (val == 0) {
    return BN_OK;
  }

  int i = 0;
  unsigned long long temp_val = val;

  // Determine required size
  int required_size = 0;
  if (val == 0) {
    required_size = 1;
  } else {
    unsigned long long current_val = val;
    while (current_val > 0) {
      required_size++;
      current_val >>= BIGNUM_BASE_BITS;
    }
  }
  if (required_size > num->capacity) {
    BigNumErrorCode err = bn_resize(num, required_size);
    if (err != BN_OK) return err;
  }

  while (temp_val > 0) {
    num->digits[i++] = (unsigned int)(temp_val & BIGNUM_BASE_MASK);
    temp_val >>= BIGNUM_BASE_BITS;
  }
  num->size = i;
  num->sign = 1;
  bn_normalize(num);
  return BN_OK;
}

// Convert BigNum to string (hex representation for simplicity, can extend to decimal)
// Returns dynamically allocated string, must be freed by caller
char* bn_to_string(const BigNum* num) {
  if (!num || bn_is_zero(num)) {
    char* str = (char*)malloc(2);
    if (str) strcpy(str, "0");
    return str;
  }

  // Each digit (32-bit) can be represented by 8 hex characters.
  // Plus 1 for sign, 1 for '0x', 1 for null terminator.
  size_t buffer_len = num->size * (BIGNUM_BASE_BITS / 4) + 3;
  char* str = (char*)malloc(buffer_len);
  if (!str) return NULL;

  char* ptr = str;

  if (num->sign == -1) {
    *ptr++ = '-';
  }
  *ptr++ = '0';
  *ptr++ = 'x';

  // Find the most significant non-zero digit
  int start_digit = num->size - 1;
  while (start_digit >= 0 && num->digits[start_digit] == 0) {
    start_digit--;
  }
  if (start_digit < 0) start_digit = 0; // Should not happen for non-zero numbers

  // Print the most significant digit without leading zeros
  sprintf(ptr, "%X", num->digits[start_digit]);
  ptr += strlen(ptr);

  // Print remaining digits with leading zeros if necessary
  for (int i = start_digit - 1; i >= 0; i--) {
    sprintf(ptr, "%08X", num->digits[i]); // %08X ensures 8 hex chars for 32-bit digit
    ptr += 8;
  }
  *ptr = '\0'; // Null-terminate
  return str;
}

// Set BigNum from string (hex representation)
// Supports "0x", "0X" prefixes, and optional leading '-' for negative numbers.
// Only hexadecimal digits are allowed.
BigNumErrorCode bn_from_string(BigNum* num, const char* str) {
  if (!num || !str) return BN_ERROR_INVALID_INPUT;

  bn_set_zero(num);
  const char* p = str;
  int input_sign = 1;

  if (*p == '-') {
    input_sign = -1;
    p++;
  }

  // Check for "0x" or "0X" prefix
  if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
    p += 2;
  }

  size_t len = strlen(p);
  if (len == 0) { // Empty string or just "-" or "0x"
    return BN_OK; // Already set to zero
  }

  // Calculate required number of digits. Each hex char is 4 bits. Each digit is 32 bits.
  // So 8 hex chars per digit.
  int num_hex_chars = len;
  int required_digits = (num_hex_chars + (BIGNUM_BASE_BITS / 4) - 1) / (BIGNUM_BASE_BITS / 4);

  if (required_digits > num->capacity) {
    BigNumErrorCode err = bn_resize(num, required_digits);
    if (err != BN_OK) return err;
  }

  num->size = required_digits;
  memset(num->digits, 0, num->capacity * sizeof(unsigned int)); // Clear digits

  // Process characters from right to left (least significant to most significant)
  // to build up digits.
  unsigned long long current_digit_val = 0;
  int current_digit_idx = 0;
  int bits_processed_in_digit = 0;

  for (int i = len - 1; i >= 0; i--) {
    char c = p[i];
    unsigned int val;
    if (c >= '0' && c <= '9') {
      val = c - '0';
    } else if (c >= 'a' && c <= 'f') {
      val = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
      val = c - 'A' + 10;
    } else {
      bn_set_zero(num); // Malformed string
      return BN_ERROR_INVALID_INPUT;
    }

    // Add the hex value to the current digit, shifting appropriately
    current_digit_val |= ((unsigned long long)val << bits_processed_in_digit);
    bits_processed_in_digit += 4;

    if (bits_processed_in_digit >= BIGNUM_BASE_BITS) {
      num->digits[current_digit_idx] = (unsigned int)current_digit_val;
      current_digit_idx++;
      current_digit_val = 0;
      bits_processed_in_digit = 0;
    }
  }

  // Store any remaining part of the last digit
  if (bits_processed_in_digit > 0) {
    num->digits[current_digit_idx] = (unsigned int)current_digit_val;
  }

  num->sign = input_sign;
  bn_normalize(num);
  return BN_OK;
}


// Set BigNum dest from BigNum src
BigNumErrorCode bn_set(BigNum* dest, const BigNum* src) {
  if (!dest || !src) return BN_ERROR_INVALID_INPUT;

  if (dest->capacity < src->size) {
    BigNumErrorCode err = bn_resize(dest, src->size);
    if (err != BN_OK) return err;
  }

  memcpy(dest->digits, src->digits, src->size * sizeof(unsigned int));
  dest->size = src->size;
  dest->sign = src->sign;
  bn_normalize(dest);
  return BN_OK;
}

// Check if BigNum is zero
int bn_is_zero(const BigNum* num) {
  return (num && num->sign == 0);
}

// Check if BigNum is one
int bn_is_one(const BigNum* num) {
  return (num && num->sign == 1 && num->size == 1 && num->digits[0] == 1);
}

// Compare absolute values of two BigNums
// Returns -1 if |a| < |b|, 0 if |a| == |b|, 1 if |a| > |b|
int bn_compare_abs(const BigNum* a, const BigNum* b) {
  if (!a || !b) return 0; // Or define an error code

  if (a->size > b->size) return 1;
  if (a->size < b->size) return -1;

  // Sizes are equal, compare digit by digit from MSB
  for (int i = a->size - 1; i >= 0; i--) {
    if (a->digits[i] > b->digits[i]) return 1;
    if (a->digits[i] < b->digits[i]) return -1;
  }
  return 0; // Numbers are equal in absolute value
}

// Compare two BigNums
// Returns -1 if a < b, 0 if a == b, 1 if a > b
int bn_compare(const BigNum* a, const BigNum* b) {
  if (!a || !b) return 0; // Or define an error code

  if (a->sign == 0 && b->sign == 0) return 0; // Both are zero
  if (a->sign == 0) return b->sign == 1 ? -1 : 1; // a is zero, b is positive or negative
  if (b->sign == 0) return a->sign == 1 ? 1 : -1; // b is zero, a is positive or negative

  if (a->sign == 1 && b->sign == -1) return 1; // Positive > Negative
  if (a->sign == -1 && b->sign == 1) return -1; // Negative < Positive

  // Both signs are the same
  int cmp_abs = bn_compare_abs(a, b);
  if (a->sign == 1) { // Both positive
    return cmp_abs;
  } else { // Both negative
    return -cmp_abs; // -5 > -10, so if |a| < |b|, then a > b
  }
}

// Print BigNum (for debugging)
void bn_print(const char* prefix, const BigNum* num) {
  if (!num) {
    printf("%s (null)\n", prefix ? prefix : "");
    return;
  }
  char* str = bn_to_string(num);
  if (str) {
    printf("%s %s (size: %d, capacity: %d, sign: %d)\n",
           prefix ? prefix : "", str, num->size, num->capacity, num->sign);
    free(str);
  } else {
    printf("%s (conversion error)\n", prefix ? prefix : "");
  }
}


// --- Arithmetic Operations ---

// Helper for addition of absolute values (unsigned addition)
// result = |a| + |b|
static BigNumErrorCode bn_add_abs(BigNum* result, const BigNum* a, const BigNum* b) {
  if (!result || !a || !b) return BN_ERROR_INVALID_INPUT;

  int max_size = (a->size > b->size ? a->size : b->size);
  int new_capacity = max_size + 1; // Potentially one extra digit for carry

  if (result->capacity < new_capacity) {
    BigNumErrorCode err = bn_resize(result, new_capacity);
    if (err != BN_OK) return err;
  }

  memset(result->digits, 0, result->capacity * sizeof(unsigned int));
  unsigned long long carry = 0;

  for (int i = 0; i < new_capacity; i++) {
    unsigned long long sum = carry;
    if (i < a->size) sum += a->digits[i];
    if (i < b->size) sum += b->digits[i];

    result->digits[i] = (unsigned int)(sum & BIGNUM_BASE_MASK);
    carry = sum >> BIGNUM_BASE_BITS;
  }

  result->size = new_capacity;
  bn_normalize(result); // Remove any leading zeros
  return BN_OK;
}

// Helper for subtraction of absolute values (|a| - |b|) where |a| >= |b|
// result = |a| - |b|
static BigNumErrorCode bn_sub_abs(BigNum* result, const BigNum* a, const BigNum* b) {
  if (!result || !a || !b) return BN_ERROR_INVALID_INPUT;
  // Precondition: bn_compare_abs(a, b) >= 0

  if (result->capacity < a->size) {
    BigNumErrorCode err = bn_resize(result, a->size);
    if (err != BN_OK) return err;
  }

  memset(result->digits, 0, result->capacity * sizeof(unsigned int));
  unsigned long long borrow = 0;

  for (int i = 0; i < a->size; i++) {
    long long diff = (long long)a->digits[i] - (i < b->size ? b->digits[i] : 0) - borrow;
    if (diff < 0) {
      result->digits[i] = (unsigned int)(diff + (1ULL << BIGNUM_BASE_BITS));
      borrow = 1;
    } else {
      result->digits[i] = (unsigned int)diff;
      borrow = 0;
    }
  }

  result->size = a->size;
  bn_normalize(result);
  return BN_OK;
}

// General Addition: result = a + b
BigNumErrorCode bn_add(BigNum* result, const BigNum* a, const BigNum* b) {
  if (!result || !a || !b) return BN_ERROR_INVALID_INPUT;

  if (a->sign == 0) return bn_set(result, b);
  if (b->sign == 0) return bn_set(result, a);

  if (a->sign == b->sign) { // Both positive or both negative
    BigNumErrorCode err = bn_add_abs(result, a, b);
    if (err != BN_OK) return err;
    result->sign = a->sign;
  } else { // Signs are different (a + (-b) or (-a) + b)
    // Equivalent to absolute subtraction: |a| - |b| or |b| - |a|
    int cmp_abs = bn_compare_abs(a, b);
    if (cmp_abs == 0) {
      bn_set_zero(result);
    } else if (cmp_abs > 0) { // |a| > |b|, result has sign of a
      BigNumErrorCode err = bn_sub_abs(result, a, b);
      if (err != BN_OK) return err;
      result->sign = a->sign;
    } else { // |a| < |b|, result has sign of b
      BigNumErrorCode err = bn_sub_abs(result, b, a);
      if (err != BN_OK) return err;
      result->sign = b->sign;
    }
  }
  bn_normalize(result);
  return BN_OK;
}

// General Subtraction: result = a - b
BigNumErrorCode bn_sub(BigNum* result, const BigNum* a, const BigNum* b) {
  if (!result || !a || !b) return BN_ERROR_INVALID_INPUT;

  if (a->sign == 0) { // 0 - b = -b
    BigNumErrorCode err = bn_set(result, b);
    if (err != BN_OK) return err;
    result->sign = -b->sign;
    bn_normalize(result);
    return BN_OK;
  }
  if (b->sign == 0) { // a - 0 = a
    return bn_set(result, a);
  }

  if (a->sign != b->sign) { // a - (-b) = a + b, or (-a) - b = -(a + b)
    BigNumErrorCode err = bn_add_abs(result, a, b);
    if (err != BN_OK) return err;
    result->sign = a->sign; // If a is positive, a+b is positive. If a is negative, -(a+b) is negative.
  } else { // Signs are the same (a - b or (-a) - (-b))
    int cmp_abs = bn_compare_abs(a, b);
    if (cmp_abs == 0) {
      bn_set_zero(result);
    } else if (cmp_abs > 0) { // |a| > |b|, result has sign of a
      BigNumErrorCode err = bn_sub_abs(result, a, b);
      if (err != BN_OK) return err;
      result->sign = a->sign;
    } else { // |a| < |b|, result has opposite sign of a (or same sign as b)
      BigNumErrorCode err = bn_sub_abs(result, b, a);
      if (err != BN_OK) return err;
      result->sign = -a->sign;
    }
  }
  bn_normalize(result);
  return BN_OK;
}

// Multiplication: result = a * b
BigNumErrorCode bn_mul(BigNum* result, const BigNum* a, const BigNum* b) {
  if (!result || !a || !b) return BN_ERROR_INVALID_INPUT;
  if (bn_is_zero(a) || bn_is_zero(b)) {
    bn_set_zero(result);
    return BN_OK;
  }

  int new_capacity = a->size + b->size;
  if (result->capacity < new_capacity) {
    BigNumErrorCode err = bn_resize(result, new_capacity);
    if (err != BN_OK) return err;
  }
  memset(result->digits, 0, result->capacity * sizeof(unsigned int));

  for (int i = 0; i < a->size; i++) {
    unsigned long long carry = 0;
    for (int j = 0; j < b->size; j++) {
      unsigned long long product = (unsigned long long)a->digits[i] * b->digits[j] +
                                   result->digits[i + j] + carry;
      result->digits[i + j] = (unsigned int)(product & BIGNUM_BASE_MASK);
      carry = product >> BIGNUM_BASE_BITS;
    }
    result->digits[i + b->size] += (unsigned int)carry; // Add last carry
  }

  result->size = new_capacity;
  result->sign = a->sign * b->sign;
  bn_normalize(result);
  return BN_OK;
}

// Division and Modulus: a = quotient * b + remainder
// `b` must not be zero.
// Uses a "schoolbook" long division algorithm.
BigNumErrorCode bn_div_mod(BigNum* quotient, BigNum* remainder, const BigNum* a, const BigNum* b) {
  if (!quotient || !remainder || !a || !b) return BN_ERROR_INVALID_INPUT;
  if (bn_is_zero(b)) return BN_ERROR_DIV_BY_ZERO;

  // Handle trivial cases
  if (bn_is_zero(a)) {
    bn_set_zero(quotient);
    bn_set_zero(remainder);
    return BN_OK;
  }

  // Compare absolute values
  int cmp_abs = bn_compare_abs(a, b);
  if (cmp_abs < 0) { // |a| < |b|
    bn_set_zero(quotient);
    bn_set(remainder, a); // Remainder is a
    return BN_OK;
  } else if (cmp_abs == 0) { // |a| == |b|
    bn_set_one(quotient);
    quotient->sign = a->sign * b->sign; // Determine sign of quotient
    bn_set_zero(remainder);
    return BN_OK;
  }

  // Normalize dividend and divisor for positive values during calculation
  BigNum* abs_a = bn_copy(a);
  abs_a->sign = 1;
  BigNum* abs_b = bn_copy(b);
  abs_b->sign = 1;

  bn_set_zero(quotient); // Initialize quotient
  quotient->sign = a->sign * b->sign;

  // The remainder will initially be `a` (absolute value), and we'll subtract `b` from it
  BigNum* current_remainder = bn_copy(abs_a);
  if (!current_remainder || !abs_a || !abs_b) {
    bn_free(abs_a); bn_free(abs_b); bn_free(current_remainder);
    return BN_ERROR_MEMORY_ALLOC;
  }

  // Determine the number of bits to normalize `abs_b` so its MSB is set.
  // This makes division more stable, similar to Knuth's algorithm.
  int normalizer_shift = 0;
  if (abs_b->size > 0) {
    unsigned int msb_b = abs_b->digits[abs_b->size - 1];
    if (msb_b == 0) { // Should not happen after bn_normalize, but defensive
      bn_free(abs_a); bn_free(abs_b); bn_free(current_remainder);
      return BN_ERROR_INVALID_INPUT;
    }
    while (!((msb_b >> (BIGNUM_BASE_BITS - 1)) & 1)) {
      msb_b <<= 1;
      normalizer_shift++;
    }
  }

  BigNum* shifted_a = bn_new();
  BigNum* shifted_b = bn_new();
  BigNumErrorCode err;

  if (normalizer_shift > 0) {
    err = bn_lshift(shifted_a, abs_a, normalizer_shift);
    if (err != BN_OK) { bn_free(abs_a); bn_free(abs_b); bn_free(current_remainder); bn_free(shifted_a); bn_free(shifted_b); return err; }
    err = bn_lshift(shifted_b, abs_b, normalizer_shift);
    if (err != BN_OK) { bn_free(abs_a); bn_free(abs_b); bn_free(current_remainder); bn_free(shifted_a); bn_free(shifted_b); return err; }
  } else {
    err = bn_set(shifted_a, abs_a);
    if (err != BN_OK) { bn_free(abs_a); bn_free(abs_b); bn_free(current_remainder); bn_free(shifted_a); bn_free(shifted_b); return err; }
    err = bn_set(shifted_b, abs_b);
    if (err != BN_OK) { bn_free(abs_a); bn_free(abs_b); bn_free(current_remainder); bn_free(shifted_a); bn_free(shifted_b); return err; }
  }

  // Now, `shifted_a` is the new dividend, `shifted_b` is the new divisor
  bn_set(current_remainder, shifted_a); // Set current_remainder to shifted dividend

  int k_diff = current_remainder->size - shifted_b->size;
  if (k_diff < 0) k_diff = 0; // Should not happen with cmp_abs check above

  // The quotient will need to accommodate k_diff + 1 digits
  if (quotient->capacity < k_diff + 1) {
    err = bn_resize(quotient, k_diff + 1);
    if (err != BN_OK) { bn_free(abs_a); bn_free(abs_b); bn_free(current_remainder); bn_free(shifted_a); bn_free(shifted_b); return err; }
  }
  memset(quotient->digits, 0, quotient->capacity * sizeof(unsigned int));


  BigNum* temp_b_shifted = bn_new(); // Temporary for shifted divisor
  BigNum* temp_product = bn_new();    // Temporary for q*divisor
  BigNum* temp_sub_result = bn_new(); // Temporary for subtraction result
  if (!temp_b_shifted || !temp_product || !temp_sub_result) {
    bn_free(abs_a); bn_free(abs_b); bn_free(current_remainder);
    bn_free(shifted_a); bn_free(shifted_b);
    bn_free(temp_b_shifted); bn_free(temp_product); bn_free(temp_sub_result);
    return BN_ERROR_MEMORY_ALLOC;
  }

  for (int k = k_diff; k >= 0; k--) {
    // Estimate the quotient digit q_hat
    // q_hat = ( (rem[k+n-1] * B + rem[k+n-2]) / b[n-1] )
    // Using unsigned long long for intermediate calculations
    unsigned long long current_dividend_val = 0;
    int current_remainder_msb_idx = current_remainder->size - 1;
    if (current_remainder_msb_idx >= k + shifted_b->size - 1) { // If there are enough digits
      current_dividend_val = current_remainder->digits[current_remainder_msb_idx];
      if (current_remainder_msb_idx > 0) {
        current_dividend_val = (current_dividend_val << BIGNUM_BASE_BITS) | current_remainder->digits[current_remainder_msb_idx-1];
      }
    }
    unsigned int msb_divisor = shifted_b->digits[shifted_b->size - 1];

    unsigned long long q_hat;
    if (msb_divisor == 0) { // Should not happen after normalization
      bn_free(abs_a); bn_free(abs_b); bn_free(current_remainder);
      bn_free(shifted_a); bn_free(shifted_b);
      bn_free(temp_b_shifted); bn_free(temp_product); bn_free(temp_sub_result);
      return BN_ERROR_INVALID_INPUT;
    }
    q_hat = current_dividend_val / msb_divisor;

    // Cap q_hat at BIGNUM_BASE_MAX (UINT_MAX)
    if (q_hat > BIGNUM_BASE_MAX) {
      q_hat = BIGNUM_BASE_MAX;
    }

    // Try subtracting q_hat * shifted_b from the relevant part of current_remainder
    err = bn_lshift(temp_b_shifted, shifted_b, k * BIGNUM_BASE_BITS);
    if (err != BN_OK) { bn_free(abs_a); bn_free(abs_b); bn_free(current_remainder); bn_free(shifted_a); bn_free(shifted_b); bn_free(temp_b_shifted); bn_free(temp_product); bn_free(temp_sub_result); return err; }

    BigNum q_hat_bn;
    q_hat_bn.digits = &((unsigned int)q_hat); // Treat q_hat as a 1-digit bignum
    q_hat_bn.size = 1;
    q_hat_bn.capacity = 1;
    q_hat_bn.sign = 1;

    err = bn_mul(temp_product, &q_hat_bn, temp_b_shifted);
    if (err != BN_OK) { bn_free(abs_a); bn_free(abs_b); bn_free(current_remainder); bn_free(shifted_a); bn_free(shifted_b); bn_free(temp_b_shifted); bn_free(temp_product); bn_free(temp_sub_result); return err; }

    while (bn_compare_abs(current_remainder, temp_product) < 0) {
      q_hat--;
      q_hat_bn.digits[0] = (unsigned int)q_hat; // Update q_hat in the temporary bignum
      err = bn_mul(temp_product, &q_hat_bn, temp_b_shifted);
      if (err != BN_OK) { bn_free(abs_a); bn_free(abs_b); bn_free(current_remainder); bn_free(shifted_a); bn_free(shifted_b); bn_free(temp_b_shifted); bn_free(temp_product); bn_free(temp_sub_result); return err; }
    }

    err = bn_sub_abs(temp_sub_result, current_remainder, temp_product);
    if (err != BN_OK) { bn_free(abs_a); bn_free(abs_b); bn_free(current_remainder); bn_free(shifted_a); bn_free(shifted_b); bn_free(temp_b_shifted); bn_free(temp_product); bn_free(temp_sub_result); return err; }
    bn_set(current_remainder, temp_sub_result);

    // Store the quotient digit
    quotient->digits[k] = (unsigned int)q_hat;
  }

  quotient->size = k_diff + 1;
  bn_normalize(quotient);
  bn_normalize(current_remainder);

  // Denormalize the remainder
  err = bn_rshift(remainder, current_remainder, normalizer_shift);
  if (err != BN_OK) { bn_free(abs_a); bn_free(abs_b); bn_free(current_remainder); bn_free(shifted_a); bn_free(shifted_b); bn_free(temp_b_shifted); bn_free(temp_product); bn_free(temp_sub_result); return err; }

  // Adjust remainder sign
  if (a->sign == -1 && !bn_is_zero(remainder)) {
    // If dividend was negative and remainder is not zero, subtract b from remainder
    // to get remainder with same sign as divisor (conventionally positive).
    // Or simply make it negative in the case of -a % b = -(a % b)
    // For C-like behavior, if a < 0, then a % b can be <= 0.
    // We ensure remainder is 0 or positive for RSA.
    // If `a` was negative and `remainder` is non-zero, then `remainder` should be `remainder - |b|`
    // so that `a = q*b + rem`. Example: -5 / 3. q = -1, rem = -2.
    // Or in python, -5 % 3 = 1.
    // For RSA, we always work with positive numbers.
    // The spec for `bn_div_mod` usually means for positive a, b.
    // For RSA, the modulus `n` is always positive. We primarily care about `mod n`.
    // So `a` will generally be positive. If it's negative, it's `a mod n`.
    // For now, let's assume inputs to div_mod for RSA are positive.
    // If a is negative, the remainder should be 0 or have the same sign as a.
    // The result of `bn_sub_abs` is always positive.
    // If a is negative, and remainder is non-zero, it means a `abs_a = q * abs_b + abs_rem`.
    // So, `a = (a_sign * q) * b_sign * abs_b + a_sign * abs_rem`.
    // If remainder is non-zero and original a was negative, we want the remainder to be `abs_rem - |b|`
    // to ensure it satisfies `a = q*b + r` where `0 <= abs(r) < abs(b)`.
    // For cryptographic purposes, the result of mod is always non-negative.
    // If `a` is negative, `(-X) mod N = (N - (X mod N)) mod N`.
    // So if `remainder` (calculated from abs_a, abs_b) is non-zero after denormalization,
    // and `a` was negative, the `remainder` needs to be `(remainder - b)`.
    if (!bn_is_zero(remainder)) {
      BigNum* temp_rem_sub_b = bn_new();
      BigNumErrorCode sub_err = bn_sub_abs(temp_rem_sub_b, remainder, abs_b); // This should not happen if abs(a) was larger than abs(b)
      if (sub_err != BN_OK) { /* handle error */ }
      bn_set(remainder, temp_rem_sub_b);
      remainder->sign = -1; // It will be negative
      bn_free(temp_rem_sub_b);
    }
  }


  bn_free(abs_a);
  bn_free(abs_b);
  bn_free(current_remainder);
  bn_free(shifted_a);
  bn_free(shifted_b);
  bn_free(temp_b_shifted);
  bn_free(temp_product);
  bn_free(temp_sub_result);

  return BN_OK;
}


// Bitwise Left Shift: result = num << shift_bits
BigNumErrorCode bn_lshift(BigNum* result, const BigNum* num, int shift_bits) {
  if (!result || !num || shift_bits < 0) return BN_ERROR_INVALID_INPUT;
  if (bn_is_zero(num)) {
    bn_set_zero(result);
    return BN_OK;
  }

  int word_shift = shift_bits / BIGNUM_BASE_BITS;
  int bit_in_word_shift = shift_bits % BIGNUM_BASE_BITS;

  int new_size = num->size + word_shift;
  if (bit_in_word_shift > 0) {
    new_size++; // Potentially needs one more digit for bits that overflow
  }

  if (new_size > BIGNUM_MAX_DIGITS) return BN_ERROR_OVERFLOW; // Prevent excessive size

  if (result->capacity < new_size) {
    BigNumErrorCode err = bn_resize(result, new_size);
    if (err != BN_OK) return err;
  }
  memset(result->digits, 0, result->capacity * sizeof(unsigned int));

  unsigned int carry = 0;
  for (int i = 0; i < num->size; i++) {
    unsigned long long temp_val = (unsigned long long)num->digits[i] << bit_in_word_shift;
    result->digits[i + word_shift] = (unsigned int)(temp_val & BIGNUM_BASE_MASK) | carry;
    carry = (unsigned int)(temp_val >> BIGNUM_BASE_BITS);
  }
  if (carry > 0) {
    result->digits[num->size + word_shift] = carry;
  }

  result->size = new_size;
  result->sign = num->sign;
  bn_normalize(result);
  return BN_OK;
}

// Bitwise Right Shift: result = num >> shift_bits
BigNumErrorCode bn_rshift(BigNum* result, const BigNum* num, int shift_bits) {
  if (!result || !num || shift_bits < 0) return BN_ERROR_INVALID_INPUT;
  if (bn_is_zero(num)) {
    bn_set_zero(result);
    return BN_OK;
  }

  int word_shift = shift_bits / BIGNUM_BASE_BITS;
  int bit_in_word_shift = shift_bits % BIGNUM_BASE_BITS;

  if (word_shift >= num->size) { // Shifting more bits than available
    bn_set_zero(result);
    return BN_OK;
  }

  int new_size = num->size - word_shift;
  if (new_size == 0) { // If it becomes 0 after shift
    bn_set_zero(result);
    return BN_OK;
  }

  if (result->capacity < new_size) {
    BigNumErrorCode err = bn_resize(result, new_size);
    if (err != BN_OK) return err;
  }
  memset(result->digits, 0, result->capacity * sizeof(unsigned int));

  unsigned int carry = 0;
  for (int i = num->size - 1; i >= word_shift; i--) {
    unsigned long long temp_val = (unsigned long long)num->digits[i] | ((unsigned long long)carry << BIGNUM_BASE_BITS);
    result->digits[i - word_shift] = (unsigned int)(temp_val >> bit_in_word_shift);
    carry = (unsigned int)(num->digits[i] & ((1U << bit_in_word_shift) - 1));
  }

  result->size = new_size;
  result->sign = num->sign; // Right shift preserves sign for positive numbers
  bn_normalize(result);
  return BN_OK;
}


// --- Modular Arithmetic ---

// Modular Exponentiation: result = (base ^ exp) % mod
// Uses left-to-right binary exponentiation (square-and-multiply)
BigNumErrorCode bn_mod_exp(BigNum* result, const BigNum* base, const BigNum* exp, const BigNum* mod) {
  if (!result || !base || !exp || !mod || bn_is_zero(mod)) {
    return BN_ERROR_INVALID_INPUT;
  }

  // result = 1
  bn_set_one(result);

  // If exp is 0, result is 1
  if (bn_is_zero(exp)) {
    return BN_OK;
  }

  BigNum* b = bn_copy(base); // Base for calculation (will be reduced mod mod)
  BigNum* e = bn_copy(exp);  // Exponent copy
  BigNum* current_base_mod_mod = bn_new(); // Stores b % mod
  BigNum* temp_mul_result = bn_new(); // Stores intermediate result * base
  BigNum* temp_square_result = bn_new(); // Stores intermediate base * base
  BigNum* temp_remainder = bn_new(); // For modulus operations
  if (!b || !e || !current_base_mod_mod || !temp_mul_result || !temp_square_result || !temp_remainder) {
    bn_free(b); bn_free(e); bn_free(current_base_mod_mod);
    bn_free(temp_mul_result); bn_free(temp_square_result); bn_free(temp_remainder);
    return BN_ERROR_MEMORY_ALLOC;
  }

  // Base should be (base % mod) if base >= mod
  BigNumErrorCode err = bn_div_mod(bn_new(), current_base_mod_mod, b, mod); // Use a dummy quotient
  if (err != BN_OK) {
    bn_free(b); bn_free(e); bn_free(current_base_mod_mod);
    bn_free(temp_mul_result); bn_free(temp_square_result); bn_free(temp_remainder);
    return err;
  }
  bn_set(b, current_base_mod_mod); // b is now (base % mod)

  // Find the highest set bit in the exponent
  int exp_bits = 0;
  for (int i = e->size - 1; i >= 0; i--) {
    if (e->digits[i] != 0) {
      unsigned int temp = e->digits[i];
      for (int j = 0; j < BIGNUM_BASE_BITS; j++) {
        if ((temp >> j) & 1) {
          exp_bits = i * BIGNUM_BASE_BITS + j + 1;
        }
      }
      break;
    }
  }

  for (int i = exp_bits - 1; i >= 0; i--) {
    // Square: result = (result * result) % mod
    err = bn_mul(temp_square_result, result, result);
    if (err != BN_OK) { goto cleanup; }
    err = bn_div_mod(bn_new(), temp_remainder, temp_square_result, mod); // Use dummy quotient
    if (err != BN_OK) { goto cleanup; }
    err = bn_set(result, temp_remainder);
    if (err != BN_OK) { goto cleanup; }

    // Check if the current bit of exponent is 1
    int digit_idx = i / BIGNUM_BASE_BITS;
    int bit_in_digit_idx = i % BIGNUM_BASE_BITS;
    if (digit_idx < e->size && ((e->digits[digit_idx] >> bit_in_digit_idx) & 1)) {
      // Multiply: result = (result * b) % mod
      err = bn_mul(temp_mul_result, result, b);
      if (err != BN_OK) { goto cleanup; }
      err = bn_div_mod(bn_new(), temp_remainder, temp_mul_result, mod); // Use dummy quotient
      if (err != BN_OK) { goto cleanup; }
      err = bn_set(result, temp_remainder);
      if (err != BN_OK) { goto cleanup; }
    }
  }

cleanup:
  bn_free(b);
  bn_free(e);
  bn_free(current_base_mod_mod);
  bn_free(temp_mul_result);
  bn_free(temp_square_result);
  bn_free(temp_remainder);

  return err; // Return any error encountered, or BN_OK
}

// Greatest Common Divisor (GCD): result = gcd(a, b)
// Uses Euclidean algorithm
BigNumErrorCode bn_gcd(BigNum* result, const BigNum* a, const BigNum* b) {
  if (!result || !a || !b) return BN_ERROR_INVALID_INPUT;

  BigNum* x = bn_copy(a);
  BigNum* y = bn_copy(b);
  BigNum* temp_rem = bn_new();
  BigNum* dummy_q = bn_new(); // Dummy for quotient in div_mod
  if (!x || !y || !temp_rem || !dummy_q) {
    bn_free(x); bn_free(y); bn_free(temp_rem); bn_free(dummy_q);
    return BN_ERROR_MEMORY_ALLOC;
  }

  x->sign = 1; // Work with absolute values
  y->sign = 1;

  BigNumErrorCode err = BN_OK;

  while (!bn_is_zero(y)) {
    err = bn_div_mod(dummy_q, temp_rem, x, y); // temp_rem = x % y
    if (err != BN_OK) break;

    err = bn_set(x, y); // x = y
    if (err != BN_OK) break;

    err = bn_set(y, temp_rem); // y = temp_rem
    if (err != BN_OK) break;
  }

  if (err == BN_OK) {
    err = bn_set(result, x); // result = x (which is the gcd)
  }

  bn_free(x);
  bn_free(y);
  bn_free(temp_rem);
  bn_free(dummy_q);
  return err;
}

// Modular Inverse: result = a^-1 (mod m)
// Finds x such that (a * x) % m = 1
// Uses Extended Euclidean Algorithm
BigNumErrorCode bn_mod_inverse(BigNum* result, const BigNum* a, const BigNum* m) {
  if (!result || !a || !m || bn_is_zero(m) || bn_is_one(m)) {
    return BN_ERROR_INVALID_INPUT;
  }

  BigNum* m_copy = bn_copy(m);
  BigNum* a_mod_m = bn_new();
  BigNum* dummy_q = bn_new();
  if (!m_copy || !a_mod_m || !dummy_q) {
    bn_free(m_copy); bn_free(a_mod_m); bn_free(dummy_q);
    return BN_ERROR_MEMORY_ALLOC;
  }
  
  // a' = a % m
  BigNumErrorCode err = bn_div_mod(dummy_q, a_mod_m, a, m);
  if (err != BN_OK) {
    bn_free(m_copy); bn_free(a_mod_m); bn_free(dummy_q);
    return err;
  }

  // If a' is zero, no inverse exists
  if (bn_is_zero(a_mod_m)) {
    bn_set_zero(result);
    bn_free(m_copy); bn_free(a_mod_m); bn_free(dummy_q);
    return BN_ERROR_MOD_INVERSE_FAILED;
  }

  BigNum* zero = bn_new(); bn_set_zero(zero);
  BigNum* one = bn_new(); bn_set_one(one);

  BigNum* r0 = bn_copy(m_copy); // r0 = m
  BigNum* r1 = bn_copy(a_mod_m); // r1 = a % m
  BigNum* s0 = bn_copy(one); // s0 = 1
  BigNum* s1 = bn_copy(zero); // s1 = 0
  BigNum* t0 = bn_copy(zero); // t0 = 0
  BigNum* t1 = bn_copy(one); // t1 = 1

  BigNum* q = bn_new(); // Quotient
  BigNum* r_new = bn_new();
  BigNum* s_new = bn_new();
  BigNum* t_new = bn_new();

  BigNum* term1 = bn_new();
  BigNum* term2 = bn_new();

  if (!zero || !one || !r0 || !r1 || !s0 || !s1 || !t0 || !t1 ||
    !q || !r_new || !s_new || !t_new || !term1 || !term2) {
    err = BN_ERROR_MEMORY_ALLOC;
    goto inv_cleanup;
  }

  while (!bn_is_zero(r1)) {
    err = bn_div_mod(q, r_new, r0, r1); // q = r0 / r1, r_new = r0 % r1
    if (err != BN_OK) break;

    // s_new = s0 - q * s1
    err = bn_mul(term1, q, s1);
    if (err != BN_OK) break;
    err = bn_sub(s_new, s0, term1);
    if (err != BN_OK) break;

    // t_new = t0 - q * t1
    err = bn_mul(term2, q, t1);
    if (err != BN_OK) break;
    err = bn_sub(t_new, t0, term2);
    if (err != BN_OK) break;

    // Update values
    bn_set(r0, r1);
    bn_set(r1, r_new);
    bn_set(s0, s1);
    bn_set(s1, s_new);
    bn_set(t0, t1);
    bn_set(t1, t_new);
  }

  // At this point, r0 holds the GCD(a, m)
  if (!bn_is_one(r0)) {
    // No modular inverse if GCD is not 1
    bn_set_zero(result);
    err = BN_ERROR_MOD_INVERSE_FAILED;
    goto inv_cleanup;
  }

  // The modular inverse is t0, but it might be negative.
  // If t0 is negative, add m until it's positive.
  if (t0->sign == -1) {
    err = bn_add(result, t0, m_copy); // result = t0 + m
    if (err != BN_OK) { goto inv_cleanup; }
    // Ensure result is within [0, m-1]
    BigNum* final_rem = bn_new();
    err = bn_div_mod(dummy_q, final_rem, result, m_copy);
    if (err != BN_OK) { bn_free(final_rem); goto inv_cleanup; }
    bn_set(result, final_rem);
    bn_free(final_rem);
  } else {
    err = bn_set(result, t0);
    if (err != BN_OK) { goto inv_cleanup; }
    // Ensure result is within [0, m-1]
    BigNum* final_rem = bn_new();
    err = bn_div_mod(dummy_q, final_rem, result, m_copy);
    if (err != BN_OK) { bn_free(final_rem); goto inv_cleanup; }
    bn_set(result, final_rem);
    bn_free(final_rem);
  }

inv_cleanup:
  bn_free(m_copy);
  bn_free(a_mod_m);
  bn_free(dummy_q);
  bn_free(zero);
  bn_free(one);
  bn_free(r0);
  bn_free(r1);
  bn_free(s0);
  bn_free(s1);
  bn_free(t0);
  bn_free(t1);
  bn_free(q);
  bn_free(r_new);
  bn_free(s_new);
  bn_free(t_new);
  bn_free(term1);
  bn_free(term2);

  return err;
}


// --- Random Number Generation ---

// Generates a random BigNum with approximately num_bits (actual bits might be less)
BigNumErrorCode bn_rand(BigNum* num, int num_bits) {
  if (!num || num_bits <= 0) return BN_ERROR_INVALID_INPUT;

  // Seed the random number generator if not already done
  // (Should be done once per program execution, e.g., in main)
  // srand((unsigned int)time(NULL));

  int required_digits = (num_bits + BIGNUM_BASE_BITS - 1) / BIGNUM_BASE_BITS;
  if (required_digits == 0) required_digits = 1; // At least one digit for 0 bits

  if (required_digits > num->capacity) {
    BigNumErrorCode err = bn_resize(num, required_digits);
    if (err != BN_OK) return err;
  }

  for (int i = 0; i < required_digits; i++) {
    num->digits[i] = get_rand_digit();
  }
  num->size = required_digits;
  num->sign = 1;

  // Zero out any excess bits in the most significant digit if num_bits is not a multiple of BIGNUM_BASE_BITS
  int excess_bits = (required_digits * BIGNUM_BASE_BITS) - num_bits;
  if (excess_bits > 0 && num_bits > 0) { // num_bits > 0 check to avoid shifting by 32 for 0-bit numbers
    num->digits[num->size - 1] >>= excess_bits;
  }

  // Ensure the most significant bit is set for cryptographic use (e.g., for primes)
  if (num_bits > 0 && num->size > 0) {
    int msb_digit_idx = num->size - 1;
    // The most significant bit we want to set is (num_bits - 1) relative to total bit count
    // Or (num_bits - 1) % BIGNUM_BASE_BITS relative to the MSB digit
    unsigned int msb_mask = 1U << ((num_bits - 1) % BIGNUM_BASE_BITS);
    num->digits[msb_digit_idx] |= msb_mask;
  }
  
  // Ensure the number is odd (if it's intended for a prime candidate)
  // For general random numbers, this is not needed.
  // For RSA prime generation, we typically want odd numbers.
  // If num_bits >= 1, make it odd.
  if (num_bits >= 1 && num->size > 0) {
    num->digits[0] |= 1;
  }

  bn_normalize(num);
  return BN_OK;
}

// Generates a random BigNum within a given range [min, max]
BigNumErrorCode bn_rand_range(BigNum* num, const BigNum* min, const BigNum* max) {
  if (!num || !min || !max) return BN_ERROR_INVALID_INPUT;
  if (bn_compare(min, max) > 0) return BN_ERROR_INVALID_INPUT; // min must be <= max

  // Calculate the range size: range = max - min + 1
  BigNum* range = bn_new();
  BigNum* one = bn_new();
  BigNum* temp_add = bn_new();
  if (!range || !one || !temp_add) {
    bn_free(range); bn_free(one); bn_free(temp_add);
    return BN_ERROR_MEMORY_ALLOC;
  }
  bn_set_one(one);

  BigNumErrorCode err = bn_sub(range, max, min);
  if (err != BN_OK) { goto cleanup_rand_range; }
  err = bn_add(range, range, one); // range = (max - min) + 1
  if (err != BN_OK) { goto cleanup_rand_range; }

  if (bn_is_zero(range)) { // max = min = 0
    err = bn_set(num, min);
    goto cleanup_rand_range;
  }

  // Determine the number of bits needed for 'range'
  int range_bits = 0;
  for (int i = range->size - 1; i >= 0; i--) {
    if (range->digits[i] != 0) {
      unsigned int temp = range->digits[i];
      for (int j = BIGNUM_BASE_BITS - 1; j >= 0; j--) {
        if ((temp >> j) & 1) {
          range_bits = i * BIGNUM_BASE_BITS + j + 1;
          break;
        }
      }
      if (range_bits > 0) break;
    }
  }

  BigNum* rand_val = bn_new();
  BigNum* temp_rem = bn_new();
  BigNum* dummy_q = bn_new();
  if (!rand_val || !temp_rem || !dummy_q) {
    err = BN_ERROR_MEMORY_ALLOC;
    goto cleanup_rand_range;
  }

  // Generate random numbers until one falls within the range
  // rand_val = (random_bits % range)
  // result = min + rand_val
  do {
    err = bn_rand(rand_val, range_bits); // Generate random number of range_bits
    if (err != BN_OK) { goto cleanup_rand_range; }

    // Take rand_val % range
    err = bn_div_mod(dummy_q, temp_rem, rand_val, range);
    if (err != BN_OK) { goto cleanup_rand_range; }
    err = bn_set(rand_val, temp_rem); // rand_val is now in [0, range-1]
    if (err != BN_OK) { goto cleanup_rand_range; }

    // result = min + rand_val
    err = bn_add(num, min, rand_val);
    if (err != BN_OK) { goto cleanup_rand_range; }

  } while (bn_compare(num, max) > 0 || bn_compare(num, min) < 0); // Should not be necessary if mod is correct

cleanup_rand_range:
  bn_free(range);
  bn_free(one);
  bn_free(temp_add);
  bn_free(rand_val);
  bn_free(temp_rem);
  bn_free(dummy_q);

  return err;
}


// rsa.h - Header for RSA library
#ifndef RSA_H
#define RSA_H

#include "bignum.h" // Includes BigNum definitions

// RSA Key Pair Structure
typedef struct {
  BigNum* n; // Modulus (public & private)
  BigNum* e; // Public exponent
  BigNum* d; // Private exponent
  // Optional: p, q, dp, dq, qinv for CRT optimization (not implemented here for simplicity)
} RSA_KeyPair;

// Function to initialize RSA_KeyPair
RSA_KeyPair* rsa_keypair_new();

// Function to free RSA_KeyPair
void rsa_keypair_free(RSA_KeyPair* keypair);

// Key Generation
// bit_length: The desired bit length of the modulus N (N = p*q).
// Typically 1024, 2048, 4096. p and q will be approx bit_length/2.
// iterations: Number of iterations for Miller-Rabin primality test. Higher = more certainty.
BigNumErrorCode rsa_generate_key(RSA_KeyPair* keypair, int bit_length, int iterations);

// Encryption (C = M^e mod N)
// plaintext: The message to encrypt (must be < N)
// ciphertext: The resulting ciphertext
BigNumErrorCode rsa_encrypt(BigNum* ciphertext, const BigNum* plaintext, const RSA_KeyPair* pub_key);

// Decryption (M = C^d mod N)
// ciphertext: The ciphertext to decrypt
// plaintext: The resulting plaintext
BigNumErrorCode rsa_decrypt(BigNum* plaintext, const BigNum* ciphertext, const RSA_KeyPair* priv_key);

#endif // RSA_H


// rsa.c - Implementation of RSA library
#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h> // For srand, time

// Helper function: Miller-Rabin Primality Test
// Returns 1 if num is probably prime, 0 if composite, <0 on error
// num: BigNum to test
// iterations: Number of rounds for the test (higher for more certainty)
int bn_is_prime(const BigNum* num, int iterations) {
    if (!num || bn_is_zero(num) || bn_is_one(num)) return 0; // 0 and 1 are not prime
    if (num->sign == -1) return 0; // Negative numbers are not prime

    // Handle small primes directly for speed
    if (num->size == 1) {
        unsigned int val = num->digits[0];
        if (val == 2 || val == 3 || val == 5 || val == 7) return 1;
        if (val % 2 == 0 || val % 3 == 0 || val % 5 == 0 || val % 7 == 0) return 0;
    }

    // Even numbers greater than 2 are not prime
    if (num->size > 0 && (num->digits[0] % 2 == 0) && (num->digits[0] != 2 || num->size > 1)) {
        return 0;
    }

    // Write num as (2^s) * d + 1 where d is odd
    BigNum* n_minus_1 = bn_new(); // n-1
    BigNum* d = bn_new();         // d
    BigNum* temp = bn_new();
    BigNum* remainder = bn_new();
    BigNum* exp_val = bn_new();   // a^x
    BigNum* two = bn_new(); bn_from_ull(two, 2);
    BigNum* one = bn_new(); bn_set_one(one);

    if (!n_minus_1 || !d || !temp || !remainder || !exp_val || !two || !one) {
        bn_free(n_minus_1); bn_free(d); bn_free(temp); bn_free(remainder);
        bn_free(exp_val); bn_free(two); bn_free(one);
        return -1; // Memory error
    }

    BigNumErrorCode err = bn_sub(n_minus_1, num, one); // n_minus_1 = num - 1
    if (err != BN_OK) { goto cleanup; }

    int s = 0;
    bn_set(d, n_minus_1); // d starts as n-1

    while (d->size > 0 && d->digits[0] % 2 == 0 && !bn_is_zero(d)) {
        err = bn_rshift(temp, d, 1); // d = d / 2
        if (err != BN_OK) { goto cleanup; }
        bn_set(d, temp);
        s++;
    }

    // Loop `iterations` times
    BigNum* a = bn_new();
    BigNum* n_minus_2 = bn_new();
    err = bn_sub(n_minus_2, num, two); // num - 2 for random range [2, num-2]
    if (err != BN_OK) { goto cleanup; }

    for (int k = 0; k < iterations; k++) {
        // Pick a random 'a' in [2, num-2]
        // Note: For very small numbers, num-2 might be < 2 or even negative.
        // We ensure a range that makes sense for Miller-Rabin.
        if (bn_compare(n_minus_2, one) < 0) { // If num-2 is less than 1, (i.e. num < 3)
            if (bn_is_one(num)) { err = BN_ERROR_INVALID_INPUT; goto cleanup; } // Should be caught earlier
            if (bn_compare(num, two) == 0) { err = BN_OK; goto cleanup; } // Special case for 2
        }

        err = bn_rand_range(a, two, n_minus_2); // a is in [2, num-2]
        if (err != BN_OK) { goto cleanup; }
        if (bn_is_zero(a)) { // Should not be zero given range
             bn_set_one(a); // Set to 1 as fallback to prevent issues, though not ideal
        }

        // x = a^d mod num
        err = bn_mod_exp(exp_val, a, d, num);
        if (err != BN_OK) { goto cleanup; }

        if (bn_is_one(exp_val) || bn_compare(exp_val, n_minus_1) == 0) {
            continue; // Probably prime
        }

        int is_composite = 1;
        for (int r = 0; r < s; r++) {
            // exp_val = (exp_val * exp_val) % num
            err = bn_mul(temp, exp_val, exp_val);
            if (err != BN_OK) { goto cleanup; }
            err = bn_div_mod(bn_new(), remainder, temp, num); // Use dummy quotient
            if (err != BN_OK) { goto cleanup; }
            bn_set(exp_val, remainder); // exp_val is now (exp_val^2) % num

            if (bn_is_one(exp_val)) {
                is_composite = 1; // It means it's composite because x^2 = 1 (mod n) but x != +/-1 (mod n)
                break; // Failed test
            }
            if (bn_compare(exp_val, n_minus_1) == 0) {
                is_composite = 0; // Probably prime
                break;
            }
        }

        if (is_composite == 1) { // If the loop finished and didn't find -1 or 1
            err = BN_ERROR_PRIMALITY_TEST_FAILED;
            goto cleanup; // Is composite
        }
    }

cleanup:
    bn_free(n_minus_1);
    bn_free(d);
    bn_free(temp);
    bn_free(remainder);
    bn_free(exp_val);
    bn_free(two);
    bn_free(one);
    bn_free(a);
    bn_free(n_minus_2);

    if (err == BN_OK) return 1; // Probably prime
    if (err == BN_ERROR_PRIMALITY_TEST_FAILED) return 0; // Definitely composite
    return -1; // Other error
}


// RSA Key Pair Functions
RSA_KeyPair* rsa_keypair_new() {
    RSA_KeyPair* keypair = (RSA_KeyPair*)malloc(sizeof(RSA_KeyPair));
    if (!keypair) return NULL;
    keypair->n = bn_new();
    keypair->e = bn_new();
    keypair->d = bn_new();
    if (!keypair->n || !keypair->e || !keypair->d) {
        rsa_keypair_free(keypair); // Free any allocated parts
        return NULL;
    }
    return keypair;
}

void rsa_keypair_free(RSA_KeyPair* keypair) {
    if (keypair) {
        bn_free(keypair->n);
        bn_free(keypair->e);
        bn_free(keypair->d);
        free(keypair);
    }
}

// Key Generation
BigNumErrorCode rsa_generate_key(RSA_KeyPair* keypair, int bit_length, int iterations) {
    if (!keypair || bit_length < 64) return BN_ERROR_INVALID_INPUT;
    if (bit_length / 2 > BIGNUM_MAX_DIGITS * BIGNUM_BASE_BITS) return BN_ERROR_INVALID_KEY_SIZE;

    // Seed the random number generator
    srand((unsigned int)time(NULL));

    int p_bits = bit_length / 2;
    int q_bits = bit_length - p_bits; // q can be slightly larger/smaller than p for security

    BigNum* p = bn_new();
    BigNum* q = bn_new();
    BigNum* one = bn_new(); bn_set_one(one);
    BigNum* phi = bn_new();
    BigNum* p_minus_1 = bn_new();
    BigNum* q_minus_1 = bn_new();
    BigNum* common_divisor = bn_new();
    BigNum* gcd_test = bn_new();

    if (!p || !q || !one || !phi || !p_minus_1 || !q_minus_1 || !common_divisor || !gcd_test) {
        bn_free(p); bn_free(q); bn_free(one); bn_free(phi);
        bn_free(p_minus_1); bn_free(q_minus_1); bn_free(common_divisor); bn_free(gcd_test);
        return BN_ERROR_MEMORY_ALLOC;
    }

    BigNumErrorCode err = BN_OK;

    // 1. Generate two distinct large prime numbers p and q
    // Ensure p and q are large enough and distinct
    printf("Generating prime p (%d bits)...\n", p_bits);
    do {
        err = bn_rand(p, p_bits);
        if (err != BN_OK) goto cleanup;
        if (bn_is_zero(p)) { continue; } // Regenerate if it's somehow zero (very unlikely)
        p->digits[0] |= 1; // Ensure odd
        p->digits[p->size - 1] |= (1U << (p_bits - 1) % BIGNUM_BASE_BITS); // Ensure MSB is set

    } while (bn_is_prime(p, iterations) != 1);
    printf("Prime p generated.\n");
    bn_print("p:", p);


    printf("Generating prime q (%d bits)...\n", q_bits);
    do {
        err = bn_rand(q, q_bits);
        if (err != BN_OK) goto cleanup;
        if (bn_is_zero(q)) { continue; }
        q->digits[0] |= 1; // Ensure odd
        q->digits[q->size - 1] |= (1U << (q_bits - 1) % BIGNUM_BASE_BITS); // Ensure MSB is set

        // Ensure q is distinct from p and not too close (for security, though simple distinct check is enough here)
    } while (bn_is_prime(q, iterations) != 1 || bn_compare(p, q) == 0);
    printf("Prime q generated.\n");
    bn_print("q:", q);

    // 2. Calculate n = p * q
    printf("Calculating n = p * q...\n");
    err = bn_mul(keypair->n, p, q);
    if (err != BN_OK) goto cleanup;
    bn_print("n:", keypair->n);

    // 3. Calculate Euler's totient: phi(n) = (p-1)(q-1)
    printf("Calculating phi(n) = (p-1)(q-1)...\n");
    err = bn_sub(p_minus_1, p, one);
    if (err != BN_OK) goto cleanup;
    err = bn_sub(q_minus_1, q, one);
    if (err != BN_OK) goto cleanup;
    err = bn_mul(phi, p_minus_1, q_minus_1);
    if (err != BN_OK) goto cleanup;
    bn_print("phi:", phi);

    // 4. Choose public exponent e. A common choice is 65537 (0x10001).
    // It must satisfy 1 < e < phi and gcd(e, phi) = 1.
    bn_from_ull(keypair->e, 65537ULL);
    bn_print("e:", keypair->e);

    printf("Checking gcd(e, phi)...\n");
    err = bn_gcd(gcd_test, keypair->e, phi);
    if (err != BN_OK) goto cleanup;
    if (!bn_is_one(gcd_test)) {
        // If gcd is not 1, we must choose another e or retry generation.
        // For simplicity, we just return error, but in real impl, iterate e.
        printf("Error: gcd(e, phi) is not 1. Found: "); bn_print("", gcd_test);
        err = BN_ERROR_INVALID_INPUT; // Could make a custom error
        goto cleanup;
    }
    printf("gcd(e, phi) is 1. OK.\n");

    // 5. Calculate private exponent d = e^-1 mod phi
    printf("Calculating d = e^-1 mod phi...\n");
    err = bn_mod_inverse(keypair->d, keypair->e, phi);
    if (err != BN_OK) {
        printf("Error calculating modular inverse for d.\n");
        goto cleanup;
    }
    bn_print("d:", keypair->d);

    printf("RSA key pair generation complete.\n");

cleanup:
    bn_free(p);
    bn_free(q);
    bn_free(one);
    bn_free(phi);
    bn_free(p_minus_1);
    bn_free(q_minus_1);
    bn_free(common_divisor);
    bn_free(gcd_test);

    return err;
}


// Encryption: C = M^e mod N
BigNumErrorCode rsa_encrypt(BigNum* ciphertext, const BigNum* plaintext, const RSA_KeyPair* pub_key) {
    if (!ciphertext || !plaintext || !pub_key || !pub_key->n || !pub_key->e) {
        return BN_ERROR_INVALID_INPUT;
    }
    if (bn_compare_abs(plaintext, pub_key->n) >= 0) {
        printf("Error: Plaintext must be smaller than modulus N for encryption.\n");
        return BN_ERROR_INVALID_INPUT; // Plaintext too large
    }

    // C = plaintext^e mod n
    return bn_mod_exp(ciphertext, plaintext, pub_key->e, pub_key->n);
}

// Decryption: M = C^d mod N
BigNumErrorCode rsa_decrypt(BigNum* plaintext, const BigNum* ciphertext, const RSA_KeyPair* priv_key) {
    if (!plaintext || !ciphertext || !priv_key || !priv_key->n || !priv_key->d) {
        return BN_ERROR_INVALID_INPUT;
    }
    if (bn_compare_abs(ciphertext, priv_key->n) >= 0) {
        printf("Error: Ciphertext must be smaller than modulus N for decryption.\n");
        return BN_ERROR_INVALID_INPUT; // Ciphertext too large
    }

    // M = ciphertext^d mod n
    return bn_mod_exp(plaintext, ciphertext, priv_key->d, priv_key->n);
}


// main.c - Example usage of BigNum and RSA libraries
#include "bignum.h"
#include "rsa.h"
#include <stdio.h>
#include <string.h>
#include <time.h> // For srand

int main() {
    // Seed the random number generator
    srand((unsigned int)time(NULL));

    printf("--- BigNum and RSA Library Example ---\n\n");

    // --- BigNum Example ---
    printf("--- BigNum Arithmetic Test ---\n");
    BigNum* num1 = bn_new();
    BigNum* num2 = bn_new();
    BigNum* result = bn_new();
    BigNum* quotient = bn_new();
    BigNum* remainder = bn_new();
    BigNum* gcd_res = bn_new();
    BigNum* inv_res = bn_new();
    BigNumErrorCode err;

    if (!num1 || !num2 || !result || !quotient || !remainder || !gcd_res || !inv_res) {
        fprintf(stderr, "Memory allocation failed in main.\n");
        return 1;
    }

    // Addition
    bn_from_string(num1, "0x123456789ABCDEF0");
    bn_from_string(num2, "0xFEDCBA9876543210");
    bn_add(result, num1, num2);
    bn_print("Num1:", num1);
    bn_print("Num2:", num2);
    bn_print("Sum :", result); // Expected: 0x111111111111111100

    // Subtraction
    bn_from_string(num1, "0x10000000000000000"); // 2^64
    bn_from_string(num2, "0x1");
    bn_sub(result, num1, num2);
    bn_print("Num1:", num1);
    bn_print("Num2:", num2);
    bn_print("Diff:", result); // Expected: 0xFFFFFFFFFFFFFFFF

    // Multiplication
    bn_from_string(num1, "0x10"); // 16
    bn_from_string(num2, "0x20"); // 32
    bn_mul(result, num1, num2);
    bn_print("Num1:", num1);
    bn_print("Num2:", num2);
    bn_print("Prod:", result); // Expected: 0x320 (512)

    // Division and Modulus
    bn_from_string(num1, "0x123456789ABCDEF0");
    bn_from_string(num2, "0x1000"); // 4096
    err = bn_div_mod(quotient, remainder, num1, num2);
    if (err == BN_OK) {
        bn_print("Dividend:", num1);
        bn_print("Divisor :", num2);
        bn_print("Quotient:", quotient);
        bn_print("Remainder:", remainder);
    } else {
        printf("Division error: %d\n", err);
    }

    // Modular Exponentiation
    bn_from_ull(num1, 7ULL); // Base
    bn_from_ull(num2, 11ULL); // Exponent
    bn_from_ull(result, 13ULL); // Modulus (re-use result for modulus)
    bn_mod_exp(quotient, num1, num2, result); // Reuse quotient for result
    bn_print("Base (7):", num1);
    bn_print("Exp (11):", num2);
    bn_print("Mod (13):", result);
    bn_print("ModExp:", quotient); // Expected: (7^11) % 13 = 10

    // GCD
    bn_from_ull(num1, 48ULL);
    bn_from_ull(num2, 18ULL);
    bn_gcd(gcd_res, num1, num2);
    bn_print("GCD(48, 18):", gcd_res); // Expected: 6

    // Modular Inverse
    bn_from_ull(num1, 3ULL); // a
    bn_from_ull(num2, 11ULL); // m
    err = bn_mod_inverse(inv_res, num1, num2);
    if (err == BN_OK) {
        bn_print("Inverse of 3 mod 11:", inv_res); // Expected: 4 (because 3*4 = 12 = 1 mod 11)
    } else {
        printf("Modular inverse failed: %d\n", err);
    }

    bn_free(num1);
    bn_free(num2);
    bn_free(result);
    bn_free(quotient);
    bn_free(remainder);
    bn_free(gcd_res);
    bn_free(inv_res);


    printf("\n--- RSA Key Generation & Crypto Test ---\n");

    RSA_KeyPair* keypair = rsa_keypair_new();
    if (!keypair) {
        fprintf(stderr, "Failed to create RSA keypair.\n");
        return 1;
    }

    int bit_length = 128; // For demonstration, use a small bit length (e.g., 128 or 256).
                          // For real security, use 1024, 2048, or higher.
    int iterations = 10; // More iterations = higher certainty of primality

    printf("Attempting to generate %d-bit RSA key pair...\n", bit_length);
    err = rsa_generate_key(keypair, bit_length, iterations);

    if (err == BN_OK) {
        printf("\nRSA Key Generation Successful!\n");
        bn_print("Public N:", keypair->n);
        bn_print("Public E:", keypair->e);
        bn_print("Private D:", keypair->d);

        // --- Encryption and Decryption Example ---
        BigNum* message = bn_new();
        BigNum* encrypted_message = bn_new();
        BigNum* decrypted_message = bn_new();

        if (!message || !encrypted_message || !decrypted_message) {
            fprintf(stderr, "Memory allocation failed for messages.\n");
            rsa_keypair_free(keypair);
            return 1;
        }

        // Choose a message less than N
        // For testing, pick a small number
        bn_from_ull(message, 12345ULL);
        bn_print("\nOriginal Message:", message);

        printf("Encrypting message...\n");
        err = rsa_encrypt(encrypted_message, message, keypair);
        if (err == BN_OK) {
            bn_print("Encrypted Message:", encrypted_message);

            printf("Decrypting message...\n");
            err = rsa_decrypt(decrypted_message, encrypted_message, keypair);
            if (err == BN_OK) {
                bn_print("Decrypted Message:", decrypted_message);

                // Verify decryption
                if (bn_compare(message, decrypted_message) == 0) {
                    printf("Decryption successful! Original message matches decrypted message.\n");
                } else {
                    printf("Decryption FAILED! Message mismatch.\n");
                }
            } else {
                printf("RSA Decryption Failed: %d\n", err);
            }
        } else {
            printf("RSA Encryption Failed: %d\n", err);
        }

        bn_free(message);
        bn_free(encrypted_message);
        bn_free(decrypted_message);

    } else {
        printf("\nRSA Key Generation Failed: %d\n", err);
    }

    rsa_keypair_free(keypair);

    return 0;
}

