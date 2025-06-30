// bignum.h - Header file for the Bignum library

#ifndef BIGNUM_H
#define BIGNUM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h> // For CHAR_BIT

// Define the base for our Bignum representation.
// Using unsigned int for digits (e.g., 32-bit or 64-bit depending on platform)
// A base of 2^32 or 2^64 is efficient for CPU operations.
// For simplicity and ease of debugging with printing, we'll use a decimal base
// like 10^9. However, for maximum performance, a power of 2 is preferred.
// Let's use a base that fits within unsigned int for better arithmetic.
// A common choice is 2^30 or 2^32 for 64-bit systems, or 2^16 for 32-bit systems.
// To make it portable and visible in hex, we'll use base 2^16.
#define BIGNUM_BASE 65536         // 2^16, digits are unsigned short (uint16_t) if BIGNUM_DIGIT_SIZE_BITS is 16
#define BIGNUM_DIGIT_BITS 16      // Number of bits per digit
#define BIGNUM_MAX_DIGIT (BIGNUM_BASE - 1) // Maximum value for a single digit

// For clarity and type safety, let's define our digit type
#if BIGNUM_DIGIT_BITS == 16
typedef unsigned short bignum_digit_t; // 2 bytes
#elif BIGNUM_DIGIT_BITS == 32
typedef unsigned int bignum_digit_t;   // 4 bytes
#elif BIGNUM_DIGIT_BITS == 64
typedef unsigned long long bignum_digit_t; // 8 bytes
#else
#error "BIGNUM_DIGIT_BITS must be 16, 32, or 64"
#endif


// Bignum structure
typedef struct {
    bignum_digit_t *digits; // Array of digits
    int size;               // Number of digits currently used
    int capacity;           // Total allocated capacity for digits
    int sign;               // 1 for positive, -1 for negative, 0 for zero
} bignum;

// --- Initialization and Memory Management ---

/**
 * @brief Initializes a bignum structure.
 * Allocates initial memory for digits and sets to zero.
 * @param bn Pointer to the bignum structure.
 */
void bn_init(bignum *bn);

/**
 * @brief Frees memory allocated for a bignum.
 * @param bn Pointer to the bignum structure.
 */
void bn_free(bignum *bn);

/**
 * @brief Resizes the digit array of a bignum.
 * @param bn Pointer to the bignum structure.
 * @param new_capacity The new capacity for the digit array.
 * @return 0 on success, -1 on allocation failure.
 */
int bn_resize(bignum *bn, int new_capacity);

/**
 * @brief Sets a bignum to zero.
 * @param bn Pointer to the bignum structure.
 */
void bn_set_zero(bignum *bn);

/**
 * @brief Copies one bignum to another.
 * @param dest Pointer to the destination bignum.
 * @param src Pointer to the source bignum.
 * @return 0 on success, -1 on allocation failure.
 */
int bn_copy(bignum *dest, const bignum *src);

// --- Conversion Functions ---

/**
 * @brief Converts a string representation to a bignum.
 * Handles positive and negative integers.
 * @param bn Pointer to the bignum structure.
 * @param str The string to convert.
 * @return 0 on success, -1 on error (invalid string or allocation failure).
 */
int bn_from_string(bignum *bn, const char *str);

/**
 * @brief Converts a long long integer to a bignum.
 * @param bn Pointer to the bignum structure.
 * @param val The long long integer to convert.
 * @return 0 on success, -1 on allocation failure.
 */
int bn_from_long_long(bignum *bn, long long val);

/**
 * @brief Converts a bignum to its string representation.
 * @param bn Pointer to the bignum structure.
 * @return A dynamically allocated string, or NULL on error.
 * The caller is responsible for freeing this string.
 */
char *bn_to_string(const bignum *bn);

// --- Utility Functions ---

/**
 * @brief Normalizes a bignum by removing leading zero digits and adjusting size.
 * Also handles setting sign to 0 if the value is zero.
 * @param bn Pointer to the bignum structure.
 */
void bn_normalize(bignum *bn);

/**
 * @brief Compares the absolute values of two bignums.
 * @param a Pointer to the first bignum.
 * @param b Pointer to the second bignum.
 * @return 1 if |a| > |b|, -1 if |a| < |b|, 0 if |a| == |b|.
 */
int bn_abs_compare(const bignum *a, const bignum *b);

/**
 * @brief Compares two bignums.
 * @param a Pointer to the first bignum.
 * @param b Pointer to the second bignum.
 * @return 1 if a > b, -1 if a < b, 0 if a == b.
 */
int bn_compare(const bignum *a, const bignum *b);

/**
 * @brief Checks if a bignum is zero.
 * @param bn Pointer to the bignum structure.
 * @return 1 if bignum is zero, 0 otherwise.
 */
int bn_is_zero(const bignum *bn);

// --- Arithmetic Operations ---

/**
 * @brief Performs addition of two bignums (a + b).
 * Result is stored in 'res'. 'res' can be 'a' or 'b'.
 * @param res Pointer to the bignum to store the result.
 * @param a Pointer to the first operand.
 * @param b Pointer to the second operand.
 * @return 0 on success, -1 on allocation failure.
 */
int bn_add(bignum *res, const bignum *a, const bignum *b);

/**
 * @brief Performs subtraction of two bignums (a - b).
 * Result is stored in 'res'. 'res' can be 'a' or 'b'.
 * @param res Pointer to the bignum to store the result.
 * @param a Pointer to the first operand.
 * @param b Pointer to the second operand.
 * @return 0 on success, -1 on allocation failure.
 */
int bn_sub(bignum *res, const bignum *a, const bignum *b);

/**
 * @brief Performs multiplication of two bignums (a * b).
 * Result is stored in 'res'. 'res' can be 'a' or 'b'.
 * Uses a basic schoolbook multiplication algorithm.
 * @param res Pointer to the bignum to store the result.
 * @param a Pointer to the first operand.
 * @param b Pointer to the second operand.
 * @return 0 on success, -1 on allocation failure.
 */
int bn_mul(bignum *res, const bignum *a, const bignum *b);


// Helper functions for internal use
// These are not exposed in the public API but are used by other bn_* functions.
int _bn_add_abs(bignum *res, const bignum *a, const bignum *b);
int _bn_sub_abs(bignum *res, const bignum *a, const bignum *b);
int _bn_mul_digit(bignum *res, const bignum *a, bignum_digit_t digit);
void _bn_lshift_digits(bignum *res, int num_digits);

#endif // BIGNUM_H


// bignum.c - Source file for the Bignum library

#include "bignum.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h> // For isdigit

// Initial capacity for digits array
#define INITIAL_CAPACITY 8
// Growth factor for reallocation
#define GROWTH_FACTOR 2

// --- Helper Functions (Internal) ---

/**
 * @brief Internal helper to add absolute values of two bignums.
 * Assumes a and b are non-negative. Result stored in res.
 * @param res Pointer to the bignum to store the result.
 * @param a Pointer to the first operand (non-negative).
 * @param b Pointer to the second operand (non-negative).
 * @return 0 on success, -1 on allocation failure.
 */
int _bn_add_abs(bignum *res, const bignum *a, const bignum *b) {
    int max_size = (a->size > b->size ? a->size : b->size);
    // Allocate space for result, potentially one more digit for carry
    if (bn_resize(res, max_size + 1) == -1) {
        return -1;
    }

    bignum_digit_t carry = 0;
    int i;
    for (i = 0; i < max_size; ++i) {
        bignum_digit_t d1 = (i < a->size) ? a->digits[i] : 0;
        bignum_digit_t d2 = (i < b->size) ? b->digits[i] : 0;

        // Sum and carry. Be careful with overflow if BIGNUM_BASE is large.
        // (d1 + d2 + carry) could exceed bignum_digit_t max if BIGNUM_BASE is near its limit.
        // For BIGNUM_BASE = 2^16 and digits being unsigned short, d1+d2+carry can be at most (2^16-1) + (2^16-1) + 1 = 2^17 - 1.
        // This fits in unsigned int (32-bit).
        unsigned int sum = (unsigned int)d1 + d2 + carry;
        res->digits[i] = sum % BIGNUM_BASE;
        carry = sum / BIGNUM_BASE;
    }

    if (carry > 0) {
        res->digits[i] = carry;
        res->size = max_size + 1;
    } else {
        res->size = max_size;
    }

    bn_normalize(res); // Remove any leading zeros (though unlikely for addition, good practice)
    res->sign = 1; // Result of adding absolute values is always positive
    return 0;
}

/**
 * @brief Internal helper to subtract absolute values of two bignums.
 * Assumes |a| >= |b| and both are non-negative. Result stored in res.
 * @param res Pointer to the bignum to store the result.
 * @param a Pointer to the first operand (non-negative, |a| >= |b|).
 * @param b Pointer to the second operand (non-negative).
 * @return 0 on success, -1 on allocation failure.
 */
int _bn_sub_abs(bignum *res, const bignum *a, const bignum *b) {
    if (bn_resize(res, a->size) == -1) {
        return -1;
    }

    int borrow = 0;
    int i;
    for (i = 0; i < a->size; ++i) {
        bignum_digit_t d1 = a->digits[i];
        bignum_digit_t d2 = (i < b->size) ? b->digits[i] : 0;

        // Perform subtraction with borrow.
        // Ensure d1 is effectively greater than d2 by adding BASE if necessary.
        int diff = (int)d1 - (int)d2 - borrow;
        if (diff < 0) {
            diff += BIGNUM_BASE;
            borrow = 1;
        } else {
            borrow = 0;
        }
        res->digits[i] = diff;
    }

    res->size = a->size; // Initial size based on 'a'
    bn_normalize(res); // Remove leading zeros
    res->sign = 1; // Will be adjusted by bn_sub caller if needed
    return 0;
}

/**
 * @brief Multiplies a bignum by a single digit.
 * Result stored in res. res can be same as a.
 * @param res Pointer to the bignum to store the result.
 * @param a Pointer to the operand bignum.
 * @param digit The digit to multiply by.
 * @return 0 on success, -1 on allocation failure.
 */
int _bn_mul_digit(bignum *res, const bignum *a, bignum_digit_t digit) {
    // If original 'res' is 'a', copy 'a' to a temp bignum first to avoid self-modification issues.
    bignum temp_a;
    int is_self_res = (res == a);
    if (is_self_res) {
        bn_init(&temp_a);
        if (bn_copy(&temp_a, a) == -1) {
            return -1;
        }
        a = &temp_a; // Use temp_a for calculations
    }

    if (bn_resize(res, a->size + 1) == -1) {
        if (is_self_res) bn_free(&temp_a);
        return -1;
    }
    res->sign = (a->sign * (digit == 0 ? 0 : 1)); // Set sign based on 'a' and 'digit'
    if (bn_is_zero(a) || digit == 0) {
        bn_set_zero(res);
        if (is_self_res) bn_free(&temp_a);
        return 0;
    }
    res->sign = a->sign; // Result sign same as 'a' if 'digit' is non-zero

    unsigned int carry = 0;
    int i;
    for (i = 0; i < a->size; ++i) {
        // Use unsigned long long for intermediate product to prevent overflow
        unsigned long long product = (unsigned long long)a->digits[i] * digit + carry;
        res->digits[i] = product % BIGNUM_BASE;
        carry = product / BIGNUM_BASE;
    }

    if (carry > 0) {
        res->digits[i] = carry;
        res->size = a->size + 1;
    } else {
        res->size = a->size;
    }

    bn_normalize(res); // Remove any leading zeros
    if (is_self_res) bn_free(&temp_a);
    return 0;
}

/**
 * @brief Left-shifts a bignum by a number of digits (multiplies by BIGNUM_BASE^num_digits).
 * Operates directly on 'res'.
 * @param res Pointer to the bignum to shift.
 * @param num_digits The number of digits to shift by.
 * @return 0 on success, -1 on allocation failure.
 */
void _bn_lshift_digits(bignum *res, int num_digits) {
    if (num_digits <= 0 || bn_is_zero(res)) {
        return;
    }

    if (bn_resize(res, res->size + num_digits) == -1) {
        // Handle error: print message, but continue to avoid crashing.
        // In a production library, propagate error code.
        fprintf(stderr, "Error: Failed to resize bignum during left shift.\n");
        return;
    }

    // Shift existing digits to the left
    for (int i = res->size - 1; i >= 0; --i) {
        res->digits[i + num_digits] = res->digits[i];
    }
    // Fill in the new low-order digits with zeros
    for (int i = 0; i < num_digits; ++i) {
        res->digits[i] = 0;
    }
    res->size += num_digits;
    bn_normalize(res); // Ensure size is correct after shift
}


// --- Initialization and Memory Management ---

void bn_init(bignum *bn) {
    if (bn == NULL) return;
    bn->digits = NULL;
    bn->size = 0;
    bn->capacity = 0;
    bn->sign = 0; // Represents zero
}

void bn_free(bignum *bn) {
    if (bn == NULL) return;
    if (bn->digits != NULL) {
        free(bn->digits);
        bn->digits = NULL;
    }
    bn->size = 0;
    bn->capacity = 0;
    bn->sign = 0;
}

int bn_resize(bignum *bn, int new_capacity) {
    if (new_capacity < 0) new_capacity = 0; // Don't allow negative capacity

    if (new_capacity == bn->capacity) {
        return 0; // No change needed
    }

    bignum_digit_t *new_digits = (bignum_digit_t *)realloc(bn->digits, new_capacity * sizeof(bignum_digit_t));
    if (new_digits == NULL && new_capacity > 0) {
        // Realloc failed, but we needed more space.
        return -1; // Allocation error
    }

    bn->digits = new_digits;
    bn->capacity = new_capacity;
    if (bn->size > bn->capacity) {
        bn->size = bn->capacity; // Trim size if capacity shrinks
    }
    // Initialize newly allocated memory to 0
    if (new_capacity > bn->size) {
        memset(bn->digits + bn->size, 0, (new_capacity - bn->size) * sizeof(bignum_digit_t));
    }
    return 0;
}

void bn_set_zero(bignum *bn) {
    if (bn == NULL) return;
    if (bn->digits != NULL) {
        // Faster to just clear size and sign if digits are still allocated
        // but it's often safer to reallocate or ensure capacity is minimal.
        // For simplicity, we just set size to 0 and sign to 0.
        // The memory isn't freed unless bn_free is called explicitly.
        bn->size = 0;
        bn->sign = 0;
        // Optionally: memset(bn->digits, 0, bn->capacity * sizeof(bignum_digit_t));
    } else {
        bn_init(bn); // Ensure it's initialized if not already
    }
}

int bn_copy(bignum *dest, const bignum *src) {
    if (dest == NULL || src == NULL) return -1;
    if (dest == src) return 0; // Copying to self, nothing to do

    bn_free(dest); // Free existing memory in destination
    bn_init(dest); // Re-initialize destination

    if (src->size == 0) { // Source is zero
        dest->sign = 0;
        dest->size = 0;
        return 0;
    }

    if (bn_resize(dest, src->size) == -1) {
        return -1; // Allocation failure
    }

    memcpy(dest->digits, src->digits, src->size * sizeof(bignum_digit_t));
    dest->size = src->size;
    dest->sign = src->sign;
    return 0;
}

// --- Conversion Functions ---

int bn_from_string(bignum *bn, const char *str) {
    if (bn == NULL || str == NULL) return -1;

    bn_set_zero(bn); // Start fresh

    const char *p = str;
    int str_len = strlen(str);
    int negative = 0;

    // Handle sign
    if (*p == '-') {
        negative = 1;
        p++;
        str_len--;
    } else if (*p == '+') {
        p++;
        str_len--;
    }

    if (str_len == 0) { // Empty string or just a sign
        return -1; // Invalid input
    }

    // Allocate sufficient capacity.
    // Each digit represents BIGNUM_DIGIT_BITS bits.
    // Each character is approx log10(2) bits (0.3 bits per char).
    // So, (str_len * log2(10)) / BIGNUM_DIGIT_BITS is a rough estimate.
    // Or just a generous number based on decimal representation.
    // Example: if BIGNUM_BASE is 2^16 (65536), then 5 decimal digits can fit (log10(65536) approx 4.8).
    // Max capacity: str_len (chars) / log10(BIGNUM_BASE) + 1.
    // For base 10, each digit is BIGNUM_DIGIT_BITS/log2(10) chars.
    // For general base, easier to just go digit by digit.

    // A more practical approach:
    // Initialize with a small capacity, then grow as needed during multiplication.
    // Or, estimate based on BIGNUM_BASE. If BIGNUM_BASE is 10^9, 9 chars per digit.
    // If BIGNUM_BASE is 2^16, about 4.8 decimal digits per bignum_digit_t.
    // So capacity = (str_len / 4) + 2 is a safe upper bound for 2^16.
    int estimated_capacity = (str_len / (BIGNUM_DIGIT_BITS / 4)) + 2; // Rough estimation for 2^16 base
    if (bn_resize(bn, estimated_capacity) == -1) {
        return -1;
    }


    // Build the number digit by digit (from string)
    bignum_digit_t val_char;
    bignum temp_bn; // Temporary bignum for multiplication by base 10
    bignum digit_bn; // Temporary bignum for current digit
    bignum base_10; // For multiplication by 10

    bn_init(&temp_bn);
    bn_init(&digit_bn);
    bn_init(&base_10);
    bn_from_long_long(&base_10, 10); // Base 10 for string conversion

    // Iterate through characters of the string
    for (int i = 0; i < str_len; ++i) {
        if (!isdigit(p[i])) {
            bn_free(&temp_bn);
            bn_free(&digit_bn);
            bn_free(&base_10);
            bn_free(bn); // Clean up partially built bignum
            return -1; // Invalid character
        }

        val_char = p[i] - '0'; // Convert char to integer digit

        // current_bn = current_bn * 10 + val_char
        // 1. Multiply current_bn by 10
        if (bn_mul(&temp_bn, bn, &base_10) == -1) {
            bn_free(&temp_bn); bn_free(&digit_bn); bn_free(&base_10); bn_free(bn); return -1;
        }
        // 2. Add current character value
        if (bn_from_long_long(&digit_bn, val_char) == -1) { // Convert char digit to bignum
            bn_free(&temp_bn); bn_free(&digit_bn); bn_free(&base_10); bn_free(bn); return -1;
        }
        if (bn_add(bn, &temp_bn, &digit_bn) == -1) { // Add to current number
            bn_free(&temp_bn); bn_free(&digit_bn); bn_free(&base_10); bn_free(bn); return -1;
        }
    }

    if (negative && !bn_is_zero(bn)) {
        bn->sign = -1;
    } else if (bn_is_zero(bn)) {
        bn->sign = 0;
    } else {
        bn->sign = 1;
    }

    bn_free(&temp_bn);
    bn_free(&digit_bn);
    bn_free(&base_10);
    return 0;
}

int bn_from_long_long(bignum *bn, long long val) {
    if (bn == NULL) return -1;

    bn_set_zero(bn);

    if (val == 0) {
        bn->sign = 0;
        return 0;
    }

    if (val < 0) {
        bn->sign = -1;
        val = -val; // Work with absolute value
    } else {
        bn->sign = 1;
    }

    long long temp_val = val;
    int count = 0;
    // Count how many digits are needed
    do {
        temp_val /= BIGNUM_BASE;
        count++;
    } while (temp_val > 0);

    if (bn_resize(bn, count) == -1) {
        return -1;
    }

    temp_val = val; // Reset to original absolute value
    int i = 0;
    do {
        bn->digits[i++] = temp_val % BIGNUM_BASE;
        temp_val /= BIGNUM_BASE;
    } while (temp_val > 0);

    bn->size = i;
    bn_normalize(bn);
    return 0;
}

char *bn_to_string(const bignum *bn) {
    if (bn == NULL) return NULL;

    if (bn_is_zero(bn)) {
        char *str = (char *)malloc(2); // "0\0"
        if (str) strcpy(str, "0");
        return str;
    }

    // Max length of string: (number of digits * log10(BASE)) + sign + null terminator
    // For BASE 2^16, log10(65536) is approx 4.8. So each digit can contribute up to 5 chars.
    int max_str_len = bn->size * 5 + 2; // +1 for sign, +1 for null terminator
    char *str = (char *)malloc(max_str_len);
    if (str == NULL) return NULL;

    // Use a temporary bignum for division operations
    bignum temp_bn;
    bn_init(&temp_bn);
    if (bn_copy(&temp_bn, bn) == -1) {
        free(str);
        bn_free(&temp_bn);
        return NULL;
    }
    temp_bn.sign = 1; // Work with absolute value for division

    bignum base_10;
    bn_init(&base_10);
    bn_from_long_long(&base_10, 10);

    char *p = str + max_str_len - 1; // Start from end of buffer for null terminator
    *p-- = '\0'; // Null terminator

    bignum remainder_bn;
    bn_init(&remainder_bn);
    bignum quotient_bn;
    bn_init(&quotient_bn);

    if (bn->size == 0 && bn->sign == 0) { // Edge case: bn is effectively zero
        *p-- = '0';
    } else {
        // Repeatedly divide by 10 and take the remainder
        while (!bn_is_zero(&temp_bn)) {
            // Simplified division by 10.
            // This is a slow operation, converting digit by digit.
            // For a robust implementation, a proper bignum division function is needed.
            // For now, we simulate by hand for string conversion.
            bignum_digit_t remainder = 0;
            for (int i = temp_bn.size - 1; i >= 0; --i) {
                unsigned long long current_val = (unsigned long long)remainder * BIGNUM_BASE + temp_bn.digits[i];
                temp_bn.digits[i] = current_val / 10;
                remainder = current_val % 10;
            }
            bn_normalize(&temp_bn);

            *p-- = (remainder % 10) + '0'; // Store remainder as character
            if (p < str && !bn_is_zero(&temp_bn)) {
                // Buffer too small, should not happen with generous max_str_len
                fprintf(stderr, "Error: String buffer overflow in bn_to_string.\n");
                bn_free(&temp_bn); bn_free(&base_10); bn_free(&remainder_bn); bn_free(&quotient_bn);
                free(str);
                return NULL;
            }
        }
    }


    if (bn->sign == -1) {
        *p-- = '-';
    }

    // Move the string to the beginning of the buffer
    memmove(str, p + 1, max_str_len - (p + 1 - str));

    bn_free(&temp_bn);
    bn_free(&base_10);
    bn_free(&remainder_bn);
    bn_free(&quotient_bn);
    return str;
}


// --- Utility Functions ---

void bn_normalize(bignum *bn) {
    if (bn == NULL) return;

    // Remove leading zero digits
    while (bn->size > 0 && bn->digits[bn->size - 1] == 0) {
        bn->size--;
    }

    // If all digits are zero, set sign to 0 (representing the number zero)
    if (bn->size == 0) {
        bn->sign = 0;
    }
}

int bn_abs_compare(const bignum *a, const bignum *b) {
    if (bn_is_zero(a) && bn_is_zero(b)) return 0;
    if (bn_is_zero(a)) return -1; // |0| < |b| (if b != 0)
    if (bn_is_zero(b)) return 1;  // |a| > |0| (if a != 0)

    if (a->size > b->size) return 1;
    if (a->size < b->size) return -1;

    // Sizes are equal, compare digit by digit from most significant
    for (int i = a->size - 1; i >= 0; --i) {
        if (a->digits[i] > b->digits[i]) return 1;
        if (a->digits[i] < b->digits[i]) return -1;
    }
    return 0; // Absolute values are equal
}

int bn_compare(const bignum *a, const bignum *b) {
    if (bn_is_zero(a) && bn_is_zero(b)) return 0;

    // Different signs
    if (a->sign == 1 && b->sign == -1) return 1;  // Positive > Negative
    if (a->sign == -1 && b->sign == 1) return -1; // Negative < Positive

    // Same signs
    if (a->sign == 1 && b->sign == 1) { // Both positive
        return bn_abs_compare(a, b);
    } else if (a->sign == -1 && b->sign == -1) { // Both negative
        // For negative numbers, smaller absolute value means larger number (e.g., -5 > -10)
        return -bn_abs_compare(a, b);
    }

    // One is zero, the other is not
    if (bn_is_zero(a)) { // a is 0, b is not 0
        return (b->sign == 1) ? -1 : 1; // 0 < positive, 0 > negative
    }
    if (bn_is_zero(b)) { // b is 0, a is not 0
        return (a->sign == 1) ? 1 : -1; // Positive > 0, Negative < 0
    }

    return 0; // Should not reach here, but for completeness.
}

int bn_is_zero(const bignum *bn) {
    return (bn->size == 0 && bn->sign == 0);
}

// --- Arithmetic Operations ---

int bn_add(bignum *res, const bignum *a, const bignum *b) {
    // Handle cases involving zero operands
    if (bn_is_zero(a)) {
        return bn_copy(res, b);
    }
    if (bn_is_zero(b)) {
        return bn_copy(res, a);
    }

    // Case 1: Same signs (addition of absolute values)
    if (a->sign == b->sign) {
        int ret = _bn_add_abs(res, a, b);
        res->sign = a->sign; // Result sign is same as operands
        return ret;
    } else { // Case 2: Different signs (subtraction of absolute values)
        int cmp_abs = bn_abs_compare(a, b);
        if (cmp_abs == 0) { // Absolute values are equal (e.g., 5 + (-5) = 0)
            bn_set_zero(res);
            return 0;
        } else if (cmp_abs > 0) { // |a| > |b| (e.g., 10 + (-5) = 5 or -10 + 5 = -5)
            int ret = _bn_sub_abs(res, a, b);
            res->sign = a->sign; // Result sign is same as the larger absolute value
            return ret;
        } else { // |a| < |b| (e.g., 5 + (-10) = -5 or -5 + 10 = 5)
            int ret = _bn_sub_abs(res, b, a); // Subtract smaller from larger
            res->sign = b->sign; // Result sign is same as the larger absolute value
            return ret;
        }
    }
}

int bn_sub(bignum *res, const bignum *a, const bignum *b) {
    // Handle cases involving zero operands
    if (bn_is_zero(b)) { // a - 0 = a
        return bn_copy(res, a);
    }
    if (bn_is_zero(a)) { // 0 - b = -b
        int ret = bn_copy(res, b);
        if (!bn_is_zero(res)) {
            res->sign = -(b->sign); // Flip sign of b
        }
        return ret;
    }

    // If a and b have the same sign:
    // (A - B) where A, B > 0 -> A - B
    // (-A - (-B)) where A, B > 0 -> -A + B = B - A
    if (a->sign == b->sign) {
        int cmp_abs = bn_abs_compare(a, b);
        if (cmp_abs == 0) { // |a| == |b|, same signs (e.g., 5-5=0, -5-(-5)=0)
            bn_set_zero(res);
            return 0;
        } else if (cmp_abs > 0) { // |a| > |b|
            int ret = _bn_sub_abs(res, a, b);
            res->sign = a->sign; // Sign is same as 'a'
            return ret;
        } else { // |a| < |b|
            int ret = _bn_sub_abs(res, b, a); // Compute |b| - |a|
            res->sign = -(a->sign); // Sign is opposite of 'a'
            return ret;
        }
    } else { // Different signs: a is positive, b is negative, or vice versa
        // (A - (-B)) = A + B
        // (-A - B) = -(A + B)
        int ret = _bn_add_abs(res, a, b); // Always add absolute values
        res->sign = a->sign; // Sign is same as 'a'
        return ret;
    }
}

int bn_mul(bignum *res, const bignum *a, const bignum *b) {
    // Handle zero operands
    if (bn_is_zero(a) || bn_is_zero(b)) {
        bn_set_zero(res);
        return 0;
    }

    // Determine the sign of the result
    res->sign = (a->sign == b->sign) ? 1 : -1;

    // Temporary storage for intermediate sums
    // Allocate enough space: sum of sizes of 'a' and 'b' is max possible size
    int result_max_size = a->size + b->size;
    bignum_digit_t *temp_digits = (bignum_digit_t *)calloc(result_max_size, sizeof(bignum_digit_t));
    if (temp_digits == NULL) {
        return -1; // Allocation error
    }

    // Schoolbook multiplication
    // Iterate through digits of 'a'
    for (int i = 0; i < a->size; ++i) {
        unsigned int carry = 0;
        // Iterate through digits of 'b'
        for (int j = 0; j < b->size; ++j) {
            // (unsigned long long) is critical to prevent overflow during product calculation
            unsigned long long product = (unsigned long long)a->digits[i] * b->digits[j] + temp_digits[i + j] + carry;
            temp_digits[i + j] = product % BIGNUM_BASE;
            carry = product / BIGNUM_BASE;
        }
        // Propagate the final carry
        if (carry > 0) {
            temp_digits[i + b->size] += carry; // Add to the next position
        }
    }

    // Copy temp_digits to res and set its size
    if (bn_resize(res, result_max_size) == -1) {
        free(temp_digits);
        return -1;
    }
    memcpy(res->digits, temp_digits, result_max_size * sizeof(bignum_digit_t));
    res->size = result_max_size;
    free(temp_digits);

    bn_normalize(res); // Remove leading zeros if any (e.g., 1*1 results in size 2, but only 1 digit needed)
    return 0;
}


// --- main.c - Example Usage for Bignum Library ---

#include "bignum.h"
#include <stdio.h>
#include <string.h>

// Helper function to print a bignum and its string representation
void print_bignum(const char *name, const bignum *bn) {
    char *str = bn_to_string(bn);
    if (str) {
        printf("%s = %s (size: %d, capacity: %d, sign: %d)\n", name, str, bn->size, bn->capacity, bn->sign);
        free(str);
    } else {
        printf("%s: Error converting to string or NULL bignum.\n", name);
    }
}

// Function to test an operation and print results
void test_operation(const char *op_name, bignum *a, bignum *b, bignum *res, int (*op_func)(bignum*, const bignum*, const bignum*)) {
    char *str_a = bn_to_string(a);
    char *str_b = bn_to_string(b);
    if (str_a && str_b) {
        printf("\n--- Testing %s: (%s) %s (%s) ---\n", op_name, str_a, op_name, str_b);
        free(str_a);
        free(str_b);
    } else {
        printf("\n--- Testing %s ---\n", op_name);
    }

    if (op_func(res, a, b) == 0) {
        print_bignum("Result", res);
    } else {
        printf("Operation failed!\n");
    }
}


int main() {
    bignum num1, num2, num3, res;
    bn_init(&num1);
    bn_init(&num2);
    bn_init(&num3);
    bn_init(&res);

    printf("--- Bignum Library Test ---\n");

    // Test bn_from_string and bn_to_string
    printf("\n--- String Conversion Tests ---\n");
    if (bn_from_string(&num1, "12345678901234567890") == 0) {
        print_bignum("num1", &num1);
    } else {
        printf("Failed to convert string to num1.\n");
    }

    if (bn_from_string(&num2, "-9876543210987654321") == 0) {
        print_bignum("num2", &num2);
    } else {
        printf("Failed to convert string to num2.\n");
    }

    if (bn_from_string(&num3, "0") == 0) {
        print_bignum("num3", &num3);
    } else {
        printf("Failed to convert string to num3.\n");
    }

    if (bn_from_string(&res, "1") == 0) {
        print_bignum("res (initially)", &res);
    } else {
        printf("Failed to convert string to res.\n");
    }

    // Test bn_from_long_long
    printf("\n--- Long Long Conversion Tests ---\n");
    bignum ll_test; bn_init(&ll_test);
    bn_from_long_long(&ll_test, 123456789LL);
    print_bignum("ll_test (positive)", &ll_test);
    bn_from_long_long(&ll_test, -987654321LL);
    print_bignum("ll_test (negative)", &ll_test);
    bn_from_long_long(&ll_test, 0LL);
    print_bignum("ll_test (zero)", &ll_test);
    bn_free(&ll_test);


    // Test Addition
    test_operation("Add", &num1, &num2, &res, bn_add); // 123... - 98...
    bn_from_string(&num1, "5000000000000000000"); // 5 * 10^18
    bn_from_string(&num2, "5000000000000000000"); // 5 * 10^18
    test_operation("Add", &num1, &num2, &res, bn_add); // 10 * 10^18
    bn_from_string(&num1, "1000");
    bn_from_string(&num2, "200");
    test_operation("Add", &num1, &num2, &res, bn_add); // 1200
    bn_from_string(&num1, "100");
    bn_from_string(&num2, "-200");
    test_operation("Add", &num1, &num2, &res, bn_add); // -100
    bn_from_string(&num1, "-100");
    bn_from_string(&num2, "200");
    test_operation("Add", &num1, &num2, &res, bn_add); // 100
    bn_from_string(&num1, "-100");
    bn_from_string(&num2, "-200");
    test_operation("Add", &num1, &num2, &res, bn_add); // -300
    bn_from_string(&num1, "12345");
    bn_from_string(&num2, "0");
    test_operation("Add (with zero)", &num1, &num2, &res, bn_add); // 12345
    bn_from_string(&num1, "0");
    bn_from_string(&num2, "56789");
    test_operation("Add (zero with num)", &num1, &num2, &res, bn_add); // 56789


    // Test Subtraction
    bn_from_string(&num1, "1000");
    bn_from_string(&num2, "200");
    test_operation("Subtract", &num1, &num2, &res, bn_sub); // 800
    bn_from_string(&num1, "200");
    bn_from_string(&num2, "1000");
    test_operation("Subtract", &num1, &num2, &res, bn_sub); // -800
    bn_from_string(&num1, "100");
    bn_from_string(&num2, "-200");
    test_operation("Subtract", &num1, &num2, &res, bn_sub); // 300 (100 - (-200))
    bn_from_string(&num1, "-100");
    bn_from_string(&num2, "200");
    test_operation("Subtract", &num1, &num2, &res, bn_sub); // -300 (-100 - 200)
    bn_from_string(&num1, "-100");
    bn_from_string(&num2, "-200");
    test_operation("Subtract", &num1, &num2, &res, bn_sub); // 100 (-100 - (-200))
    bn_from_string(&num1, "5000000000000000000");
    bn_from_string(&num2, "1000000000000000000");
    test_operation("Subtract", &num1, &num2, &res, bn_sub); // 4 * 10^18
    bn_from_string(&num1, "12345");
    bn_from_string(&num2, "0");
    test_operation("Subtract (with zero)", &num1, &num2, &res, bn_sub); // 12345
    bn_from_string(&num1, "0");
    bn_from_string(&num2, "56789");
    test_operation("Subtract (zero with num)", &num1, &num2, &res, bn_sub); // -56789


    // Test Multiplication
    bn_from_string(&num1, "123");
    bn_from_string(&num2, "45");
    test_operation("Multiply", &num1, &num2, &res, bn_mul); // 123 * 45 = 5535
    bn_from_string(&num1, "123456789");
    bn_from_string(&num2, "987654321");
    test_operation("Multiply", &num1, &num2, &res, bn_mul); // large numbers
    bn_from_string(&num1, "100");
    bn_from_string(&num2, "-5");
    test_operation("Multiply", &num1, &num2, &res, bn_mul); // -500
    bn_from_string(&num1, "-10");
    bn_from_string(&num2, "-20");
    test_operation("Multiply", &num1, &num2, &res, bn_mul); // 200
    bn_from_string(&num1, "0");
    bn_from_string(&num2, "12345");
    test_operation("Multiply (by zero)", &num1, &num2, &res, bn_mul); // 0
    bn_from_string(&num1, "1");
    bn_from_string(&num2, "1");
    test_operation("Multiply (1*1)", &num1, &num2, &res, bn_mul); // 1


    // Test Comparison
    printf("\n--- Comparison Tests ---\n");
    bn_from_string(&num1, "12345");
    bn_from_string(&num2, "12345");
    printf("12345 vs 12345: %d (expected 0)\n", bn_compare(&num1, &num2));
    bn_from_string(&num2, "1234");
    printf("12345 vs 1234: %d (expected 1)\n", bn_compare(&num1, &num2));
    bn_from_string(&num2, "123456");
    printf("12345 vs 123456: %d (expected -1)\n", bn_compare(&num1, &num2));
    bn_from_string(&num1, "-100");
    bn_from_string(&num2, "-200");
    printf("-100 vs -200: %d (expected 1)\n", bn_compare(&num1, &num2));
    bn_from_string(&num1, "-200");
    bn_from_string(&num2, "-100");
    printf("-200 vs -100: %d (expected -1)\n", bn_compare(&num1, &num2));
    bn_from_string(&num1, "100");
    bn_from_string(&num2, "-100");
    printf("100 vs -100: %d (expected 1)\n", bn_compare(&num1, &num2));
    bn_from_string(&num1, "0");
    bn_from_string(&num2, "0");
    printf("0 vs 0: %d (expected 0)\n", bn_compare(&num1, &num2));
    bn_from_string(&num1, "0");
    bn_from_string(&num2, "5");
    printf("0 vs 5: %d (expected -1)\n", bn_compare(&num1, &num2));
    bn_from_string(&num1, "0");
    bn_from_string(&num2, "-5");
    printf("0 vs -5: %d (expected 1)\n", bn_compare(&num1, &num2));


    // Clean up
    bn_free(&num1);
    bn_free(&num2);
    bn_free(&num3);
    bn_free(&res);

    printf("\n--- All tests completed ---\n");

    return 0;
}

