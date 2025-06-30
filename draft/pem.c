#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// --- Base64 Encoding/Decoding Functions ---

// Base64 table
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Function to encode data to Base64
// Returns a dynamically allocated string, caller must free it.
// Returns NULL on error.
char* base64_encode(const unsigned char* data, size_t input_length) {
    size_t output_length = 4 * ((input_length + 2) / 3);
    char* encoded_data = (char*)malloc(output_length + 1);
    if (encoded_data == NULL) return NULL;

    int i = 0, j = 0;
    for (i = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = base64_chars[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 0 * 6) & 0x3F];
    }

    // Handle padding
    switch (input_length % 3) {
        case 1:
            encoded_data[j - 1] = '=';
        case 2:
            encoded_data[j - 2] = '=';
            break;
    }
    encoded_data[j] = '\0';

    return encoded_data;
}

// Function to get index of Base64 character (helper for decoding)
static int base64_char_to_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return 0; // Padding character, treated as 0 for calculation
    return -1; // Invalid character
}

// Function to decode Base64 data
// Returns a dynamically allocated unsigned char array, caller must free it.
// Sets decoded_length to the length of the decoded data.
// Returns NULL on error.
unsigned char* base64_decode(const char* data, size_t* decoded_length) {
    size_t input_length = strlen(data);
    if (input_length % 4 != 0) {
        fprintf(stderr, "Error: Base64 input length not a multiple of 4.\n");
        return NULL;
    }

    // Calculate expected output length (approx)
    size_t temp_output_length = (input_length / 4) * 3;
    unsigned char* decoded_data = (unsigned char*)malloc(temp_output_length);
    if (decoded_data == NULL) return NULL;

    *decoded_length = 0;
    int i = 0, j = 0;

    for (i = 0; i < input_length;) {
        int val_a = base64_char_to_val(data[i++]);
        int val_b = base64_char_to_val(data[i++]);
        int val_c = base64_char_to_val(data[i++]);
        int val_d = base64_char_to_val(data[i++]);

        if (val_a == -1 || val_b == -1 || val_c == -1 || val_d == -1) {
            fprintf(stderr, "Error: Invalid Base64 character found.\n");
            free(decoded_data);
            return NULL;
        }

        uint32_t triple = (val_a << 3 * 6) + (val_b << 2 * 6) + (val_c << 1 * 6) + (val_d << 0 * 6);

        // Check for padding and append bytes
        if (data[i - 2] != '=') { // If not a padding char
            decoded_data[j++] = (triple >> 0x10) & 0xFF;
            (*decoded_length)++;
        }
        if (data[i - 1] != '=') { // If not a padding char
            decoded_data[j++] = (triple >> 0x08) & 0xFF;
            (*decoded_length)++;
        }
        if (data[i - 1] != '=') { // If not a padding char
            decoded_data[j++] = (triple >> 0x00) & 0xFF;
            (*decoded_length)++;
        }
    }

    // Reallocate to exact size if needed (optional, but good practice)
    unsigned char* final_decoded_data = (unsigned char*)realloc(decoded_data, *decoded_length);
    if (final_decoded_data == NULL && *decoded_length > 0) { // realloc can return NULL if size is 0
        // Realloc failed, but decoded_data might still be valid if size > 0
        // Or handle based on specific memory management strategy
        return decoded_data;
    }
    return final_decoded_data ? final_decoded_data : decoded_data; // return decoded_data if realloc fails on non-zero size
}

// --- Simplified DER Encoding/Decoding (for OCTET STRING) ---

// Function to encode a raw byte array as a DER OCTET STRING (tag 0x04)
// This is a very simplified DER encoder. Real DER involves complex ASN.1 structures.
// Returns a dynamically allocated unsigned char array, caller must free it.
// Sets der_length to the length of the DER data.
// Returns NULL on error.
unsigned char* der_encode_octet_string(const unsigned char* raw_data, size_t raw_data_length, size_t* der_length) {
    // DER format for OCTET STRING:
    // Tag: 0x04 (OCTET STRING)
    // Length: can be 1 to 4 bytes for lengths up to 2^32-1.
    //         Short form: 1 byte (0-127)
    //         Long form: 1 byte (0x80 | num_bytes_for_length) followed by length bytes
    // Value: The raw data

    size_t length_bytes_count;
    unsigned char length_bytes[4]; // Max 4 bytes for length (for lengths up to 2^32-1)

    if (raw_data_length < 128) {
        length_bytes_count = 1;
        length_bytes[0] = (unsigned char)raw_data_length;
    } else if (raw_data_length < 256) { // Length fits in 1 byte, but needs long form header
        length_bytes_count = 2;
        length_bytes[0] = 0x81;
        length_bytes[1] = (unsigned char)raw_data_length;
    } else if (raw_data_length < 65536) { // Length fits in 2 bytes
        length_bytes_count = 3;
        length_bytes[0] = 0x82;
        length_bytes[1] = (unsigned char)((raw_data_length >> 8) & 0xFF);
        length_bytes[2] = (unsigned char)(raw_data_length & 0xFF);
    } else {
        // For simplicity, we'll cap at 2-byte length encoding for this example.
        // A full implementation would handle 3 and 4 byte lengths for larger data.
        fprintf(stderr, "Error: Raw data too large for this simplified DER encoder.\n");
        return NULL;
    }

    *der_length = 1 + length_bytes_count + raw_data_length; // Tag + Length Bytes + Value
    unsigned char* der_data = (unsigned char*)malloc(*der_length);
    if (der_data == NULL) return NULL;

    der_data[0] = 0x04; // ASN.1 Tag for OCTET STRING
    memcpy(der_data + 1, length_bytes, length_bytes_count);
    memcpy(der_data + 1 + length_bytes_count, raw_data, raw_data_length);

    return der_data;
}

// Function to decode a simplified DER OCTET STRING
// Extracts the raw data from a DER OCTET STRING.
// Returns a dynamically allocated unsigned char array, caller must free it.
// Sets extracted_length to the length of the extracted raw data.
// Returns NULL on error or if the DER is not a simple OCTET STRING.
unsigned char* der_decode_octet_string(const unsigned char* der_data, size_t der_data_length, size_t* extracted_length) {
    if (der_data_length < 2) {
        fprintf(stderr, "Error: DER data too short.\n");
        return NULL;
    }

    if (der_data[0] != 0x04) { // Check for OCTET STRING tag
        fprintf(stderr, "Error: Not a DER OCTET STRING (tag 0x04).\n");
        return NULL;
    }

    size_t length_byte_start = 1;
    size_t data_offset;
    size_t len = 0;

    if ((der_data[length_byte_start] & 0x80) == 0) { // Short form length
        len = der_data[length_byte_start];
        data_offset = length_byte_start + 1;
    } else { // Long form length
        size_t num_length_bytes = der_data[length_byte_start] & 0x7F;
        if (num_length_bytes == 0 || num_length_bytes > 2) { // Max 2 bytes for this example
            fprintf(stderr, "Error: Unsupported DER length byte format or too many length bytes.\n");
            return NULL;
        }
        if (der_data_length < length_byte_start + 1 + num_length_bytes) {
            fprintf(stderr, "Error: DER data truncated, length bytes missing.\n");
            return NULL;
        }

        for (size_t i = 0; i < num_length_bytes; ++i) {
            len = (len << 8) | der_data[length_byte_start + 1 + i];
        }
        data_offset = length_byte_start + 1 + num_length_bytes;
    }

    if (der_data_length < data_offset + len) {
        fprintf(stderr, "Error: DER data truncated, value missing.\n");
        return NULL;
    }

    *extracted_length = len;
    unsigned char* raw_data = (unsigned char*)malloc(*extracted_length);
    if (raw_data == NULL) return NULL;

    memcpy(raw_data, der_data + data_offset, *extracted_length);
    return raw_data;
}


// --- PEM Formatting Functions ---

// Function to wrap Base64 data with PEM headers/footers
// Returns a dynamically allocated string, caller must free it.
// Returns NULL on error.
char* pem_encode(const char* base64_data, const char* type) {
    if (!base64_data || !type) return NULL;

    char header[100];
    char footer[100];
    snprintf(header, sizeof(header), "-----BEGIN %s-----\n", type);
    snprintf(footer, sizeof(footer), "-----END %s-----\n", type);

    size_t header_len = strlen(header);
    size_t footer_len = strlen(footer);
    size_t base64_len = strlen(base64_data);

    // PEM lines are typically 64 characters long, plus newline
    size_t line_length = 64;
    size_t num_lines = (base64_len + line_length - 1) / line_length;
    size_t newlines_len = num_lines; // one newline per line

    size_t pem_len = header_len + base64_len + newlines_len + footer_len;
    char* pem_data = (char*)malloc(pem_len + 1);
    if (pem_data == NULL) return NULL;

    strcpy(pem_data, header);
    char* current_pos = pem_data + header_len;

    // Add Base64 data with line breaks
    for (size_t i = 0; i < base64_len; i += line_length) {
        size_t chunk_len = (i + line_length > base64_len) ? (base64_len - i) : line_length;
        memcpy(current_pos, base64_data + i, chunk_len);
        current_pos += chunk_len;
        *current_pos++ = '\n';
    }

    strcpy(current_pos, footer);
    return pem_data;
}

// Function to unwrap PEM data, returning the contained Base64 string
// Returns a dynamically allocated string, caller must free it.
// Sets type to a dynamically allocated string containing the PEM type (e.g., "PRIVATE KEY"). Caller must free it.
// Returns NULL on error or if the PEM format is invalid.
char* pem_decode(const char* pem_data, char** type) {
    if (!pem_data) return NULL;

    char* start_tag = strstr(pem_data, "-----BEGIN ");
    if (!start_tag) return NULL;
    start_tag += strlen("-----BEGIN "); // Move past "-----BEGIN "

    char* end_tag_line = strstr(start_tag, "-----\n");
    if (!end_tag_line) return NULL;

    size_t type_len = end_tag_line - start_tag;
    *type = (char*)malloc(type_len + 1);
    if (!*type) return NULL;
    memcpy(*type, start_tag, type_len);
    (*type)[type_len] = '\0';

    char* base64_start = end_tag_line + strlen("-----\n");
    char footer_prefix[100];
    snprintf(footer_prefix, sizeof(footer_prefix), "-----END %s-----", *type);
    char* base64_end = strstr(base64_start, footer_prefix);
    if (!base64_end) {
        free(*type);
        return NULL;
    }

    // Extract raw Base64 data, skipping newlines and whitespace
    size_t raw_base64_len = base64_end - base64_start;
    char* temp_base64 = (char*)malloc(raw_base64_len + 1);
    if (!temp_base64) {
        free(*type);
        return NULL;
    }

    size_t k = 0;
    for (size_t i = 0; i < raw_base64_len; ++i) {
        if (base64_start[i] != '\n' && base64_start[i] != '\r' && base64_start[i] != ' ' && base64_start[i] != '\t') {
            temp_base64[k++] = base64_start[i];
        }
    }
    temp_base64[k] = '\0';

    // Reallocate to the actual length
    char* final_base64 = (char*)realloc(temp_base64, k + 1);
    if (!final_base64) {
        free(*type);
        return temp_base64; // Return original if realloc fails
    }

    return final_base64;
}


// --- Main Demonstration ---

void print_hex(const unsigned char* data, size_t len, const char* label) {
    printf("%s (Length: %zu bytes):\n", label, len);
    for (size_t i = 0; i < len; ++i) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n\n");
}

int main() {
    // --- 1. Dummy Raw Key Data (e.g., a 16-byte symmetric key or part of a private key) ---
    unsigned char raw_key_data[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    size_t raw_key_data_len = sizeof(raw_key_data);
    print_hex(raw_key_data, raw_key_data_len, "Original Raw Key Data");

    // --- 2. Encode Raw Data to Simplified DER (OCTET STRING) ---
    printf("--- DER Encoding Process ---\n");
    size_t der_encoded_len;
    unsigned char* der_encoded_data = der_encode_octet_string(raw_key_data, raw_key_data_len, &der_encoded_len);

    if (der_encoded_data) {
        print_hex(der_encoded_data, der_encoded_len, "DER Encoded Data (Simplified OCTET STRING)");

        // --- 3. Encode DER to Base64 ---
        printf("--- Base64 Encoding Process ---\n");
        char* base64_encoded_data = base64_encode(der_encoded_data, der_encoded_len);

        if (base64_encoded_data) {
            printf("Base64 Encoded Data:\n%s\n\n", base64_encoded_data);

            // --- 4. Wrap Base64 in PEM Format ---
            printf("--- PEM Encoding Process ---\n");
            const char* pem_type = "DEMO PRIVATE KEY";
            char* pem_output = pem_encode(base64_encoded_data, pem_type);

            if (pem_output) {
                printf("PEM Encoded Output:\n%s\n", pem_output);

                // --- 5. PEM Decoding ---
                printf("--- PEM Decoding Process ---\n");
                char* decoded_pem_type = NULL;
                char* decoded_base64 = pem_decode(pem_output, &decoded_pem_type);

                if (decoded_base64 && decoded_pem_type) {
                    printf("Decoded PEM Type: %s\n", decoded_pem_type);
                    printf("Decoded Base64 from PEM:\n%s\n\n", decoded_base64);

                    // --- 6. Base64 Decoding ---
                    printf("--- Base64 Decoding Process ---\n");
                    size_t decoded_der_len;
                    unsigned char* decoded_der_data = base64_decode(decoded_base64, &decoded_der_len);

                    if (decoded_der_data) {
                        print_hex(decoded_der_data, decoded_der_len, "Decoded DER from Base64");

                        // --- 7. Simplified DER Decoding ---
                        printf("--- DER Decoding Process ---\n");
                        size_t final_extracted_len;
                        unsigned char* final_extracted_data = der_decode_octet_string(decoded_der_data, decoded_der_len, &final_extracted_len);

                        if (final_extracted_data) {
                            print_hex(final_extracted_data, final_extracted_len, "Final Extracted Raw Key Data");

                            // Compare with original
                            if (final_extracted_len == raw_key_data_len &&
                                memcmp(final_extracted_data, raw_key_data, raw_key_data_len) == 0) {
                                printf("Success: Original raw data matches final extracted data.\n");
                            } else {
                                printf("Error: Data mismatch after full encoding/decoding cycle.\n");
                            }
                            free(final_extracted_data);
                        } else {
                            fprintf(stderr, "Failed to decode DER octet string.\n");
                        }
                        free(decoded_der_data);
                    } else {
                        fprintf(stderr, "Failed to Base64 decode.\n");
                    }
                } else {
                    fprintf(stderr, "Failed to PEM decode.\n");
                }
                free(decoded_pem_type);
                free(decoded_base64);
            } else {
                fprintf(stderr, "Failed to PEM encode.\n");
            }
            free(pem_output);
        } else {
            fprintf(stderr, "Failed to Base64 encode.\n");
        }
        free(base64_encoded_data);
    } else {
        fprintf(stderr, "Failed to DER encode octet string.\n");
    }
    free(der_encoded_data);

    return 0;
}

