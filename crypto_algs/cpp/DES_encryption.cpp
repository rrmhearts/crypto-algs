#include <iostream>
#include <string>
#include <vector>
#include <algorithm> // For std::reverse in decryption

// --- DES Algorithm Constants (Simplified for Illustration) ---

// Initial Permutation (IP) Table (64 elements)
// const int IP_TABLE[64] = { /* ... 64 values representing the permutation ... */ };
const int IP_TABLE[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

// Expansion Permutation (E) Table (32 elements expand to 48)
// const int E_TABLE[48] = { /* ... 48 values representing the expansion ... */ };
const int E_TABLE[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

// P-Box Permutation (P) Table (32 elements)
// const int P_TABLE[32] = { /* ... 32 values representing the permutation ... */ };
const int P_TABLE[32] = {
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25
};

// S-Box tables (8 S-boxes, each 6-bit input, 4-bit output)
// const int S_BOXES[8][4][16] = { /* ... 8 S-box tables ... */ };
const int S_BOXES[8][4][16] = {
    // S1
    {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
     {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
     {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
     {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},

    // S2
    {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
     {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
     {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
     {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},

    // S3
    {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
     {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
     {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
     {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},

    // S4
    {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
     {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
     {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
     {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},

    // S5
    {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
     {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
     {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
     {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},

    // S6
    {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
     {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
     {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
     {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},

    // S7
    {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
     {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
     {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
     {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},

    // S8
    {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
     {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
     {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
     {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}
};

// Permuted Choice 1 (PC-1) Table for Key Generation (56 bits from 64-bit key)
// const int PC1_TABLE[56] = { /* ... 56 values ... */ };
const int PC1_TABLE[56] = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
};

// Permuted Choice 2 (PC-2) Table for Key Generation (48 bits from 56-bit shifted key)
// const int PC2_TABLE[48] = { /* ... 48 values ... */ };
const int PC2_TABLE[48] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

// Left Shift schedule for Key Generation (determines shifts per round)
// const int SHIFT_SCHEDULE[16] = { /* ... 16 shift values ... */ };
const int SHIFT_SCHEDULE[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

// Inverse Initial Permutation (IP_INV) Table (64 elements)
// const int IP_INV_TABLE[64] = { /* ... 64 values representing the inverse permutation ... */ };
const int IP_INV_TABLE[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
};

// --- Helper Functions (Conceptual) ---

// Function to convert string to bitset (or vector<bool>)
std::vector<bool> string_to_bits(const std::string& text) {
    // Implement conversion of ASCII characters to 8-bit binary
    // Pad with zeros if the text length is not a multiple of 8 bytes (64 bits)
    // Note: Proper padding schemes (like PKCS#7) are crucial for secure implementations
    std::vector<bool> bits;
    // ... conversion logic ...
    return bits;
}

// Function to convert bitset to string
std::string bits_to_string(const std::vector<bool>& bits) {
    // Implement conversion of 8-bit binary chunks back to ASCII characters
    std::string text;
    // ... conversion logic ...
    return text;
}

// Function to apply a permutation table to a bitset
std::vector<bool> apply_permutation(const std::vector<bool>& input, const int* table, int table_size) {
    std::vector<bool> output(table_size);
    for (int i = 0; i < table_size; ++i) {
        output[i] = input[table[i] - 1]; // Adjust for 0-based indexing
    }
    return output;
}

// Function to perform a circular left shift on a bitset
std::vector<bool> circular_left_shift(const std::vector<bool>& input, int shift_amount) {
    std::vector<bool> shifted = input;
    std::rotate(shifted.begin(), shifted.begin() + shift_amount, shifted.end());
    return shifted;
}

// Function to perform XOR operation on two bitsets
std::vector<bool> xor_bits(const std::vector<bool>& a, const std::vector<bool>& b) {
    std::vector<bool> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

// Function to perform S-box substitution
std::vector<bool> s_box_substitution(const std::vector<bool>& input) {
    std::vector<bool> output(32); // 8 S-boxes, each outputting 4 bits
    for (int i = 0; i < 8; ++i) {
        // Extract 6-bit input for current S-box
        std::vector<bool> s_box_input(input.begin() + (i * 6), input.begin() + ((i + 1) * 6));

        // Determine row and column for S-box lookup
        int row = (s_box_input[0] << 1) | s_box_input[5]; // First and last bits form the row
        int col = (s_box_input[1] << 3) | (s_box_input[2] << 2) | (s_box_input[3] << 1) | s_box_input[4]; // Middle four bits form the column

        // Get 4-bit output from S-box table
        int s_box_output_val = S_BOXES[i][row][col];

        // Convert decimal output to 4-bit binary and place into overall output
        for (int j = 0; j < 4; ++j) {
            output[(i * 4) + j] = ((s_box_output_val >> (3 - j)) & 1);
        }
    }
    return output;
}

// --- DES Key Generation ---

std::vector<std::vector<bool>> generate_round_keys(const std::string& master_key_hex) {
    // 1. Convert 64-bit (16 hex characters) key to 64-bit binary
    std::vector<bool> master_key_bits = string_to_bits(master_key_hex); 

    // 2. Apply Permuted Choice 1 (PC-1) to get 56-bit key
    std::vector<bool> pc1_key = apply_permutation(master_key_bits, PC1_TABLE, 56);

    // 3. Divide into two 28-bit halves (C0 and D0)
    std::vector<bool> c_half(pc1_key.begin(), pc1_key.begin() + 28);
    std::vector<bool> d_half(pc1_key.begin() + 28, pc1_key.end());

    std::vector<std::vector<bool>> round_keys(16);

    // 4. Perform 16 rounds of key generation
    for (int i = 0; i < 16; ++i) {
        // Apply circular left shifts based on SHIFT_SCHEDULE
        c_half = circular_left_shift(c_half, SHIFT_SCHEDULE[i]);
        d_half = circular_left_shift(d_half, SHIFT_SCHEDULE[i]);

        // Concatenate C_i and D_i
        std::vector<bool> combined_key(56);
        std::copy(c_half.begin(), c_half.end(), combined_key.begin());
        std::copy(d_half.begin(), d_half.end(), combined_key.begin() + 28);

        // Apply Permuted Choice 2 (PC-2) to get 48-bit round key
        round_keys[i] = apply_permutation(combined_key, PC2_TABLE, 48);
    }
    return round_keys;
}

// --- DES Encryption Function ---

std::string des_encrypt(const std::string& plaintext, const std::string& key_hex) {
    // 1. Convert plaintext to 64-bit binary block
    std::vector<bool> block = string_to_bits(plaintext);

    // 2. Generate 16 round keys
    std::vector<std::vector<bool>> round_keys = generate_round_keys(key_hex);

    // 3. Apply Initial Permutation (IP)
    block = apply_permutation(block, IP_TABLE, 64);

    // 4. Divide into Left and Right 32-bit halves
    std::vector<bool> left_half(block.begin(), block.begin() + 32);
    std::vector<bool> right_half(block.begin() + 32, block.end());

    // 5. Perform 16 rounds of Feistel Network
    for (int i = 0; i < 16; ++i) {
        std::vector<bool> temp_right_half = right_half; // Store current right half for swap

        // Expansion (E)
        std::vector<bool> expanded_right = apply_permutation(right_half, E_TABLE, 48);

        // XOR with Round Key
        std::vector<bool> xored_expanded = xor_bits(expanded_right, round_keys[i]);

        // S-box Substitution
        std::vector<bool> s_box_output = s_box_substitution(xored_expanded);

        // P-Box Permutation
        std::vector<bool> p_box_output = apply_permutation(s_box_output, P_TABLE, 32);

        // XOR with Left Half
        right_half = xor_bits(left_half, p_box_output);

        // Swap (old right becomes new left)
        left_half = temp_right_half;
    }

    // 6. Swap halves back (after 16 rounds, the halves are "unswapped")
    std::vector<bool> combined_block(64);
    std::copy(right_half.begin(), right_half.end(), combined_block.begin()); // New Left is actually the final right
    std::copy(left_half.begin(), left_half.end(), combined_block.begin() + 32); // New Right is actually the final left

    // 7. Apply Inverse Initial Permutation (IP_INV)
    combined_block = apply_permutation(combined_block, IP_INV_TABLE, 64);

    // 8. Convert bitset to string (ciphertext)
    return bits_to_string(combined_block);
}

// --- DES Decryption Function ---

std::string des_decrypt(const std::string& ciphertext, const std::string& key_hex) {
    // Decryption is essentially the same as encryption, but with round keys applied in reverse order.
    std::vector<bool> block = string_to_bits(ciphertext);
    std::vector<std::vector<bool>> round_keys = generate_round_keys(key_hex);

    // Reverse the order of round keys for decryption
    std::reverse(round_keys.begin(), round_keys.end()); 

    block = apply_permutation(block, IP_TABLE, 64);

    std::vector<bool> left_half(block.begin(), block.begin() + 32);
    std::vector<bool> right_half(block.begin() + 32, block.end());

    for (int i = 0; i < 16; ++i) {
        std::vector<bool> temp_right_half = right_half; 

        std::vector<bool> expanded_right = apply_permutation(right_half, E_TABLE, 48);
        std::vector<bool> xored_expanded = xor_bits(expanded_right, round_keys[i]);
        std::vector<bool> s_box_output = s_box_substitution(xored_expanded);
        std::vector<bool> p_box_output = apply_permutation(s_box_output, P_TABLE, 32);
        right_half = xor_bits(left_half, p_box_output);
        left_half = temp_right_half;
    }

    std::vector<bool> combined_block(64);
    std::copy(right_half.begin(), right_half.end(), combined_block.begin());
    std::copy(left_half.begin(), left_half.end(), combined_block.begin() + 32);

    combined_block = apply_permutation(combined_block, IP_INV_TABLE, 64);

    return bits_to_string(combined_block);
}

int main() {
    std::string plaintext = "HelloDES"; // Must be 8 characters (64 bits) for this simplified example
    std::string key = "password";    // 8 characters (64 bits), effective 56-bit key used

    // Pad plaintext to 64 bits if needed (using a simple padding here, for illustration)
    // In real-world DES implementations, padding like PKCS#7 would be used.
    // This example assumes a fixed 64-bit plaintext block for simplicity.
    if (plaintext.length() < 8) {
        plaintext.resize(8, '\0'); 
    } else if (plaintext.length() > 8) {
        plaintext = plaintext.substr(0, 8); // Truncate for this basic example
    }

    // Encrypt the plaintext
    std::string ciphertext = des_encrypt(plaintext, key);

    // Decrypt the ciphertext
    std::string decrypted_text = des_decrypt(ciphertext, key);

    std::cout << "Original Text: " << plaintext << std::endl;
    std::cout << "Encrypted Text (Hex/Binary Representation): " << ciphertext << std::endl; // Output might be non-printable characters
    std::cout << "Decrypted Text: " << decrypted_text << std::endl;

    return 0;
}
