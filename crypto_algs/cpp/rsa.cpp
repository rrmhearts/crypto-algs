#include <iostream>
#include <vector>
#include <string>
#include <cassert>

// Greatest Common Divisor
int gcd(int a, int b) {
    while (b != 0) {
        int tmp = b;
        b = a % b;
        a = tmp;
    }
    return a;
}

// Modular Exponentiation (base^exp % mod)
// Assumes larger numbers and applies mod iteratively.
long long mod_exp(long long base, long long exp, long long mod) {
    long long result = 1;
    // base^exp % mod = (base%mod)^exp % mod
    base %= mod;

    while (exp > 0) {
        // If odd, multiply by base once
        if (exp % 2 == 1)
            result = (result * base) % mod;
        // Remove odd factor and divide by two
        exp = exp >> 1;
        // Include the square in the answer
        base = (base * base) % mod;
    }
    return result;
}

// Modular Inverse using Extended Euclidean Algorithm
// Find co-prime numbers such that it returns d
// where e * d % phi == 1
int mod_inverse(int e, int phi) {
    int t = 0, newt = 1;
    int r = phi, newr = e;

    while (newr != 0) {
        int quotient = r / newr;
        int temp = newt;
        newt = t - quotient * newt;
        t = temp;

        temp = newr;
        newr = r - quotient * newr;
        r = temp;
    }

    if (r > 1) return -1; // e is not invertible
    if (t < 0) t += phi;
    return t;
}

// Encrypt string message to vector of ciphertext integers
std::vector<long long> encrypt_string(const std::string& message, int e, int n) {
    std::vector<long long> encrypted;
    for (char ch : message) {
        long long m = static_cast<int>(ch);
        encrypted.push_back(mod_exp(m, e, n));
    }
    return encrypted;
}

// Decrypt vector of ciphertext to string
std::string decrypt_string(const std::vector<long long>& encrypted, int d, int n) {
    std::string decrypted;
    for (long long c : encrypted) {
        long long m = mod_exp(c, d, n);
        decrypted += static_cast<char>(m);
    }
    return decrypted;
}

int main() {
    // Small primes
    int p = 61;
    int q = 53;

    // Compute n and phi(n)
    int n = p * q;
    int phi = (p - 1) * (q - 1);

    // Choose e (public key exponent)
    int e = 17;
    while (gcd(e, phi) != 1)
        ++e;

    // Compute d (private key exponent)
    int d = mod_inverse(e, phi);
    if (d == -1) {
        std::cerr << "Failed to find modular inverse.\n";
        return 1;
    }
    
    int answer = (e*d)%phi;
    printf("e*d %c n = %d\n", 37, answer);
    assert( (e*d) % phi == 1);

    std::cout << "Public key: (" << e << ", " << n << ")\n";
    std::cout << "Private key: (" << d << ", " << n << ")\n";

    std::string message = "HELLO RSA!";
    std::cout << "Original Message: " << message << "\n";

    // Encrypt: c = m^e mod n
    auto encrypted = encrypt_string(message, e, n);
    std::cout << "Encrypted: ";
    for (auto c : encrypted)
        std::cout << c << " ";
    std::cout << "\n";

    // Decrypt: m = c^d mod n
    std::string decrypted = decrypt_string(encrypted, d, n);
    std::cout << "Decrypted Message: " << decrypted << "\n";

    return 0;
}
