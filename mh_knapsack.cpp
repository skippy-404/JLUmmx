#include "mh_knapsack.h"
#include <algorithm> // For std::reverse
#include <vector>
#include <stdexcept>
#include <iostream> // For debugging, to be removed later
#include <cstdlib>  // For rand, srand
#include <ctime>    // For time
#include <cstring>  // For strlen
#include <iomanip>  // For std::setw, std::setfill
#include <bitset>   // For std::bitset (needed for encryptString)

// Helper to convert mpz_t to string (hex for now for easier debugging, can be decimal)
std::string mpz_to_str_helper(const mpz_t val) {
    char* s = mpz_get_str(NULL, 10, val); // Base 10
    std::string str_val(s);
    void (*freefunc)(void *, size_t);
    mp_get_memory_functions(NULL, NULL, &freefunc);
    freefunc(s, strlen(s) + 1);
    return str_val;
}

// --- MHKeyPair Implementation ---

void MHKeyPair::initRandom() {
    gmp_randinit_default(rstate);
    gmp_randseed_ui(rstate, time(NULL) + rand()); // Seed with time and rand()
}

void MHKeyPair::clearKeys() {
    // ManagedMpz自动管理生命周期，无需手动mpz_clear
    private_key_w.clear();
    public_key_b.clear();
    // q, r, r_inv也是ManagedMpz，析构时会自动调用mpz_clear

    privateKey_w_str.clear();
    publicKey_b_str.clear();
    q_str.clear();
    r_str.clear();
    r_inv_str.clear();
}

MHKeyPair::MHKeyPair(size_t num_items, unsigned int item_min_bit_length) {
    // q, r, r_inv现在是ManagedMpz，自动初始化
    initRandom();
    generateKeys(num_items, item_min_bit_length);
}

MHKeyPair::~MHKeyPair() {
    clearKeys();
    gmp_randclear(rstate);
}

void MHKeyPair::mpz_vector_to_string_vector(const std::vector<ManagedMpz>& mpz_vec, std::vector<std::string>& str_vec) {
    str_vec.clear();
    for (const auto& val : mpz_vec) {
        str_vec.push_back(mpz_to_str_helper(val.value));
    }
}

void MHKeyPair::string_to_mpz_t(const std::string& s, mpz_t& val) {
    if (mpz_set_str(val, s.c_str(), 10) != 0) { // Base 10
        throw std::runtime_error("Failed to convert string to mpz_t: " + s);
    }
}

std::string MHKeyPair::mpz_to_string(const mpz_t& val) {
    return mpz_to_str_helper(val);
}

void MHKeyPair::updateStringRepresentations() {
    mpz_vector_to_string_vector(private_key_w, privateKey_w_str);
    mpz_vector_to_string_vector(public_key_b, publicKey_b_str);
    q_str = mpz_to_str_helper(q.value);
    r_str = mpz_to_str_helper(r.value);
    r_inv_str = mpz_to_str_helper(r_inv.value);
}

void MHKeyPair::generateKeys(size_t num_items, unsigned int item_min_bit_length) {
    clearKeys(); // Clear any existing keys before generating new ones

    // 1. Generate superincreasing sequence w
    private_key_w.resize(num_items); // ManagedMpz自动初始化
    ManagedMpz sum_w; // 自动初始化
    ManagedMpz temp_rand_val; // 自动初始化

    // First element w_0
    mpz_urandomb(private_key_w[0].value, rstate, item_min_bit_length);
    mpz_add_ui(private_key_w[0].value, private_key_w[0].value, 1); // Ensure it's not zero
    mpz_add(sum_w.value, sum_w.value, private_key_w[0].value);

    for (size_t i = 1; i < num_items; ++i) {
        // Generate w_i > sum of previous w's
        // For a bit more randomness, w_i = sum_w + random_small_number
        mpz_urandomb(temp_rand_val.value, rstate, item_min_bit_length / 2 + 1); // Smaller random number
        mpz_add_ui(temp_rand_val.value, temp_rand_val.value, 1); // Ensure it's at least 1
        mpz_add(private_key_w[i].value, sum_w.value, temp_rand_val.value); 
        mpz_add(sum_w.value, sum_w.value, private_key_w[i].value);
    }

    // 2. Choose q such that q > sum(w_i)
    // Ensure q is at least 256 bits as per requirement (or sum_w bits + some, whichever is larger)
    unsigned int q_min_bits = std::max((unsigned int)256, (unsigned int)mpz_sizeinbase(sum_w.value, 2) + (unsigned int)rand()%10 + 5);
    mpz_urandomb(q.value, rstate, q_min_bits - mpz_sizeinbase(sum_w.value, 2)); // Generate additional bits
    mpz_add(q.value, q.value, sum_w.value); // q = sum_w + random_large_number
    mpz_add_ui(q.value, q.value, rand()%100 + 1); // Add a small random number to ensure q > sum_w
    
    // 3. Choose r such that gcd(r, q) = 1 and 1 < r < q
    ManagedMpz gcd_val; // 自动初始化
    do {
        mpz_urandomm(r.value, rstate, q.value); // r is random in [0, q-1]
        if (mpz_cmp_ui(r.value, 1) <= 0) mpz_add_ui(r.value, r.value, 2); // Ensure r > 1
        mpz_gcd(gcd_val.value, r.value, q.value);
    } while (mpz_cmp_ui(gcd_val.value, 1) != 0);

    // 4. Calculate r_inv such that r * r_inv = 1 (mod q)
    if (mpz_invert(r_inv.value, r.value, q.value) == 0) {
        // This should not happen if gcd(r,q)=1
        throw std::runtime_error("Failed to compute modular inverse r_inv. gcd(r,q) was not 1?");
    }

    // 5. Generate public key b_i = (w_i * r) mod q
    public_key_b.resize(num_items); // ManagedMpz自动初始化
    for (size_t i = 0; i < num_items; ++i) {
        mpz_mul(public_key_b[i].value, private_key_w[i].value, r.value);
        mpz_mod(public_key_b[i].value, public_key_b[i].value, q.value);
    }

    updateStringRepresentations(); // Update string versions for easy access
}

size_t MHKeyPair::getModulus_q_bitLength() const {
    if (mpz_cmp_ui(q.value, 0) == 0) { // Check if q is initialized (not zero)
        return 0; // Or throw an error, or handle as appropriate
    }
    return mpz_sizeinbase(q.value, 2);
}


// --- MerkleHellman Implementation ---

void MerkleHellman::clearInternalKeys() {
    // ManagedMpz自动管理生命周期，无需手动mpz_clear
    public_key_b_mpz.clear();
    if (canDecrypt) {
        private_key_w_mpz.clear();
        // q_mpz, r_inv_mpz也是ManagedMpz，析构时会自动调用mpz_clear
    }
}

void MerkleHellman::string_vector_to_mpz_vector(const std::vector<std::string>& str_vec, std::vector<ManagedMpz>& mpz_vec) {
    mpz_vec.resize(str_vec.size()); // ManagedMpz自动初始化
    for (size_t i = 0; i < str_vec.size(); ++i) {
        MHKeyPair::string_to_mpz_t(str_vec[i], mpz_vec[i].value);
    }
}

MerkleHellman::MerkleHellman(const MHKeyPair& keyPair) : canDecrypt(true) {
    string_vector_to_mpz_vector(keyPair.getPublicKey_b_str(), public_key_b_mpz);
    string_vector_to_mpz_vector(keyPair.getPrivateKey_w_str(), private_key_w_mpz);
    // q_mpz, r_inv_mpz是ManagedMpz，自动初始化
    MHKeyPair::string_to_mpz_t(keyPair.getModulus_q_str(), q_mpz.value);
    MHKeyPair::string_to_mpz_t(keyPair.getMultiplierInverse_r_inv_str(), r_inv_mpz.value);
}

MerkleHellman::MerkleHellman(const std::vector<std::string>& public_key_b_str,
                             const std::vector<std::string>& private_key_w_str,
                             const std::string& q_str_param,
                             const std::string& r_inv_str_param) : canDecrypt(true) {
    string_vector_to_mpz_vector(public_key_b_str, public_key_b_mpz);
    string_vector_to_mpz_vector(private_key_w_str, private_key_w_mpz);
    // q_mpz, r_inv_mpz是ManagedMpz，自动初始化
    MHKeyPair::string_to_mpz_t(q_str_param, q_mpz.value);
    MHKeyPair::string_to_mpz_t(r_inv_str_param, r_inv_mpz.value);
}

MerkleHellman::MerkleHellman(const std::vector<std::string>& public_key_b_str) : canDecrypt(false) {
    string_vector_to_mpz_vector(public_key_b_str, public_key_b_mpz);
    // q_mpz, r_inv_mpz是ManagedMpz，自动初始化但不会在仅加密模式下使用
}

MerkleHellman::~MerkleHellman() {
    clearInternalKeys();
}

std::string MerkleHellman::encryptBinaryString(const std::string& binary_message) const {
    if (binary_message.length() > public_key_b_mpz.size()) {
        throw std::runtime_error("Binary message length exceeds public key size.");
    }
    if (binary_message.empty()) {
        return "0";
    }

    ManagedMpz sum_c; // 自动初始化为0

    for (size_t i = 0; i < binary_message.length(); ++i) {
        if (binary_message[i] == '1') {
            if (i < public_key_b_mpz.size()) { // Ensure we don't go out of bounds
                 mpz_add(sum_c.value, sum_c.value, public_key_b_mpz[i].value);
            } else {
                throw std::out_of_range("Binary message index out of public key range during encryption.");
            }
        }
    }

    std::string ciphertext = MHKeyPair::mpz_to_string(sum_c.value);
    return ciphertext;
}

// Encrypts string by converting to binary blocks
std::vector<std::string> MerkleHellman::encryptString(const std::string& message_text) const {
    if (public_key_b_mpz.empty()) {
        throw std::runtime_error("Public key is empty, cannot encrypt.");
    }
    std::vector<std::string> encrypted_blocks;
    std::string binary_representation;
    for (char c : message_text) {
        std::bitset<8> bits(c);
        binary_representation += bits.to_string();
    }

    size_t block_size = public_key_b_mpz.size(); // Each block encrypts 'block_size' bits
    for (size_t i = 0; i < binary_representation.length(); i += block_size) {
        std::string block = binary_representation.substr(i, block_size);
        encrypted_blocks.push_back(encryptBinaryString(block));
    }
    return encrypted_blocks;
}

std::string MerkleHellman::decryptToBinaryString(const std::string& ciphertext_sum_str) const {
    if (!canDecrypt) {
        throw std::runtime_error("Decryption keys not available for this MerkleHellman instance.");
    }
    if (private_key_w_mpz.empty() || mpz_cmp_ui(q_mpz.value, 0) == 0 || mpz_cmp_ui(r_inv_mpz.value, 0) == 0) {
        throw std::runtime_error("Private key components (w, q, r_inv) not properly initialized for decryption.");
    }

    ManagedMpz c_prime, current_sum; // 自动初始化
    MHKeyPair::string_to_mpz_t(ciphertext_sum_str, current_sum.value);

    // C' = C * r^-1 (mod q)
    mpz_mul(c_prime.value, current_sum.value, r_inv_mpz.value);
    mpz_mod(c_prime.value, c_prime.value, q_mpz.value);

    std::string binary_message_reversed = "";
    // Solve subset sum for c_prime using superincreasing w (solve in reverse)
    for (int i = private_key_w_mpz.size() - 1; i >= 0; --i) {
        if (mpz_cmp(c_prime.value, private_key_w_mpz[i].value) >= 0) {
            binary_message_reversed += '1';
            mpz_sub(c_prime.value, c_prime.value, private_key_w_mpz[i].value);
        } else {
            binary_message_reversed += '0';
        }
    }
    std::reverse(binary_message_reversed.begin(), binary_message_reversed.end());

    return binary_message_reversed;
}

std::string MerkleHellman::decryptString(const std::vector<std::string>& ciphertext_blocks) const {
    if (!canDecrypt) {
        throw std::runtime_error("Decryption keys not available.");
    }
    std::string decrypted_binary_string;
    for (const auto& block : ciphertext_blocks) {
        decrypted_binary_string += decryptToBinaryString(block);
    }

    std::string original_message;
    for (size_t i = 0; i < decrypted_binary_string.length(); i += 8) {
        std::string byte_str = decrypted_binary_string.substr(i, 8);
        if (byte_str.length() == 8) { // Ensure it's a full byte
            try {
                std::bitset<8> bits(byte_str);
                original_message += static_cast<char>(bits.to_ulong());
            } catch (const std::invalid_argument& ia) {
                // Handle cases where byte_str is not valid binary for bitset
                // This might happen if decrypted_binary_string has a length not multiple of 8
                // or contains non '0'/'1' characters (though decryptToBinaryString should prevent this)
                std::cerr << "Warning: Could not convert binary segment to char: " << byte_str << std::endl;
            }
        }
    }
    return original_message;
} 