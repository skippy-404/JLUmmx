#include <iostream>
#include <string>
#include <vector>
#include <stdexcept> // For std::exception
#include "mh_knapsack.h"
// #include "rsa.h" // No longer needed for MH demo

// 证书类 - 为MH调整或简化
// 对于MH，证书主要用于分发公钥。签名机制不同于RSA。
// 我们可以简单地创建一个包含公钥信息和主体信息的数据结构，
// 然后"签名"这个结构（例如用一个外部的哈希和对称加密，或只是展示概念）。
// 或者，如果目标是兼容X.509类的结构，我们需要定义如何将MH公钥嵌入。
// 这里我们先简化处理，重点是密钥的分发。

class CertificateMH {
public:
    std::string subject;
    std::vector<std::string> publicKey_b; // Merkle-Hellman公钥
    std::string q_modulus; // Merkle-Hellman 模数q, 虽然不是严格公钥，但加密时可能需要
                           // 或者说，公钥应该被认为是 (b, q) 对，或者b本身已经足够大
                           // 传统MH加密仅需要b，但为了清晰和未来扩展，可包含q
    std::string signature; // 模拟签名

    CertificateMH(const std::string& sub, const MHKeyPair& keyPair) 
        : subject(sub) {
        publicKey_b = keyPair.getPublicKey_b_str();
        q_modulus = keyPair.getModulus_q_str();
        // 模拟签名：简单哈希主体和公钥
        std::string data_to_sign = subject;
        for(const auto& item : publicKey_b) data_to_sign += item;
        data_to_sign += q_modulus;
        // 实际中，这里应该用一个安全的签名算法（如RSA或ECDSA）对哈希进行签名
        // 但我们这里没有另一个签名算法，所以用一个占位符
        unsigned long hash = 0;
        for (char c : data_to_sign) {
            hash = hash * 31 + static_cast<unsigned char>(c);
        }
        signature = std::to_string(hash); 
    }

    void print() const {
        std::cout << "  Subject: " << subject << std::endl;
        std::cout << "  Public Key (b items): " << publicKey_b.size() << " elements" << std::endl;
        // for(const auto& item : publicKey_b) std::cout << "    " << item << std::endl;
        std::cout << "  Modulus q (for context): " << q_modulus << std::endl;
        std::cout << "  Simulated Signature: " << signature << std::endl;
    }

    // 简单的验证模拟 (这里仅检查签名非空，实际应重新计算哈希并对比)
    bool verifyMock() const {
        return !signature.empty();
    }
};


int main() {
    std::cout << "Merkle-Hellman Knapsack Cryptosystem Demo" << std::endl;
    std::cout << "=========================================" << std::endl << std::endl;

    try {
        // 1. 生成密钥对
        // 参数: 密钥中项目的数量 (例如，8个项目可以加密8位块)
        // 为了满足题目中 >=256bit 的要求（通常指模数或关键安全参数），
        // MHKeyPair构造函数内部会确保模数q足够大。
        // num_items这里选择8，意味着一次加密8位块。可以增加来一次加密更多位。
        // 如果要一次加密256位，那么num_items应该是256。
        // 我们选择 num_items = 32 (加密 32 位块)，item_min_bit_length可以小一些，比如8-10
        // 实际参数可以根据需要调整，较大的num_items会使公钥非常大。
        // 题目中大数运算，位数>=256bit，这里指的应该是模数q的位数。
        // MHKeyPair 构造函数中已处理了q的位数。
        // 我们让背包元素的数量为，比如说，16个，这样可以一次处理16比特。
        // 或者，为了简单演示字符加密，让它是8个元素。
        // size_t num_knapsack_items = 8; // 每个块8比特 (1 字节) - 移除未使用的变量
        // 如果要求公钥本身（即所有b_i的总和或q）有256位，num_knapsack_items可以设为256
        // 但这会使公钥非常长。我们假设256位是指q。
        // 若严格按"位数>=256bit"用于公钥，则num_knapsack_items应为256.
        // 这里我们取一个折中，比如 num_knapsack_items = 64, item_min_bit_length = 4
        // 这意味着我们一次加密 64 bits.
        // 根据图片要求"位数>=256bit"，这通常指RSA的模数N或ECC的域参数。
        // 对于MH，关键大数是q。我们的MHKeyPair已确保q至少256位。
        // 背包的大小（num_items）决定了一次可以加密多少位。
        // 为了演示，我们用 num_items = 16 (一次加密2个字节)
        std::cout << "Generating Merkle-Hellman key pair..." << std::endl;
        MHKeyPair keyPair(16, 10); // 16 items in knapsack, first item approx 10 bits
        std::cout << "Key pair generated!" << std::endl << std::endl;

        std::cout << "Public Key (b - first few elements shown if many):" << std::endl;
        const auto& pub_key_b = keyPair.getPublicKey_b_str();
        for(size_t i=0; i < std::min((size_t)5, pub_key_b.size()); ++i) { // Print first 5 or less
            std::cout << "  b[" << i << "] = " << pub_key_b[i] << std::endl;
        }
        if (pub_key_b.size() > 5) std::cout << "  ... and " << (pub_key_b.size() - 5) << " more elements." << std::endl;
        std::cout << "Modulus q: " << keyPair.getModulus_q_str() << " (bit length: " << keyPair.getModulus_q_bitLength() << " bits)" << std::endl;
        // std::cout << "Private Key (w - superincreasing - first few):" << std::endl;
        // const auto& priv_key_w = keyPair.getPrivateKey_w_str();
        // for(size_t i=0; i < std::min((size_t)5, priv_key_w.size()); ++i) {
        //     std::cout << "  w[" << i << "] = " << priv_key_w[i] << std::endl;
        // }
        // std::cout << "Multiplier r: " << keyPair.getMultiplier_r_str() << std::endl;
        // std::cout << "Inverse r_inv: " << keyPair.getMultiplierInverse_r_inv_str() << std::endl << std::endl;

        // 2. 创建 MerkleHellman 实例
        MerkleHellman mh(keyPair);

        // 3. 加密消息
        std::string message = "Hello MH! This is a test message.";
        std::cout << "Original message: " << message << std::endl;

        std::vector<std::string> ciphertext_blocks = mh.encryptString(message);
        std::cout << "Encrypted message (blocks):" << std::endl;
        for (size_t i = 0; i < ciphertext_blocks.size(); ++i) {
            std::cout << "  Block " << i + 1 << ": " << ciphertext_blocks[i] << std::endl;
        }
        std::cout << std::endl;

        // 4. 解密消息
        std::string decryptedMessage = mh.decryptString(ciphertext_blocks);
        std::cout << "Decrypted message: " << decryptedMessage << std::endl << std::endl;

        // 5. 检查加解密是否一致
        if (message == decryptedMessage) {
            std::cout << "SUCCESS: Decrypted message matches original message." << std::endl;
        } else {
            std::cout << "FAILURE: Decrypted message does NOT match original message." << std::endl;
            std::cout << "Original length:  " << message.length() << std::endl;
            std::cout << "Decrypted length: " << decryptedMessage.length() << std::endl;
            std::cout << "Original:  \"" << message << "\"" << std::endl;
            std::cout << "Decrypted: \"" << decryptedMessage << "\"" << std::endl;
            
            // 检查是否只是尾部有额外的空字符
            std::string trimmed_decrypted = decryptedMessage;
            while (!trimmed_decrypted.empty() && trimmed_decrypted.back() == '\0') {
                trimmed_decrypted.pop_back();
            }
            if (message == trimmed_decrypted) {
                std::cout << "NOTE: Messages match after removing trailing null characters." << std::endl;
            }
        }
        std::cout << std::endl;

        // 6. 生成并显示证书 (模拟)
        std::cout << "Generating (simulated) certificate for MH public key..." << std::endl;
        CertificateMH cert("CN=MH User, O=Knapsack Test, C=ZZ", keyPair);
        std::cout << "Certificate generated:" << std::endl;
        cert.print();
        std::cout << "Certificate (mock) verification: " << (cert.verifyMock() ? "Looks OK" : "Failed") << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
        return 1;
    }

    return 0;
} 