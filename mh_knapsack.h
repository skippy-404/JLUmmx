#ifndef MH_KNAPSACK_H
#define MH_KNAPSACK_H

#include <vector>
#include <string>
#include <stdexcept> // For std::runtime_error
#include <gmp.h>     // GNU Multiple Precision Arithmetic Library

// 包装类，用于在C++容器中安全管理mpz_t
class ManagedMpz {
public:
    mpz_t value;
    
    // 默认构造函数
    ManagedMpz() { mpz_init(value); }
    
    // 拷贝构造函数
    ManagedMpz(const ManagedMpz& other) { 
        mpz_init_set(value, other.value); 
    }
    
    // 移动构造函数
    ManagedMpz(ManagedMpz&& other) noexcept {
        mpz_init(value);
        mpz_swap(value, other.value); 
    }
    
    // 拷贝赋值运算符
    ManagedMpz& operator=(const ManagedMpz& other) {
        if (this != &other) {
            mpz_set(value, other.value);
        }
        return *this;
    }
    
    // 移动赋值运算符
    ManagedMpz& operator=(ManagedMpz&& other) noexcept {
        if (this != &other) {
            mpz_swap(value, other.value);
        }
        return *this;
    }
    
    // 析构函数
    ~ManagedMpz() { mpz_clear(value); }

    // 允许隐式转换为mpz_srcptr (const)
    operator mpz_srcptr() const { return value; }
    
    // 允许隐式转换为mpz_ptr (非const)
    operator mpz_ptr() { return value; }
    
    // 显式访问mpz_t
    mpz_ptr get() { return value; }
    mpz_srcptr get() const { return value; }
};

// Forward declaration
class MerkleHellman;

class MHKeyPair {
public:
    // Constructor
    // num_items: a_i 元素个数，也是一次加密的比特数
    // item_min_bit_lengh: w_1 的大致比特长度，后续w_i会快速增长
    MHKeyPair(size_t num_items = 256, unsigned int item_min_bit_length = 10);
    ~MHKeyPair();

    // 生成密钥对
    void generateKeys(size_t num_items = 256, unsigned int item_min_bit_length = 10);

    // 获取公钥 (b_1, b_2, ..., b_n)
    const std::vector<std::string>& getPublicKey_b_str() const { return publicKey_b_str; }

    // 获取私钥 (w_1, w_2, ..., w_n) - 超递增序列
    const std::vector<std::string>& getPrivateKey_w_str() const { return privateKey_w_str; }
    
    // 获取模数 q
    const std::string& getModulus_q_str() const { return q_str; }

    // 获取乘数 r (主要用于内部或调试)
    const std::string& getMultiplier_r_str() const { return r_str; }
    
    // 获取 r 的模 q 逆 r_inv (用于解密)
    const std::string& getMultiplierInverse_r_inv_str() const { return r_inv_str; }

    // 获取模数 q 的位长度
    size_t getModulus_q_bitLength() const;

    // 供MerkleHellman类访问内部mpz_t类型的密钥
    friend class MerkleHellman;

private:
    std::vector<ManagedMpz> private_key_w; // 超递增背包序列 w
    std::vector<ManagedMpz> public_key_b;  // 普通背包序列 b
    ManagedMpz q;                         // 模数 q, q > sum(w_i)
    ManagedMpz r;                         // 乘数 r, gcd(r, q) = 1
    ManagedMpz r_inv;                     // r 的模 q 逆元: r * r_inv = 1 (mod q)

    // 字符串表示形式，方便外部获取
    std::vector<std::string> privateKey_w_str;
    std::vector<std::string> publicKey_b_str;
    std::string q_str;
    std::string r_str;
    std::string r_inv_str;

    gmp_randstate_t rstate;          // GMP随机数状态

    void initRandom();               // 初始化随机数生成器
    void clearKeys();                // 清理mpz_t资源
    void updateStringRepresentations(); // 更新密钥的字符串表示

    // 辅助函数: ManagedMpz vector to string vector
    static void mpz_vector_to_string_vector(const std::vector<ManagedMpz>& mpz_vec, std::vector<std::string>& str_vec);
    // 辅助函数: string to mpz_t
    static void string_to_mpz_t(const std::string& s, mpz_t& val);
    // 辅助函数: mpz_t to string
    static std::string mpz_to_string(const mpz_t& val);
};

class MerkleHellman {
public:
    // 使用密钥对初始化 (用于解密和加密)
    MerkleHellman(const MHKeyPair& keyPair);

    // 使用公钥、q 和 r_inv 初始化 (主要用于外部解密器，或分离的密钥管理)
    // 注意: 实际中更常见的是仅用公钥加密，用完整私钥信息解密
    MerkleHellman(const std::vector<std::string>& public_key_b_str,
                  const std::vector<std::string>& private_key_w_str, // 私钥w
                  const std::string& q_str,                           // 模数q
                  const std::string& r_inv_str);                      // r的逆r_inv

    // 仅使用公钥初始化 (用于加密)
    MerkleHellman(const std::vector<std::string>& public_key_b_str);
    
    ~MerkleHellman();

    // 加密二进制字符串 (例如 "1011001")
    // 返回加密后的和 (十进制字符串)
    std::string encryptBinaryString(const std::string& binary_message) const;

    // 加密普通文本字符串
    // 内部会将文本转为二进制块进行加密
    // 返回每个块加密后的密文列表
    std::vector<std::string> encryptString(const std::string& message_text) const;
    
    // 解密单个密文块 (十进制字符串)
    // 返回解密后的二进制字符串
    std::string decryptToBinaryString(const std::string& ciphertext_sum_str) const;

    // 解密密文块列表
    // 返回解密后的原始文本字符串
    std::string decryptString(const std::vector<std::string>& ciphertext_blocks) const;

private:
    std::vector<ManagedMpz> public_key_b_mpz;  // 公钥 b (ManagedMpz 格式)
    
    // 解密所需参数
    std::vector<ManagedMpz> private_key_w_mpz; // 私钥 w (ManagedMpz 格式)
    ManagedMpz q_mpz;                         // 模数 q (ManagedMpz 格式)
    ManagedMpz r_inv_mpz;                     // r_inv (ManagedMpz 格式)

    bool canDecrypt;                     // 标记是否拥有解密所需完整信息

    void clearInternalKeys();

    // 辅助函数: string vector to ManagedMpz vector
    static void string_vector_to_mpz_vector(const std::vector<std::string>& str_vec, std::vector<ManagedMpz>& mpz_vec);
};

#endif // MH_KNAPSACK_H 