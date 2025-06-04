#ifndef RSA_BLIND_SIGNATURE_H
#define RSA_BLIND_SIGNATURE_H

#include <string>
#include <vector>
#include <utility>
#include <sstream>
#include <iomanip>
#include <gmp.h>

// 简单的哈希函数，将字符串转换为较小的数字表示
inline std::string simpleHash(const std::string& input) {
    // 使用简单的加法哈希
    unsigned long hash = 0;
    for (char c : input) {
        hash = hash * 31 + static_cast<unsigned char>(c);
    }
    
    // 转换为十六进制字符串
    std::stringstream ss;
    ss << std::hex << hash;
    return ss.str();
}

// RSA密钥对类
class RSAKeyPair {
public:
    // 生成新的密钥对
    RSAKeyPair(unsigned int bits = 2048);
    
    // 析构函数
    ~RSAKeyPair();
    
    // 获取公钥(e, n)
    std::pair<std::string, std::string> getPublicKey() const;
    
    // 获取私钥(d, n)
    std::pair<std::string, std::string> getPrivateKey() const;
    
    // 从字符串导入公钥
    void importPublicKey(const std::string& e, const std::string& n);
    
    // 从字符串导入私钥
    void importPrivateKey(const std::string& d, const std::string& n);
    
    // 生成新的密钥对
    void generateKeyPair(unsigned int bits = 2048);
    
private:
    mpz_t p, q;      // 两个大素数
    mpz_t n;         // 模数 n = p*q
    mpz_t phi;       // 欧拉函数值 φ(n) = (p-1)*(q-1)
    mpz_t e;         // 公钥指数
    mpz_t d;         // 私钥指数
    
    // 随机数生成器状态
    gmp_randstate_t rstate;
    
    // 初始化随机数生成器
    void initRandom();
};

// RSA盲签名类
class RSABlindSignature {
public:
    // 使用给定密钥对初始化
    RSABlindSignature(const RSAKeyPair& keyPair);
    
    // 使用公钥字符串初始化
    RSABlindSignature(const std::string& e, const std::string& n);
    
    // 析构函数
    ~RSABlindSignature();
    
    // 设置公钥
    void setPublicKey(const std::string& e, const std::string& n);
    
    // 设置私钥
    void setPrivateKey(const std::string& d, const std::string& n);
    
    // 用户: 生成盲因子
    std::string generateBlindingFactor() const;
    
    // 用户: 使用公钥和盲因子对消息进行盲化
    std::string blind(const std::string& message, const std::string& blindingFactor) const;
    
    // 签名者: 对盲化消息进行签名
    std::string signBlindedMessage(const std::string& blindedMessage) const;
    
    // 用户: 从盲签名中移除盲因子，获得原始消息的签名
    std::string unblind(const std::string& blindSignature, const std::string& blindingFactor) const;
    
    // 验证签名
    bool verify(const std::string& message, const std::string& signature) const;
    
private:
    mpz_t e;         // 公钥指数
    mpz_t d;         // 私钥指数
    mpz_t n;         // 模数
    
    bool hasPublicKey;   // 是否有公钥
    bool hasPrivateKey;  // 是否有私钥
    
    // 随机数生成器状态
    gmp_randstate_t rstate;
    
    // 初始化随机数生成器
    void initRandom();
};

#endif // RSA_BLIND_SIGNATURE_H