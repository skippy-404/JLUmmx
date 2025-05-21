#ifndef RSA_H
#define RSA_H

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

// RSA加密解密类
class RSA {
public:
    // 使用给定密钥对初始化
    RSA(const RSAKeyPair& keyPair);
    
    // 使用公钥字符串初始化
    RSA(const std::string& e, const std::string& n);
    
    // 析构函数
    ~RSA();
    
    // 设置公钥
    void setPublicKey(const std::string& e, const std::string& n);
    
    // 设置私钥
    void setPrivateKey(const std::string& d, const std::string& n);
    
    // 加密整数
    std::string encrypt(const std::string& message) const;
    
    // 解密整数
    std::string decrypt(const std::string& ciphertext) const;
    
    // 加密字符串
    std::vector<std::string> encryptString(const std::string& message) const;
    
    // 解密字符串
    std::string decryptString(const std::vector<std::string>& ciphertext) const;
    
    // 生成数字签名
    std::string sign(const std::string& message) const;
    
    // 验证数字签名
    bool verify(const std::string& message, const std::string& signature) const;
    
private:
    mpz_t e;         // 公钥指数
    mpz_t d;         // 私钥指数
    mpz_t n;         // 模数
    
    bool hasPublicKey;   // 是否有公钥
    bool hasPrivateKey;  // 是否有私钥
};

// 证书类
class Certificate {
public:
    // 创建新证书
    Certificate(const std::string& subject, const RSAKeyPair& keyPair);
    
    // 从文件加载证书
    explicit Certificate(const std::string& filename);
    
    // 保存证书到文件
    bool save(const std::string& filename) const;
    
    // 获取证书主题
    std::string getSubject() const;
    
    // 获取证书公钥
    std::pair<std::string, std::string> getPublicKey() const;
    
    // 获取证书签名
    std::string getSignature() const;
    
    // 验证证书签名
    bool verify(const RSA& verifier) const;
    
private:
    std::string subject;                         // 证书主题
    std::pair<std::string, std::string> pubKey;  // 公钥(e, n)
    std::string signature;                       // 证书签名
    std::string serialNumber;                    // 序列号
    std::string validFrom;                       // 有效期开始
    std::string validTo;                         // 有效期结束
    
    // 生成序列号
    void generateSerialNumber();
    
    // 设置有效期
    void setValidity(int days = 365);
};

#endif // RSA_H 