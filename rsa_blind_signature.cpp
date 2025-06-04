#include "rsa_blind_signature.h"
#include <iostream>
#include <ctime>
#include <cstdlib>
#include <stdexcept>

// 辅助函数：将mpz_t转换为字符串
static std::string mpz_to_str(const mpz_t num) {
    char* str = mpz_get_str(nullptr, 10, num);
    std::string result(str);
    free(str);
    return result;
}

// 辅助函数：将字符串转换为mpz_t
static void str_to_mpz(mpz_t result, const std::string& str) {
    mpz_set_str(result, str.c_str(), 10);
}

// ============== RSAKeyPair 实现 ==============

void RSAKeyPair::initRandom() {
    gmp_randinit_mt(rstate);
    unsigned long seed = static_cast<unsigned long>(time(nullptr));
    gmp_randseed_ui(rstate, seed);
}

RSAKeyPair::RSAKeyPair(unsigned int bits) {
    mpz_init(p);
    mpz_init(q);
    mpz_init(n);
    mpz_init(phi);
    mpz_init(e);
    mpz_init(d);
    
    initRandom();
    generateKeyPair(bits);
}

RSAKeyPair::~RSAKeyPair() {
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(phi);
    mpz_clear(e);
    mpz_clear(d);
    gmp_randclear(rstate);
}

void RSAKeyPair::generateKeyPair(unsigned int bits) {
    // 生成两个大素数 p 和 q
    mpz_t temp;
    mpz_init(temp);
    
    // 确保 p 和 q 的位数大约为 bits/2
    unsigned int pbits = bits / 2;
    unsigned int qbits = bits - pbits;
    
    // 生成素数 p
    mpz_urandomb(p, rstate, pbits);
    mpz_setbit(p, pbits - 1);  // 确保 p 至少有 pbits 位
    mpz_nextprime(p, p);
    
    // 生成素数 q，确保 q != p
    do {
        mpz_urandomb(q, rstate, qbits);
        mpz_setbit(q, qbits - 1);  // 确保 q 至少有 qbits 位
        mpz_nextprime(q, q);
    } while (mpz_cmp(p, q) == 0);
    
    // 计算 n = p * q
    mpz_mul(n, p, q);
    
    // 计算 φ(n) = (p-1) * (q-1)
    mpz_sub_ui(temp, p, 1);
    mpz_sub_ui(phi, q, 1);
    mpz_mul(phi, phi, temp);
    
    // 选择公钥指数 e，通常使用 65537
    mpz_set_ui(e, 65537);
    
    // 确保 gcd(e, φ(n)) = 1
    mpz_gcd(temp, e, phi);
    if (mpz_cmp_ui(temp, 1) != 0) {
        // 如果 gcd(e, φ(n)) != 1，选择另一个 e
        mpz_set_ui(e, 65539);  // 下一个常用的公钥指数
        mpz_gcd(temp, e, phi);
        if (mpz_cmp_ui(temp, 1) != 0) {
            // 如果仍然不互质，找到一个互质的 e
            mpz_set_ui(e, 3);
            while (mpz_cmp_ui(temp, 1) != 0) {
                mpz_add_ui(e, e, 2);
                mpz_gcd(temp, e, phi);
            }
        }
    }
    
    // 计算私钥指数 d，满足 d*e ≡ 1 (mod φ(n))
    mpz_invert(d, e, phi);
    
    mpz_clear(temp);
}

std::pair<std::string, std::string> RSAKeyPair::getPublicKey() const {
    return {mpz_to_str(e), mpz_to_str(n)};
}

std::pair<std::string, std::string> RSAKeyPair::getPrivateKey() const {
    return {mpz_to_str(d), mpz_to_str(n)};
}

void RSAKeyPair::importPublicKey(const std::string& e_str, const std::string& n_str) {
    str_to_mpz(e, e_str);
    str_to_mpz(n, n_str);
}

void RSAKeyPair::importPrivateKey(const std::string& d_str, const std::string& n_str) {
    str_to_mpz(d, d_str);
    str_to_mpz(n, n_str);
}

// ============== RSABlindSignature 实现 ==============

void RSABlindSignature::initRandom() {
    gmp_randinit_mt(rstate);
    unsigned long seed = static_cast<unsigned long>(time(nullptr));
    gmp_randseed_ui(rstate, seed);
}

RSABlindSignature::RSABlindSignature(const RSAKeyPair& keyPair) 
    : hasPublicKey(true), hasPrivateKey(true) {
    mpz_init(e);
    mpz_init(d);
    mpz_init(n);
    
    // 从密钥对获取公钥和私钥
    auto publicKey = keyPair.getPublicKey();
    auto privateKey = keyPair.getPrivateKey();
    
    str_to_mpz(e, publicKey.first);
    str_to_mpz(d, privateKey.first);
    str_to_mpz(n, publicKey.second);
    
    initRandom();
}

RSABlindSignature::RSABlindSignature(const std::string& e_str, const std::string& n_str) 
    : hasPublicKey(true), hasPrivateKey(false) {
    mpz_init(e);
    mpz_init(d);
    mpz_init(n);
    
    str_to_mpz(e, e_str);
    str_to_mpz(n, n_str);
    
    initRandom();
}

RSABlindSignature::~RSABlindSignature() {
    mpz_clear(e);
    mpz_clear(d);
    mpz_clear(n);
    gmp_randclear(rstate);
}

void RSABlindSignature::setPublicKey(const std::string& e_str, const std::string& n_str) {
    str_to_mpz(e, e_str);
    str_to_mpz(n, n_str);
    hasPublicKey = true;
}

void RSABlindSignature::setPrivateKey(const std::string& d_str, const std::string& n_str) {
    str_to_mpz(d, d_str);
    str_to_mpz(n, n_str);
    hasPrivateKey = true;
}

// 用户: 生成盲因子
std::string RSABlindSignature::generateBlindingFactor() const {
    if (!hasPublicKey) {
        throw std::runtime_error("Public key is required to generate blinding factor");
    }
    
    mpz_t r, gcd_result;
    mpz_init(r);
    mpz_init(gcd_result);
    
    // 创建一个非const的随机数状态副本
    gmp_randstate_t temp_rstate;
    gmp_randinit_mt(temp_rstate);
    gmp_randseed_ui(temp_rstate, static_cast<unsigned long>(time(nullptr)));
    
    // 生成随机数 r，满足 gcd(r, n) = 1
    do {
        mpz_urandomm(r, temp_rstate, n);
        mpz_gcd(gcd_result, r, n);
    } while (mpz_cmp_ui(gcd_result, 1) != 0 || mpz_cmp_ui(r, 1) <= 0);
    
    std::string result = mpz_to_str(r);
    
    mpz_clear(r);
    mpz_clear(gcd_result);
    gmp_randclear(temp_rstate);
    
    return result;
}

// 用户: 使用公钥和盲因子对消息进行盲化
std::string RSABlindSignature::blind(const std::string& message, const std::string& blindingFactor) const {
    if (!hasPublicKey) {
        throw std::runtime_error("Public key is required for blinding");
    }
    
    mpz_t m, r, blinded_m;
    mpz_init(m);
    mpz_init(r);
    mpz_init(blinded_m);
    
    // 将消息转换为数字
    str_to_mpz(m, message);
    
    // 将盲因子转换为数字
    str_to_mpz(r, blindingFactor);
    
    // 计算盲化消息: m' = m * r^e mod n
    mpz_powm(blinded_m, r, e, n);  // r^e mod n
    mpz_mul(blinded_m, m, blinded_m);  // m * r^e
    mpz_mod(blinded_m, blinded_m, n);  // (m * r^e) mod n
    
    std::string result = mpz_to_str(blinded_m);
    
    mpz_clear(m);
    mpz_clear(r);
    mpz_clear(blinded_m);
    
    return result;
}

// 签名者: 对盲化消息进行签名
std::string RSABlindSignature::signBlindedMessage(const std::string& blindedMessage) const {
    if (!hasPrivateKey) {
        throw std::runtime_error("Private key is required for signing");
    }
    
    mpz_t blinded_m, blinded_sig;
    mpz_init(blinded_m);
    mpz_init(blinded_sig);
    
    // 将盲化消息转换为数字
    str_to_mpz(blinded_m, blindedMessage);
    
    // 计算盲签名: s' = (m')^d mod n
    mpz_powm(blinded_sig, blinded_m, d, n);
    
    std::string result = mpz_to_str(blinded_sig);
    
    mpz_clear(blinded_m);
    mpz_clear(blinded_sig);
    
    return result;
}

// 用户: 从盲签名中移除盲因子，获得原始消息的签名
std::string RSABlindSignature::unblind(const std::string& blindSignature, const std::string& blindingFactor) const {
    if (!hasPublicKey) {
        throw std::runtime_error("Public key is required for unblinding");
    }
    
    mpz_t blinded_sig, r, sig, r_inv;
    mpz_init(blinded_sig);
    mpz_init(r);
    mpz_init(sig);
    mpz_init(r_inv);
    
    // 将盲签名转换为数字
    str_to_mpz(blinded_sig, blindSignature);
    
    // 将盲因子转换为数字
    str_to_mpz(r, blindingFactor);
    
    // 计算 r 的模逆元: r^(-1) mod n
    if (mpz_invert(r_inv, r, n) == 0) {
        throw std::runtime_error("Failed to compute modular inverse of blinding factor");
    }
    
    // 计算原始签名: s = s' * r^(-1) mod n
    mpz_mul(sig, blinded_sig, r_inv);
    mpz_mod(sig, sig, n);
    
    std::string result = mpz_to_str(sig);
    
    mpz_clear(blinded_sig);
    mpz_clear(r);
    mpz_clear(sig);
    mpz_clear(r_inv);
    
    return result;
}

// 验证签名
bool RSABlindSignature::verify(const std::string& message, const std::string& signature) const {
    if (!hasPublicKey) {
        throw std::runtime_error("Public key is required for verification");
    }
    
    mpz_t m, sig, decrypted_sig;
    mpz_init(m);
    mpz_init(sig);
    mpz_init(decrypted_sig);
    
    // 将消息转换为数字
    str_to_mpz(m, message);
    
    // 将签名转换为数字
    str_to_mpz(sig, signature);
    
    // 验证签名: m == sig^e mod n
    mpz_powm(decrypted_sig, sig, e, n);
    
    // 比较解密后的签名与原始消息
    int result = mpz_cmp(decrypted_sig, m);
    
    mpz_clear(m);
    mpz_clear(sig);
    mpz_clear(decrypted_sig);
    
    return result == 0;
} 