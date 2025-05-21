#include "rsa.h"
#include <ctime>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <random>
#include <chrono>

// RSAKeyPair实现

RSAKeyPair::RSAKeyPair(unsigned int bits) {
    // 初始化GMP变量
    mpz_init(p);
    mpz_init(q);
    mpz_init(n);
    mpz_init(phi);
    mpz_init(e);
    mpz_init(d);
    
    // 初始化随机数生成器
    initRandom();
    
    // 生成密钥对
    generateKeyPair(bits);
}

RSAKeyPair::~RSAKeyPair() {
    // 清理GMP变量
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(phi);
    mpz_clear(e);
    mpz_clear(d);
    
    // 清理随机数生成器
    gmp_randclear(rstate);
}

void RSAKeyPair::initRandom() {
    // 初始化随机数生成器
    gmp_randinit_mt(rstate);
    
    // 使用当前时间和随机设备作为种子
    unsigned long seed = static_cast<unsigned long>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    std::random_device rd;
    seed ^= rd();
    
    gmp_randseed_ui(rstate, seed);
}

void RSAKeyPair::generateKeyPair(unsigned int bits) {
    // 确保位数足够大
    if (bits < 256) {
        bits = 256;
    }
    
    // 生成两个大素数p和q
    mpz_t temp;
    mpz_init(temp);
    
    // 生成素数p
    while (1) {
        mpz_urandomb(p, rstate, bits / 2);
        // 设置最高位为1，确保生成的数足够大
        mpz_setbit(p, bits / 2 - 1);
        // 设置最低位为1，确保是奇数
        mpz_setbit(p, 0);
        
        // 进行素性检测
        if (mpz_probab_prime_p(p, 50) > 0) {
            break;
        }
    }
    
    // 生成素数q，确保q != p
    while (1) {
        mpz_urandomb(q, rstate, bits / 2);
        // 设置最高位为1，确保生成的数足够大
        mpz_setbit(q, bits / 2 - 1);
        // 设置最低位为1，确保是奇数
        mpz_setbit(q, 0);
        
        // 确保q != p
        if (mpz_cmp(p, q) == 0) {
            continue;
        }
        
        // 进行素性检测
        if (mpz_probab_prime_p(q, 50) > 0) {
            break;
        }
    }
    
    // 计算n = p*q
    mpz_mul(n, p, q);
    
    // 计算欧拉函数值 φ(n) = (p-1)*(q-1)
    mpz_sub_ui(temp, p, 1);      // temp = p-1
    mpz_sub_ui(phi, q, 1);       // phi = q-1
    mpz_mul(phi, phi, temp);     // phi = (p-1)*(q-1)
    
    // 选择公钥指数e，常用值65537
    mpz_set_ui(e, 65537);
    
    // 确保gcd(e, phi) = 1
    mpz_t gcd_result;
    mpz_init(gcd_result);
    
    mpz_gcd(gcd_result, e, phi);
    
    while (mpz_cmp_ui(gcd_result, 1) != 0) {
        mpz_add_ui(e, e, 2);
        mpz_gcd(gcd_result, e, phi);
    }
    
    // 计算私钥指数d，满足d*e ≡ 1 (mod φ(n))
    mpz_invert(d, e, phi);
    
    mpz_clear(gcd_result);
    mpz_clear(temp);
}

std::pair<std::string, std::string> RSAKeyPair::getPublicKey() const {
    char* e_str = mpz_get_str(nullptr, 16, e);
    char* n_str = mpz_get_str(nullptr, 16, n);
    
    std::string e_string(e_str);
    std::string n_string(n_str);
    
    free(e_str);
    free(n_str);
    
    return std::make_pair(e_string, n_string);
}

std::pair<std::string, std::string> RSAKeyPair::getPrivateKey() const {
    char* d_str = mpz_get_str(nullptr, 16, d);
    char* n_str = mpz_get_str(nullptr, 16, n);
    
    std::string d_string(d_str);
    std::string n_string(n_str);
    
    free(d_str);
    free(n_str);
    
    return std::make_pair(d_string, n_string);
}

void RSAKeyPair::importPublicKey(const std::string& e_str, const std::string& n_str) {
    mpz_set_str(e, e_str.c_str(), 16);
    mpz_set_str(n, n_str.c_str(), 16);
}

void RSAKeyPair::importPrivateKey(const std::string& d_str, const std::string& n_str) {
    mpz_set_str(d, d_str.c_str(), 16);
    mpz_set_str(n, n_str.c_str(), 16);
}

// RSA实现

RSA::RSA(const RSAKeyPair& keyPair) {
    mpz_init(e);
    mpz_init(d);
    mpz_init(n);
    
    // 导入公钥
    std::pair<std::string, std::string> pubKey = keyPair.getPublicKey();
    mpz_set_str(e, pubKey.first.c_str(), 16);
    mpz_set_str(n, pubKey.second.c_str(), 16);
    hasPublicKey = true;
    
    // 导入私钥
    std::pair<std::string, std::string> privKey = keyPair.getPrivateKey();
    mpz_set_str(d, privKey.first.c_str(), 16);
    hasPrivateKey = true;
}

RSA::RSA(const std::string& e_str, const std::string& n_str) {
    mpz_init(e);
    mpz_init(d);
    mpz_init(n);
    
    // 导入公钥
    mpz_set_str(e, e_str.c_str(), 16);
    mpz_set_str(n, n_str.c_str(), 16);
    hasPublicKey = true;
    hasPrivateKey = false;
}

RSA::~RSA() {
    mpz_clear(e);
    mpz_clear(d);
    mpz_clear(n);
}

void RSA::setPublicKey(const std::string& e_str, const std::string& n_str) {
    mpz_set_str(e, e_str.c_str(), 16);
    mpz_set_str(n, n_str.c_str(), 16);
    hasPublicKey = true;
}

void RSA::setPrivateKey(const std::string& d_str, const std::string& n_str) {
    mpz_set_str(d, d_str.c_str(), 16);
    mpz_set_str(n, n_str.c_str(), 16);
    hasPrivateKey = true;
}

std::string RSA::encrypt(const std::string& message) const {
    if (!hasPublicKey) {
        throw std::runtime_error("需要公钥进行加密");
    }
    
    mpz_t m, c;
    mpz_init(m);
    mpz_init(c);
    
    // 将消息转换为大整数
    mpz_set_str(m, message.c_str(), 16);
    
    // 检查消息是否小于n
    if (mpz_cmp(m, n) >= 0) {
        mpz_clear(m);
        mpz_clear(c);
        throw std::runtime_error("消息过大，无法加密");
    }
    
    // 使用公式 c = m^e mod n 加密
    mpz_powm(c, m, e, n);
    
    // 将结果转换为十六进制字符串
    char* c_str = mpz_get_str(nullptr, 16, c);
    std::string result(c_str);
    free(c_str);
    
    mpz_clear(m);
    mpz_clear(c);
    
    return result;
}

std::string RSA::decrypt(const std::string& ciphertext) const {
    if (!hasPrivateKey) {
        throw std::runtime_error("需要私钥进行解密");
    }
    
    mpz_t c, m;
    mpz_init(c);
    mpz_init(m);
    
    // 将密文转换为大整数
    mpz_set_str(c, ciphertext.c_str(), 16);
    
    // 使用公式 m = c^d mod n 解密
    mpz_powm(m, c, d, n);
    
    // 将结果转换为十六进制字符串
    char* m_str = mpz_get_str(nullptr, 16, m);
    std::string result(m_str);
    free(m_str);
    
    mpz_clear(c);
    mpz_clear(m);
    
    return result;
}

std::vector<std::string> RSA::encryptString(const std::string& message) const {
    if (!hasPublicKey) {
        throw std::runtime_error("需要公钥进行加密");
    }
    
    std::vector<std::string> result;
    
    // 计算每个块可以容纳的字节数
    size_t keySize = mpz_sizeinbase(n, 2);
    size_t blockSize = (keySize - 1) / 8;  // 留出一个字节的安全边界
    
    for (size_t i = 0; i < message.length(); i += blockSize) {
        // 提取当前块
        size_t currentBlockSize = std::min(blockSize, message.length() - i);
        std::string block = message.substr(i, currentBlockSize);
        
        // 将块转换为十六进制字符串
        std::stringstream ss;
        for (char c : block) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(c));
        }
        
        // 加密块
        std::string encryptedBlock = encrypt(ss.str());
        result.push_back(encryptedBlock);
    }
    
    return result;
}

std::string RSA::decryptString(const std::vector<std::string>& ciphertext) const {
    if (!hasPrivateKey) {
        throw std::runtime_error("需要私钥进行解密");
    }
    
    std::string result;
    
    for (const std::string& block : ciphertext) {
        // 解密块
        std::string decryptedHex = decrypt(block);
        
        // 确保十六进制字符串长度为偶数
        if (decryptedHex.length() % 2 != 0) {
            decryptedHex = "0" + decryptedHex;
        }
        
        // 将十六进制字符串转换回字符
        for (size_t i = 0; i < decryptedHex.length(); i += 2) {
            std::string byteString = decryptedHex.substr(i, 2);
            char byte = static_cast<char>(std::stoi(byteString, nullptr, 16));
            result.push_back(byte);
        }
    }
    
    return result;
}

std::string RSA::sign(const std::string& message) const {
    if (!hasPrivateKey) {
        throw std::runtime_error("需要私钥进行签名");
    }
    
    mpz_t m, s;
    mpz_init(m);
    mpz_init(s);
    
    // 将消息转换为大整数
    mpz_set_str(m, message.c_str(), 16);
    
    // 检查消息是否小于n
    if (mpz_cmp(m, n) >= 0) {
        mpz_clear(m);
        mpz_clear(s);
        throw std::runtime_error("消息过大，无法签名");
    }
    
    // 使用私钥签名：s = m^d mod n
    mpz_powm(s, m, d, n);
    
    // 将结果转换为十六进制字符串
    char* s_str = mpz_get_str(nullptr, 16, s);
    std::string result(s_str);
    free(s_str);
    
    mpz_clear(m);
    mpz_clear(s);
    
    return result;
}

bool RSA::verify(const std::string& message, const std::string& signature) const {
    if (!hasPublicKey) {
        throw std::runtime_error("需要公钥进行验证");
    }
    
    mpz_t m, s, v;
    mpz_init(m);
    mpz_init(s);
    mpz_init(v);
    
    // 将消息和签名转换为大整数
    mpz_set_str(m, message.c_str(), 16);
    mpz_set_str(s, signature.c_str(), 16);
    
    // 使用公钥验证：v = s^e mod n
    mpz_powm(v, s, e, n);
    
    // 比较v和m是否相等
    bool result = (mpz_cmp(v, m) == 0);
    
    mpz_clear(m);
    mpz_clear(s);
    mpz_clear(v);
    
    return result;
}

// Certificate实现

Certificate::Certificate(const std::string& subject, const RSAKeyPair& keyPair) 
    : subject(subject) {
    try {
        // 获取公钥
        pubKey = keyPair.getPublicKey();
        
        // 生成序列号
        generateSerialNumber();
        
        // 设置有效期
        setValidity();
        
        // 创建RSA对象用于签名
        RSA rsa(keyPair);
        
        // 创建证书内容的摘要
        std::stringstream ss;
        ss << subject << ";" 
           << pubKey.first << ";" 
           << pubKey.second << ";" 
           << serialNumber << ";" 
           << validFrom << ";" 
           << validTo;
        
        // 计算摘要的哈希值
        std::string digestHash = simpleHash(ss.str());
        
        // 签名摘要
        signature = rsa.sign(digestHash);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("证书生成失败: ") + e.what());
    }
}

Certificate::Certificate(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("无法打开证书文件");
    }
    
    std::string line;
    
    // 读取主题
    if (!std::getline(file, line)) {
        throw std::runtime_error("证书格式错误：读取错误");
    }
    
    if (line.substr(0, 8) != "Subject:") {
        throw std::runtime_error("证书格式错误：缺少主题标签");
    }
    
    // 找到冒号后的第一个非空格字符
    size_t pos = line.find(':');
    if (pos != std::string::npos) {
        pos++; // 跳过冒号
        // 跳过空格
        while (pos < line.size() && line[pos] == ' ') {
            pos++;
        }
        subject = line.substr(pos);
    } else {
        throw std::runtime_error("证书格式错误：主题格式不正确");
    }
    
    // 读取公钥
    std::string e_str, n_str;
    if (!std::getline(file, line)) {
        throw std::runtime_error("证书格式错误：读取错误");
    }
    
    if (line != "Public Key:") {
        throw std::runtime_error("证书格式错误：缺少公钥标签");
    }
    
    // 读取公钥e
    if (!std::getline(file, line)) {
        throw std::runtime_error("证书格式错误：读取错误");
    }
    
    if (line.substr(0, 2) != "e:") {
        throw std::runtime_error("证书格式错误：缺少公钥e标签");
    }
    
    pos = line.find(':');
    if (pos != std::string::npos) {
        pos++; // 跳过冒号
        // 跳过空格
        while (pos < line.size() && line[pos] == ' ') {
            pos++;
        }
        e_str = line.substr(pos);
    } else {
        throw std::runtime_error("证书格式错误：公钥e格式不正确");
    }
    
    // 读取公钥n
    if (!std::getline(file, line)) {
        throw std::runtime_error("证书格式错误：读取错误");
    }
    
    if (line.substr(0, 2) != "n:") {
        throw std::runtime_error("证书格式错误：缺少公钥n标签");
    }
    
    pos = line.find(':');
    if (pos != std::string::npos) {
        pos++; // 跳过冒号
        // 跳过空格
        while (pos < line.size() && line[pos] == ' ') {
            pos++;
        }
        n_str = line.substr(pos);
    } else {
        throw std::runtime_error("证书格式错误：公钥n格式不正确");
    }
    
    pubKey = std::make_pair(e_str, n_str);
    
    // 读取序列号
    if (!std::getline(file, line)) {
        throw std::runtime_error("证书格式错误：读取错误");
    }
    
    if (line.substr(0, 14) != "Serial Number:") {
        throw std::runtime_error("证书格式错误：缺少序列号标签");
    }
    
    pos = line.find(':');
    if (pos != std::string::npos) {
        pos++; // 跳过冒号
        // 跳过空格
        while (pos < line.size() && line[pos] == ' ') {
            pos++;
        }
        serialNumber = line.substr(pos);
    } else {
        throw std::runtime_error("证书格式错误：序列号格式不正确");
    }
    
    // 读取有效期开始
    if (!std::getline(file, line)) {
        throw std::runtime_error("证书格式错误：读取错误");
    }
    
    if (line.substr(0, 11) != "Valid From:") {
        throw std::runtime_error("证书格式错误：缺少有效期开始标签");
    }
    
    pos = line.find(':');
    if (pos != std::string::npos) {
        pos++; // 跳过冒号
        // 跳过空格
        while (pos < line.size() && line[pos] == ' ') {
            pos++;
        }
        validFrom = line.substr(pos);
    } else {
        throw std::runtime_error("证书格式错误：有效期开始格式不正确");
    }
    
    // 读取有效期结束
    if (!std::getline(file, line)) {
        throw std::runtime_error("证书格式错误：读取错误");
    }
    
    if (line.substr(0, 9) != "Valid To:") {
        throw std::runtime_error("证书格式错误：缺少有效期结束标签");
    }
    
    pos = line.find(':');
    if (pos != std::string::npos) {
        pos++; // 跳过冒号
        // 跳过空格
        while (pos < line.size() && line[pos] == ' ') {
            pos++;
        }
        validTo = line.substr(pos);
    } else {
        throw std::runtime_error("证书格式错误：有效期结束格式不正确");
    }
    
    // 读取签名
    if (!std::getline(file, line)) {
        throw std::runtime_error("证书格式错误：读取错误");
    }
    
    if (line.substr(0, 10) != "Signature:") {
        throw std::runtime_error("证书格式错误：缺少签名标签");
    }
    
    pos = line.find(':');
    if (pos != std::string::npos) {
        pos++; // 跳过冒号
        // 跳过空格
        while (pos < line.size() && line[pos] == ' ') {
            pos++;
        }
        signature = line.substr(pos);
    } else {
        throw std::runtime_error("证书格式错误：签名格式不正确");
    }
    
    file.close();
}

bool Certificate::save(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    file << "Subject: " << subject << std::endl;
    file << "Public Key:" << std::endl;
    file << "e: " << pubKey.first << std::endl;
    file << "n: " << pubKey.second << std::endl;
    file << "Serial Number: " << serialNumber << std::endl;
    file << "Valid From: " << validFrom << std::endl;
    file << "Valid To: " << validTo << std::endl;
    file << "Signature: " << signature << std::endl;
    
    file.close();
    return true;
}

std::string Certificate::getSubject() const {
    return subject;
}

std::pair<std::string, std::string> Certificate::getPublicKey() const {
    return pubKey;
}

std::string Certificate::getSignature() const {
    return signature;
}

bool Certificate::verify(const RSA& verifier) const {
    // 创建证书内容的摘要
    std::stringstream ss;
    ss << subject << ";" 
       << pubKey.first << ";" 
       << pubKey.second << ";" 
       << serialNumber << ";" 
       << validFrom << ";" 
       << validTo;
    
    // 计算摘要的哈希值
    std::string digestHash = simpleHash(ss.str());
    
    // 验证签名
    return verifier.verify(digestHash, signature);
}

void Certificate::generateSerialNumber() {
    // 使用当前时间和随机数生成序列号
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    for (int i = 0; i < 16; ++i) {
        ss << std::hex << dis(gen);
    }
    
    serialNumber = ss.str();
}

void Certificate::setValidity(int days) {
    // 获取当前时间
    std::time_t now = std::time(nullptr);
    std::tm* timeinfo = std::localtime(&now);
    
    char buffer[80];
    
    // 设置有效期开始时间
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    validFrom = buffer;
    
    // 设置有效期结束时间
    timeinfo->tm_mday += days;
    std::mktime(timeinfo);  // 规范化时间
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    validTo = buffer;
} 