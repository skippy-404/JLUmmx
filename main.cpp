#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include "rsa.h"

int main() {
    std::cout << "RSA公钥密码算法演示程序" << std::endl;
    std::cout << "=======================" << std::endl << std::endl;
    
    // 1. 生成密钥对
    std::cout << "正在生成RSA密钥对（2048位）..." << std::endl;
    RSAKeyPair keyPair(2048);
    std::cout << "密钥对生成完成！" << std::endl << std::endl;
    
    // 显示公钥和私钥
    std::pair<std::string, std::string> publicKey = keyPair.getPublicKey();
    std::pair<std::string, std::string> privateKey = keyPair.getPrivateKey();
    
    std::cout << "公钥 (e, n):" << std::endl;
    std::cout << "e = " << publicKey.first << std::endl;
    std::cout << "n = " << publicKey.second << std::endl << std::endl;
    
    std::cout << "私钥 (d, n):" << std::endl;
    std::cout << "d = " << privateKey.first << std::endl;
    std::cout << "n = " << privateKey.second << std::endl << std::endl;
    
    // 2. 使用公钥加密消息
    std::string message = "这是一条测试消息，将使用RSA算法进行加密和解密。";
    std::cout << "原始消息: " << message << std::endl;
    
    const RSA rsa(keyPair);
    std::vector<std::string> ciphertext = rsa.encryptString(message);
    
    std::cout << "加密后的密文:" << std::endl;
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        std::cout << "块 " << (i + 1) << ": " << ciphertext[i] << std::endl;
    }
    std::cout << std::endl;
    
    // 3. 使用私钥解密消息
    std::string decryptedMessage = rsa.decryptString(ciphertext);
    std::cout << "解密后的消息: " << decryptedMessage << std::endl << std::endl;
    
    // 4. 数字签名
    std::string documentToSign = "这是一份需要签名的文档";
    std::cout << "需要签名的文档: " << documentToSign << std::endl;
    
    // 计算文档哈希
    std::string documentHash = simpleHash(documentToSign);
    std::cout << "文档哈希: " << documentHash << std::endl;
    
    // 使用私钥签名
    std::string signature = rsa.sign(documentHash);
    std::cout << "数字签名: " << signature << std::endl;
    
    // 使用公钥验证签名
    bool isValid = rsa.verify(documentHash, signature);
    std::cout << "签名验证结果: " << (isValid ? "有效" : "无效") << std::endl << std::endl;
    
    // 5. 生成证书
    try {
        std::cout << "生成数字证书..." << std::endl;
        Certificate cert("CN=RSA Demo,O=RSA Test,C=CN", keyPair);
        
        std::cout << "证书生成完成！" << std::endl;
        std::cout << "证书主题: " << cert.getSubject() << std::endl;
        std::cout << "证书签名: " << cert.getSignature() << std::endl;
        
        // 保存证书到文件
        std::string certFile = "rsa_certificate.cert";
        if (cert.save(certFile)) {
            std::cout << "证书已保存到文件: " << certFile << std::endl << std::endl;
        } else {
            std::cout << "证书保存失败！" << std::endl << std::endl;
        }
        
        // 加载并验证证书
        std::cout << "从文件加载证书..." << std::endl;
        Certificate loadedCert(certFile);
        std::cout << "证书加载成功！" << std::endl;
        
        // 验证证书
        std::cout << "验证证书签名..." << std::endl;
        bool isCertValid = loadedCert.verify(rsa);
        std::cout << "证书验证结果: " << (isCertValid ? "有效" : "无效") << std::endl;
    } catch (const std::exception& e) {
        std::cout << "错误: " << e.what() << std::endl;
    }
    
    return 0;
} 