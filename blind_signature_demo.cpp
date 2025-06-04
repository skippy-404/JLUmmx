#include "rsa_blind_signature.h"
#include <iostream>
#include <string>
#include <iomanip>

// 辅助函数：打印分隔线
void printSeparator() {
    std::cout << std::setfill('=') << std::setw(60) << "" << std::setfill(' ') << std::endl;
}

// 辅助函数：打印步骤标题
void printStep(int stepNumber, const std::string& title) {
    std::cout << "\n步骤 " << stepNumber << ": " << title << std::endl;
    std::cout << std::setfill('-') << std::setw(60) << "" << std::setfill(' ') << std::endl;
}

int main() {
    std::cout << "RSA盲签名（Blind Signature）演示程序" << std::endl;
    printSeparator();
    std::cout << "盲签名允许用户获得消息的签名，而不向签名者透露消息内容。" << std::endl;
    std::cout << "这在电子货币、电子投票等需要隐私保护的场景中非常有用。" << std::endl;
    
    try {
        // 步骤1：生成RSA密钥对
        printStep(1, "生成RSA密钥对");
        std::cout << "正在生成1024位RSA密钥对..." << std::endl;
        RSAKeyPair keyPair(1024); // 使用较小的密钥长度以加快演示速度
        
        // 显示公钥和私钥
        auto publicKey = keyPair.getPublicKey();
        auto privateKey = keyPair.getPrivateKey();
        
        std::cout << "公钥 (e, n):" << std::endl;
        std::cout << "e = " << publicKey.first << std::endl;
        std::cout << "n = " << publicKey.second << std::endl << std::endl;
        
        std::cout << "私钥 (d, n):" << std::endl;
        std::cout << "d = " << privateKey.first << std::endl;
        std::cout << "n = " << privateKey.second << std::endl;
        
        // 步骤2：初始化盲签名对象
        printStep(2, "初始化盲签名对象");
        RSABlindSignature blindSig(keyPair);
        std::cout << "盲签名对象已初始化，包含公钥和私钥" << std::endl;
        
        // 步骤3：用户准备要签名的消息
        printStep(3, "用户准备要签名的消息");
        std::string message = "这是一条需要签名但不想让签名者看到的秘密消息";
        std::cout << "原始消息: " << message << std::endl;
        
        // 对消息进行哈希处理（在实际应用中通常会这样做）
        std::string messageHash = simpleHash(message);
        std::cout << "消息哈希: " << messageHash << std::endl;
        
        // 步骤4：用户生成盲因子
        printStep(4, "用户生成盲因子");
        std::string blindingFactor = blindSig.generateBlindingFactor();
        std::cout << "盲因子: " << blindingFactor << std::endl;
        
        // 步骤5：用户使用盲因子对消息进行盲化
        printStep(5, "用户使用盲因子对消息进行盲化");
        std::string blindedMessage = blindSig.blind(messageHash, blindingFactor);
        std::cout << "盲化后的消息: " << blindedMessage << std::endl;
        
        // 步骤6：签名者对盲化消息进行签名
        printStep(6, "签名者对盲化消息进行签名");
        std::cout << "签名者看到的是盲化后的消息，无法知道原始内容" << std::endl;
        std::string blindSignature = blindSig.signBlindedMessage(blindedMessage);
        std::cout << "盲签名: " << blindSignature << std::endl;
        
        // 步骤7：用户移除盲因子，获得原始消息的签名
        printStep(7, "用户移除盲因子，获得原始消息的签名");
        std::string signature = blindSig.unblind(blindSignature, blindingFactor);
        std::cout << "去盲后的签名: " << signature << std::endl;
        
        // 步骤8：验证签名
        printStep(8, "验证签名");
        bool isValid = blindSig.verify(messageHash, signature);
        std::cout << "签名验证结果: " << (isValid ? "有效" : "无效") << std::endl;
        
        // 额外测试：尝试修改消息后验证
        std::string tamperedMessage = messageHash + "1"; // 在哈希末尾添加"1"
        bool isTamperedValid = blindSig.verify(tamperedMessage, signature);
        std::cout << "\n修改消息后验证结果: " << (isTamperedValid ? "有效" : "无效") << std::endl;
        std::cout << "（这表明签名确实与原始消息绑定，修改消息会导致验证失败）" << std::endl;
        
        printSeparator();
        std::cout << "\n盲签名演示完成！" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
} 