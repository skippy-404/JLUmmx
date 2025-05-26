# Merkle-Hellman 背包公钥密码算法实现

这是一个使用C++实现的Merkle-Hellman (MH) 背包公钥密码算法，主要用于教学和演示目的。它支持以下核心功能：

1.  **密钥生成算法**: 生成MH公钥（普通背包序列）和私钥（超递增背包序列、模数q、乘数r及其逆元）。
2.  **加密算法**: 使用公钥将消息（文本字符串）加密为密文和。
3.  **解密算法**: 使用私钥将密文和解密回原始消息。
4.  **大数运算**: 采用GMP大数库处理运算，确保模数q满足至少256位的要求。
5.  **证书（模拟）**: 包含一个简化的证书结构，用于演示如何将MH公钥与主体信息关联。

**重要提示**: Merkle-Hellman背包密码系统在历史上已被证明是不安全的，不应用于实际生产环境中的安全需求。此实现主要用于理解其工作原理。

## 特性

-   基于背包问题的公钥密码体制。
-   使用GMP (GNU Multiple Precision Arithmetic Library) 进行大数运算。
-   密钥生成过程包括创建超递增序列、选择模数 `q` 和乘数 `r`。
-   支持将文本消息转换为二进制后进行分块加密。
-   包含一个模拟的证书类 `CertificateMH` 来展示公钥的分发概念。

## 编译要求

-   C++11 或更高版本编译器 (如 g++)
-   GMP (GNU Multiple Precision Arithmetic Library)

## 安装GMP库

### Ubuntu/Debian
```bash
sudo apt-get install libgmp-dev
```

### macOS (使用 Homebrew)
```bash
brew install gmp
```

### Fedora/CentOS
```bash
sudo yum install gmp-devel
```

## 编译方法

项目包含一个 `Makefile`。在项目根目录下执行：

```bash
make
```

如果需要手动编译（假设在macOS上使用Homebrew安装的GMP）：
```bash
# 编译 Merkle-Hellman 核心逻辑
g++ -c mh_knapsack.cpp -o mh_knapsack.o -std=c++11 -I/opt/homebrew/include

# 编译主程序
g++ -c main.cpp -o main.o -std=c++11 -I/opt/homebrew/include

# 链接生成可执行文件 (例如 mh_demo)
g++ main.o mh_knapsack.o -o mh_demo -L/opt/homebrew/lib -lgmp -std=c++11
```
(请根据您的GMP安装路径调整 `-I` 和 `-L` 标志)

## 运行方法

编译成功后，运行生成的可执行文件 (默认为 `mh_demo`，如果使用Makefile可能是 `main` 或其他在Makefile中定义的目标名)：

```bash
./mh_demo
```
或者，如果Makefile生成的目标是 `main`：
```bash
./main
```

## 类结构

-   `MHKeyPair`: 用于生成和管理Merkle-Hellman密钥对。
    -   私钥组件: 超递增序列 `w`，模数 `q`，乘数 `r`，`r`的模`q`逆元 `r_inv`。
    -   公钥组件: 普通背包序列 `b` (由 `w`, `r`, `q` 导出)。
-   `MerkleHellman`: 提供使用MH密钥对进行加密和解密的功能。
-   `CertificateMH`: 一个简化的类，用于模拟包含MH公钥和主体信息的证书。

## 注意事项

-   此项目是根据实验要求从RSA实现修改而来，专注于Merkle-Hellman算法。
-   由于MH算法的已知安全漏洞，请勿在任何需要安全保障的真实场景中使用此代码。 