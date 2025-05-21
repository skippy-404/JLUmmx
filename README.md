# RSA公钥密码算法实现

这是一个使用C++实现的RSA公钥密码算法，支持以下功能：

1. 密钥生成算法
2. 加密算法
3. 解密算法
4. 数字签名
5. 证书生成和验证

## 特性

- 采用GMP大数库实现大整数运算，支持2048位及以上密钥
- 完整实现RSA加密、解密、签名和验证功能
- 支持生成和验证X.509格式的简化版证书
- 支持分块加密，可加密任意长度的字符串消息

## 编译要求

- C++11或更高版本
- GMP (GNU Multiple Precision Arithmetic Library)
- 支持Linux、macOS和Windows（需配置适当的开发环境）

## 编译方法

首先确保安装了GMP库：

### Ubuntu/Debian
```bash
sudo apt-get install libgmp-dev
```

### macOS
```bash
brew install gmp
```

### 编译
```bash
make
```

## 运行方法

编译成功后，运行生成的可执行文件：

```bash
./rsa_demo
```

## 类结构

- `RSAKeyPair`: 用于生成和管理RSA密钥对
- `RSA`: 提供加密、解密、签名和验证功能
- `Certificate`: 提供证书生成、保存、加载和验证功能 