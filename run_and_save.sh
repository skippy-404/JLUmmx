#!/bin/bash

# 编译程序
echo "编译程序..."
make

# 检查编译是否成功
if [ $? -ne 0 ]; then
    echo "编译失败，退出脚本"
    exit 1
fi

# 创建输出目录（如果不存在）
mkdir -p output

# 获取当前时间戳
timestamp=$(date +"%Y%m%d_%H%M%S")
output_file="output/blind_signature_demo_${timestamp}.txt"

# 运行程序并保存输出
echo "运行程序并将输出保存到 ${output_file}..."
./blind_signature_demo | tee "${output_file}"

echo ""
echo "程序执行完成，输出已保存到 ${output_file}" 