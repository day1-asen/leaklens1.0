# LFM2.5-1.2B-Thinking 模型部署指南

## 概述

本指南说明如何在 LeakLens 项目中部署和使用 LFM2.5-1.2B-Thinking 本地模型。

## 步骤 1: 下载模型

1. 从官方渠道下载 LFM2.5-1.2B-Thinking 模型文件
2. 将模型文件解压到项目根目录，形成以下结构：
   ```
   leaklens/
   ├── LFM2.5-1.2B-Thinking/
   │   ├── config.json
   │   ├── model.safetensors
   │   └── tokenizer.json
   ├── src/
   ├── tests/
   └── ...
   ```

## 步骤 2: 安装依赖

```bash
# 安装基本依赖
pip install transformers torch

# 安装加速库（可选，用于更快的推理）
pip install accelerate optimum

# 安装量化库（可选，用于减少内存使用）
pip install bitsandbytes
```

## 步骤 3: 测试模型

运行测试脚本验证模型是否正确加载：

```bash
python test_model.py
```

## 步骤 4: 在项目中使用模型

### 方法 1: 使用 generate_text 函数

```python
from leaklens import generate_text

# 生成文本
response = generate_text("Explain what LeakLens is and how it works")
print(response)
```

### 方法 2: 直接使用 LFModel 类

```python
from leaklens import get_lf_model

# 获取模型实例
model = get_lf_model()

# 生成文本
response = model.generate("Explain what LeakLens is and how it works")
print(response)
```

## 配置选项

### 模型路径

默认情况下，模型会从 `./LFM2.5-1.2B-Thinking` 路径加载。如果模型位于其他位置，可以在初始化时指定：

```python
from leaklens import get_lf_model

# 从自定义路径加载模型
model = get_lf_model(model_path="/path/to/LFM2.5-1.2B-Thinking")
```

### 设备选择

默认情况下，模型会自动使用可用的 CUDA 设备（如果有），否则使用 CPU：

```python
from leaklens import get_lf_model

# 强制使用 CPU
model = get_lf_model(device="cpu")

# 强制使用 CUDA
model = get_lf_model(device="cuda")
```

### 量化设置

默认情况下，模型不使用量化。如果需要减少内存使用，可以启用 4-bit 量化：

```python
from leaklens import get_lf_model

# 启用 4-bit 量化
model = get_lf_model(use_quantization=True)
```

## 常见问题

### 1. 模型加载失败

- 确保模型文件完整且路径正确
- 检查依赖是否安装正确
- 确保有足够的内存（至少 4GB RAM 用于 CPU 推理）

### 2. 推理速度慢

- 尝试使用 CUDA 设备
- 启用 4-bit 量化
- 减少生成的文本长度

### 3. 内存不足

- 启用 4-bit 量化
- 使用更小的模型
- 增加系统内存

## 示例

```python
# 示例 1: 基本使用
from leaklens import generate_text

response = generate_text("What is LeakLens?")
print(response)

# 示例 2: 自定义参数
from leaklens import get_lf_model

model = get_lf_model(
    model_path="./LFM2.5-1.2B-Thinking",
    use_quantization=True,
    device="cuda"
)

response = model.generate(
    "How to use LeakLens for web scraping?",
    max_length=300,
    temperature=0.8
)
print(response)
```
