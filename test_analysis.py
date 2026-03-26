from src.leaklens.config.深度分析 import DeepAnalyzer

# 初始化分析器
analyzer = DeepAnalyzer()

# 测试数据
test_data = { 
    'type': 'Internal IP', 
    'matched_text': '192.168.1.1', 
    'severity': 'INFO', 
    'location': 'test', 
    'confidence': 0.25, 
    'entropy': 0, 
    'id': 'test-1' 
}
context = { 'url': 'http://test.com' }

# 测试语义分析
print("=== 测试语义分析 ===")
prompt = f"""请用中文分析以下内容是否为真实的敏感信息（不是测试数据）：

信息类型：{test_data.get('type', 'unknown')}
信息内容："{test_data.get('matched_text', '')}"
发现位置：{context.get('url', 'unknown')}
周围文本："{context.get('surrounding_text', '')[:300]}"

请进行以下分析：
1. 这是真实的敏感信息还是测试/示例数据？
2. 如果是敏感信息，它属于什么具体类型？（身份证、手机号、API密钥、CSRF令牌等）
3. 详细分析信息的格式和特征，说明为什么它是敏感信息
4. 评估该信息的敏感度等级（高、中、低）
5. 置信度评分（0-1）

你必须以JSON格式返回，所有内容使用中文，例如：
{{"is_real": true, "type": "CSRF令牌", "confidence": 0.95, "reason": "符合CSRF令牌格式，出现在HTML头部脚本中", "sensitivity": "中等", "details": "令牌长度为40字符，包含字母和数字，符合CSRF令牌特征"}}"""

print("Prompt:", prompt)
response = analyzer._call_llm_generate(prompt)
print("\n模型返回:", response)

cleaned = analyzer._extract_json(response)
print("\n提取的JSON:", cleaned)

try:
    import json
    result = json.loads(cleaned)
    print("\n解析结果:", result)
except Exception as e:
    print("\n解析失败:", e)
