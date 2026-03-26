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

# 直接调用_semantic_analysis方法
print("=== 测试完整的_semantic_analysis方法 ===")
result = analyzer._semantic_analysis(test_data, context)
print("语义分析结果:", result)
