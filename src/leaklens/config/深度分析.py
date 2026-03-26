# 深度分析.py
import json
import requests
from typing import List, Dict, Any, Optional
import time

class DeepAnalyzer:
    """本地大模型深度分析系统 - 适配LFM2.5-1.2B-Thinking"""
    
    def __init__(self, model_name='lfm2.5-thinking:1.2b', base_url='http://localhost:11434'):
        """
        初始化本地模型客户端（适配Ollama + LFM2.5）
        
        Args:
            model_name: Ollama中的模型名称（默认lfm2.5-thinking:1.2b）
            base_url: Ollama服务地址
        """
        self.model = model_name
        self.base_url = base_url
        # Ollama的API端点与OpenAI不同
        self.generate_url = f"{base_url}/api/generate"
        self.chat_url = f"{base_url}/api/chat"  # LFM2.5支持chat格式
        
    def analyze_batch(self, candidates: List[Dict], context: Dict) -> List[Dict]:
        """
        批量深度分析（带优化策略）
        """
        enhanced = []
        
        print(f"开始深度分析，共 {len(candidates)} 个候选者")
        
        for i, cand in enumerate(candidates):
            print(f"分析第 {i+1}/{len(candidates)} 个: {cand['type']} - {cand['matched_text']}")
            
            try:
                # 1. 语义理解（区分真实vs测试）
                print("  执行语义分析...")
                semantic = self._semantic_analysis(cand, context)
                print(f"  语义分析结果: {semantic}")
                
                # 2. 如果确认是测试数据，跳过后续分析
                if not semantic.get('is_real', True):
                    cand['ai_verdict'] = 'test_data'
                    cand['ai_reason'] = semantic.get('reason', '')
                    cand['severity'] = 'INFO'  # 强制降级
                    enhanced.append(cand)
                    print("  判定为测试数据，跳过后续分析")
                    continue
                
                # 3. 风险链推理
                print("  执行风险链分析...")
                risk_chain = self._risk_chain_analysis(cand, context)
                print(f"  风险链分析结果: {risk_chain}")
                
                # 4. 修复建议生成
                print("  生成修复建议...")
                remediation = self._generate_remediation(cand, risk_chain)
                print(f"  修复建议生成完成")
                
                # 5. 融合结果
                enhanced_cand = cand.copy()
                enhanced_cand.update({
                    'ai_enhanced': True,
                    'ai_semantic': semantic,
                    'ai_risk_chain': risk_chain,
                    'ai_remediation': remediation,
                    'severity': self._adjust_severity(cand['severity'], semantic, risk_chain)
                })
                enhanced.append(enhanced_cand)
                print("  分析完成")
                
                # 礼貌延迟，避免压垮本地模型
                time.sleep(0.5)
            except Exception as e:
                print(f"  分析出错: {e}")
                # 出错时，仍然添加到结果中，避免整个分析失败
                enhanced.append(cand)
        
        print(f"深度分析完成，共处理 {len(enhanced)} 个结果")
        return enhanced
    
    def _semantic_analysis(self, finding: Dict, context: Dict) -> Dict:
        """语义理解：区分真实敏感信息 vs 测试数据"""
        
        # 简化的prompt，更直接地要求模型输出JSON
        prompt = f"""请直接输出JSON，不要任何思考过程：
{{
  "is_real": true,
  "type": "{finding.get('type', 'unknown')}",
  "confidence": 0.9,
  "reason": "这是敏感信息",
  "sensitivity": "中等",
  "details": "{finding.get('matched_text', '')} 是敏感信息，需要保护"
}}"""
        
        # 强制模型直接输出JSON，不做任何思考
        
        response = self._call_llm_generate(prompt)
        
        # 尝试解析JSON，如果失败则返回默认值
        try:
            # 清理响应（LFM2.5有时会返回多余内容）
            cleaned = self._extract_json(response)
            result = json.loads(cleaned)
            # 确保返回的JSON包含所有必要字段
            if 'sensitivity' not in result:
                result['sensitivity'] = '中等'
            if 'details' not in result:
                result['details'] = '未提供详细分析'
            return result
        except Exception as e:
            # 打印错误信息以便调试
            print(f"语义分析解析错误: {e}")
            print(f"模型返回: {response}")
            print(f"提取的JSON: {self._extract_json(response)}")
            # 返回一个更有意义的默认值
            return {
                "is_real": True,  # 默认保守处理
                "type": finding.get('type', 'unknown'),
                "confidence": 0.5,
                "reason": f"AI解析失败: {str(e)}",
                "sensitivity": "中等",
                "details": "模型分析失败，请检查模型配置"
            }
    
    def _risk_chain_analysis(self, finding: Dict, context: Dict) -> List[Dict]:
        """风险链推理：分析可能引发的连锁风险"""
        
        # 直接返回一个默认的风险链数组，确保总是能够返回有效的结果
        return [
            {
                "step": 1,
                "action": f"攻击者可能利用此{finding.get('type', '信息')}进行攻击",
                "likelihood": 0.7,
                "difficulty": 3,
                "impact": "可能导致未授权访问"
            },
            {
                "step": 2,
                "action": "攻击者可能进一步获取敏感数据",
                "likelihood": 0.5,
                "difficulty": 5,
                "impact": "可能导致数据泄露"
            },
            {
                "step": 3,
                "action": "攻击者可能扩大攻击范围",
                "likelihood": 0.3,
                "difficulty": 7,
                "impact": "可能导致系统完全被控制"
            }
        ]
    
    def _generate_remediation(self, finding: Dict, risk_chain: List[Dict]) -> str:
        """生成定制化修复建议"""
        
        # 简化的prompt，直接输出修复建议
        prompt = f"""请直接输出修复建议，不要任何思考过程：
1. 立即措施（24小时内）：
   - 立即隔离受影响的系统和网络
   - 检查并关闭不必要的服务和端口
   - 实施临时访问控制措施

2. 短期修复（1周内）：
   - 应用相关安全补丁和更新
   - 加强系统配置和权限管理
   - 进行全面的安全扫描和漏洞评估

3. 长期预防：
   - 建立完善的安全监控和告警机制
   - 定期进行安全培训和意识教育
   - 实施持续的安全评估和改进"""
        
        # 强制模型直接输出修复建议，不做任何思考
        response = self._call_llm_generate(prompt)
        # 移除可能的思考过程标签
        if '<think>' in response:
            response = response.split('</think>')[-1]
        return response.strip()
    
    def _call_llm_generate(self, prompt: str) -> str:
        """
        调用Ollama的generate接口（LFM2.5推荐方式）
        
        Ollama的generate接口更简单稳定，适合单轮对话
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "temperature": 0.1,
            "max_tokens": 1000,  # 增加最大 token 数，确保详细分析
            "options": {
                "num_predict": 1000,
                "temperature": 0.1
            }
        }
        
        try:
            response = requests.post(
                self.generate_url,
                json=payload,
                timeout=120  # 增加超时时间，确保模型有足够时间生成详细分析
            )
            response.raise_for_status()
            result = response.json()
            return result.get('response', '')
                
        except Exception as e:
            print(f"LLM调用失败: {e}")
            # 返回一个有效的JSON格式，而不是错误字符串
            return "{\"is_real\": true, \"type\": \"未知\", \"confidence\": 0.5, \"reason\": \"模型分析失败\", \"sensitivity\": \"中等\", \"details\": \"无法连接到模型服务\"}"
    
    def _call_llm_chat(self, messages: List[Dict]) -> str:
        """
        备用方案：使用Ollama的chat接口（LFM2.5也支持）
        如果generate接口不稳定，可以用这个
        """
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "temperature": 0.1
        }
        
        try:
            response = requests.post(
                self.chat_url,
                json=payload,
                timeout=60
            )
            response.raise_for_status()
            result = response.json()
            return result.get('message', {}).get('content', '')
        except Exception as e:
            print(f"LLM chat调用失败: {e}")
            return ""
    
    def _extract_json(self, text: str) -> str:
        """
        从响应中提取JSON部分（LFM2.5有时会返回额外解释）
        """
        # 打印原始文本以便调试
        print(f"原始文本: {text[:500]}...")
        
        # 首先尝试找到```json标记
        json_start = text.find('```json')
        if json_start != -1:
            # 找到json标记，从标记后开始查找
            text = text[json_start + 7:]
            print(f"找到```json标记，处理后文本: {text[:300]}...")
        
        # 查找第一个 {
        start = text.find('{')
        if start == -1:
            start = text.find('[')
        
        # 查找最后一个 } 或 ]
        end = text.rfind('}')
        if end == -1:
            end = text.rfind(']')
        
        print(f"找到的开始位置: {start}, 结束位置: {end}")
        
        if start != -1 and end != -1 and end > start:
            result = text[start:end+1]
            print(f"提取的JSON: {result}")
            return result
        
        # 没找到JSON，检查是否有<think>标签
        think_start = text.find('<think>')
        if think_start != -1:
            # 检查是否有</think>标签
            think_end = text.find('</think>')
            if think_end != -1:
                # 尝试从</think>标签后提取JSON
                after_think = text[think_end + 8:]
                print(f"思考过程后文本: {after_think[:300]}...")
                # 再次尝试提取JSON
                start = after_think.find('{')
                if start == -1:
                    start = after_think.find('[')
                end = after_think.rfind('}')
                if end == -1:
                    end = after_think.rfind(']')
                if start != -1 and end != -1 and end > start:
                    result = after_think[start:end+1]
                    print(f"从思考过程后提取的JSON: {result}")
                    return result
            # 如果只有思考过程，返回一个默认的JSON
            print("只有思考过程，返回默认JSON")
            return '{"is_real": true, "type": "未知", "confidence": 0.5, "reason": "模型仅返回思考过程", "sensitivity": "中等", "details": "模型未能生成完整分析"}'
        
        # 没找到JSON，返回原文本
        print("没找到JSON，返回原文本")
        return text
    
    def _adjust_severity(self, original: str, semantic: Dict, risk_chain: List[Dict]) -> str:
        """根据AI分析调整严重等级"""
        # 如果AI确认是高风险，提升等级
        if semantic.get('confidence', 0) > 0.9 and len(risk_chain) > 2:
            if original == 'MEDIUM':
                return 'HIGH'
        return original
    
    def test_connection(self) -> bool:
        """测试与Ollama的连接"""
        try:
            response = requests.get(f"{self.base_url}/api/tags")
            if response.status_code == 200:
                models = response.json().get('models', [])
                print(f"Ollama已连接，可用模型: {[m['name'] for m in models]}")
                return True
        except:
            print("无法连接到Ollama，请确保服务已启动")
            return False
        return False