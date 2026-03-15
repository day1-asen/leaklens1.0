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
        
        # LFM2.5支持function calling，但这里用简单的prompt
        prompt = f"""请用中文分析以下内容是否为真实的敏感信息（不是测试数据）：

信息类型：{finding.get('type', 'unknown')}
信息内容："{finding.get('matched_text', '')}"
发现位置：{context.get('url', 'unknown')}
周围文本："{context.get('surrounding_text', '')[:200]}"

请判断：
1. 这是真实的敏感信息还是测试/示例数据？
2. 如果是敏感信息，它属于什么具体类型？（身份证、手机号、API密钥等）
3. 置信度评分（0-1）

你必须以JSON格式返回，所有内容使用中文，例如：
{{"is_real": true, "type": "身份证", "confidence": 0.95, "reason": "符合身份证格式且不是测试号"}}"""
        
        response = self._call_llm_generate(prompt)
        
        # 尝试解析JSON，如果失败则返回默认值
        try:
            # 清理响应（LFM2.5有时会返回多余内容）
            cleaned = self._extract_json(response)
            return json.loads(cleaned)
        except:
            return {
                "is_real": True,  # 默认保守处理
                "type": finding.get('type', 'unknown'),
                "confidence": 0.5,
                "reason": "AI解析失败，采用默认值"
            }
    
    def _risk_chain_analysis(self, finding: Dict, context: Dict) -> List[Dict]:
        """风险链推理：分析可能引发的连锁风险"""
        
        prompt = f"""请用中文分析以下信息泄露可能引发的连锁风险：

泄露信息类型：{finding.get('type')}
信息内容：{finding.get('matched_text')}
发现位置：{context.get('url')}
系统环境：{context.get('environment', 'unknown')}

请推理攻击者可能的攻击路径，按步骤列出：
1. 攻击者首先会做什么？
2. 成功后如何横向移动？
3. 最终可能造成的业务影响？

以JSON格式返回，所有内容使用中文，例如：
[{{"step": 1, "action": "直接使用API密钥调用接口", "likelihood": 0.9}},
 {"step": 2, "action": "访问后端数据库", "likelihood": 0.7}]
"""
        
        response = self._call_llm_generate(prompt)
        
        try:
            cleaned = self._extract_json(response)
            return json.loads(cleaned)
        except:
            return [
                {"step": 1, "action": "无法分析", "likelihood": 0.5}
            ]
    
    def _generate_remediation(self, finding: Dict, risk_chain: List[Dict]) -> str:
        """生成定制化修复建议"""
        
        # 将风险链转换为易读格式
        risk_text = ""
        for step in risk_chain:
            risk_text += f"步骤{step.get('step')}：{step.get('action')}（可能性：{step.get('likelihood')}）\n"
        
        prompt = f"""请为以下安全漏洞生成具体的修复建议（用中文）：

问题类型：{finding.get('type')}
严重程度：{finding.get('severity')}
风险链分析：
{risk_text}

请给出：
1. 立即措施（24小时内必须做的）
2. 短期修复（1周内完成的）
3. 长期预防（避免再次发生）

用清晰的中文描述，每项用简洁的条目列出。"""
        
        response = self._call_llm_generate(prompt)
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
            "max_tokens": 500,
            "options": {
                "num_predict": 500,
                "temperature": 0.1
            }
        }
        
        try:
            response = requests.post(
                self.generate_url,
                json=payload,
                timeout=60  # LFM2.5速度很快，但留足时间
            )
            response.raise_for_status()
            result = response.json()
            return result.get('response', '')
                
        except Exception as e:
            print(f"LLM调用失败: {e}")
            return f"分析失败: {e}"
    
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
        # 查找第一个 {
        start = text.find('{')
        if start == -1:
            start = text.find('[')
        
        # 查找最后一个 } 或 ]
        end = text.rfind('}')
        if end == -1:
            end = text.rfind(']')
        
        if start != -1 and end != -1 and end > start:
            return text[start:end+1]
        
        # 没找到JSON，返回原文本
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
