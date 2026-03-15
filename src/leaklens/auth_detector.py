import requests
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import time


class AuthDetector:
    """鉴权状态检测器"""
    
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        
    def detect_auth_requirement(self, endpoint: Dict, auth_token: str = None) -> Dict:
        """
        检测接口是否需要鉴权
        
        原理：
        1. 带有效凭证访问（如果有）
        2. 不带凭证访问
        3. 对比响应差异
        """
        url = endpoint['url']
        method = endpoint.get('method', 'GET')
        
        result = {
            'url': url,
            'method': method,
            'requires_auth': True,
            'auth_type': None,
            'auth_bypass_possible': False,
            'confidence': 0.0,
            'details': {}
        }
        
        # 1. 发送基准请求（无认证）
        try:
            no_auth_response = self._send_request(url, method)
            result['details']['no_auth_status'] = no_auth_response.status_code
            result['details']['no_auth_length'] = len(no_auth_response.text)
        except Exception as e:
            result['details']['no_auth_error'] = str(e)
            return result
        
        # 2. 如果有token，发送带认证的请求
        if auth_token:
            try:
                auth_response = self._send_request(url, method, auth_token)
                result['details']['auth_status'] = auth_response.status_code
                result['details']['auth_length'] = len(auth_response.text)
                
                # 3. 对比分析
                analysis = self._compare_responses(no_auth_response, auth_response)
                result.update(analysis)
                
            except Exception as e:
                result['details']['auth_error'] = str(e)
        else:
            # 无token时，通过错误响应判断
            result.update(self._analyze_no_auth_response(no_auth_response))
        
        return result
    
    def _send_request(self, url: str, method: str, auth_token: str = None) -> requests.Response:
        """发送HTTP请求"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        if auth_token:
            # 尝试多种认证头格式
            headers['Authorization'] = f'Bearer {auth_token}'
        
        # 根据方法发送请求
        if method == 'GET':
            return self.session.get(url, headers=headers, timeout=10, verify=False)
        elif method == 'POST':
            return self.session.post(url, headers=headers, timeout=10, verify=False)
        elif method == 'PUT':
            return self.session.put(url, headers=headers, timeout=10, verify=False)
        elif method == 'DELETE':
            return self.session.delete(url, headers=headers, timeout=10, verify=False)
        else:
            return self.session.get(url, headers=headers, timeout=10, verify=False)
    
    def _compare_responses(self, no_auth: requests.Response, auth: requests.Response) -> Dict:
        """
        对比带认证和不带认证的响应
        
        判断逻辑：
        - 如果无认证返回200，有认证也返回200 → 可能无鉴权
        - 如果无认证返回200，有认证返回401/403 → 鉴权正常
        - 如果无认证返回401/403，有认证返回200 → 鉴权正常
        """
        result = {
            'requires_auth': True,
            'auth_type': None,
            'auth_bypass_possible': False,
            'confidence': 0.0
        }
        
        # 情况1：都返回200
        if no_auth.status_code == 200 and auth.status_code == 200:
            # 进一步比较内容
            if no_auth.text == auth.text:
                result['requires_auth'] = False
                result['auth_bypass_possible'] = True
                result['confidence'] = 0.9
                result['details']['reason'] = '无认证和有认证返回相同内容'
            else:
                # 内容不同，可能是部分公开
                similarity = self._calculate_similarity(no_auth.text, auth.text)
                if similarity > 0.8:
                    result['requires_auth'] = False
                    result['auth_bypass_possible'] = True
                    result['confidence'] = 0.7
                    result['details']['reason'] = f'内容相似度{similarity:.2%}'
        
        # 情况2：无认证200，有认证401/403
        elif no_auth.status_code == 200 and auth.status_code in [401, 403]:
            result['requires_auth'] = False
            result['auth_bypass_possible'] = True
            result['confidence'] = 0.95
            result['details']['reason'] = '无认证可访问，但有认证时被拒绝（鉴权逻辑异常）'
        
        # 情况3：无认证401/403，有认证200（正常情况）
        elif no_auth.status_code in [401, 403] and auth.status_code == 200:
            result['requires_auth'] = True
            result['auth_bypass_possible'] = False
            result['confidence'] = 0.95
            result['auth_type'] = self._extract_auth_type(no_auth)
            result['details']['reason'] = '鉴权正常'
        
        # 情况4：都返回401/403
        elif no_auth.status_code in [401, 403] and auth.status_code in [401, 403]:
            result['requires_auth'] = True
            result['auth_bypass_possible'] = False
            result['confidence'] = 0.8
            result['details']['reason'] = 'token无效或过期'
        
        return result
    
    def _analyze_no_auth_response(self, response: requests.Response) -> Dict:
        """仅通过无认证响应分析鉴权需求"""
        result = {
            'requires_auth': True,
            'auth_type': None,
            'auth_bypass_possible': False,
            'confidence': 0.5
        }
        
        # 根据状态码判断
        if response.status_code == 200:
            # 可能不需要认证，也可能是公开接口
            result['requires_auth'] = False
            result['confidence'] = 0.6
            
            # 检查响应内容是否包含敏感信息
        elif response.status_code in [401, 403]:
            result['requires_auth'] = True
            result['auth_type'] = self._extract_auth_type(response)
            result['confidence'] = 0.8
            result['details']['reason'] = '无认证被拒绝'
        
        return result
    
    def _extract_auth_type(self, response: requests.Response) -> str:
        """从响应中提取认证类型"""
        # 检查WWW-Authenticate头
        auth_header = response.headers.get('WWW-Authenticate')
        if auth_header:
            if 'Bearer' in auth_header:
                return 'Bearer Token'
            elif 'Basic' in auth_header:
                return 'Basic Auth'
            elif 'Digest' in auth_header:
                return 'Digest Auth'
        
        # 检查响应内容
        content = response.text.lower()
        if 'jwt' in content:
            return 'JWT'
        elif 'token' in content:
            return 'Token'
        elif 'authentication' in content:
            return 'Unknown'
        
        return 'Unknown'
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """计算两个文本的相似度"""
        # 简单的相似度计算：共同字符数 / 总字符数
        if not text1 or not text2:
            return 0.0
        
        common_chars = set(text1) & set(text2)
        total_chars = set(text1) | set(text2)
        
        return len(common_chars) / len(total_chars) if total_chars else 0.0
