import re
import requests
from typing import Dict, List, Optional, Set
import itertools


class IDORDetector:
    """IDOR越权测试器"""
    
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.request_cache = {}  # 缓存请求结果
        self.session.mount('http://', requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10))
        self.session.mount('https://', requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10))
        
    def extract_ids_from_url(self, url: str) -> List[Dict]:
        """
        从URL中提取可能的ID参数
        参考：IDOR漏洞常见于数字ID、UUID等可预测标识符
        """
        ids = []
        
        # 1. 路径中的数字ID (如 /users/123)
        path_ids = re.findall(r'/([0-9]+)(?:/|$)', url)
        for id_val in path_ids:
            ids.append({
                'type': 'path_numeric',
                'value': id_val,
                'position': 'path',
                'pattern': f'/users/{id_val}'
            })
        
        # 2. 路径中的UUID
        uuid_pattern = r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:/|$)'
        uuids = re.findall(uuid_pattern, url, re.IGNORECASE)
        for uuid_val in uuids:
            ids.append({
                'type': 'path_uuid',
                'value': uuid_val,
                'position': 'path',
                'pattern': f'/documents/{uuid_val}'
            })
        
        # 3. 查询参数中的ID (如 ?user_id=123)
        query_patterns = [
            r'[?&](?:id|user_id|uid|pid|doc_id|file_id)=([0-9]+)',
            r'[?&](?:uuid|token|guid)=([a-f0-9-]{36})',
        ]
        
        for pattern in query_patterns:
            matches = re.findall(pattern, url, re.IGNORECASE)
            for match in matches:
                ids.append({
                    'type': 'query_numeric' if match.isdigit() else 'query_uuid',
                    'value': match,
                    'position': 'query',
                    'parameter': self._extract_param_name(url, match)
                })
        
        return ids
    
    def _extract_param_name(self, url: str, value: str) -> str:
        """提取参数名"""
        pattern = f'([?&])([^=]+)={re.escape(value)}'
        match = re.search(pattern, url)
        if match:
            return match.group(2)
        return 'id'
    
    def generate_test_ids(self, original_id: Dict, range_size: int = 5) -> List[str]:
        """
        生成测试ID序列
        参考IDOR测试方法：遍历相邻ID
        """
        test_ids = []
        
        if original_id['type'] == 'path_numeric' or original_id['type'] == 'query_numeric':
            try:
                num = int(original_id['value'])
                # 生成相邻数字
                for i in range(max(1, num - range_size), num + range_size + 1):
                    if i != num:
                        test_ids.append(str(i))
                # 添加一些边界值
                test_ids.extend(['1', '0', '9999', '10000', '99999'])
            except:
                pass
        
        elif original_id['type'] == 'path_uuid' or original_id['type'] == 'query_uuid':
            # UUID格式，生成变体
            test_ids.extend([
                '00000000-0000-0000-0000-000000000000',
                '11111111-1111-1111-1111-111111111111',
                '12345678-1234-1234-1234-123456789012',
                'ffffffff-ffff-ffff-ffff-ffffffffffff',
            ])
        
        # 去重
        return list(set(test_ids))
    
    def test_idor(self, 
                   endpoint: Dict, 
                   auth_token: str = None, 
                   range_size: int = 5) -> List[Dict]:
        """
        测试IDOR漏洞
        
        原理：
        1. 提取URL中的ID参数
        2. 生成测试ID序列
        3. 遍历测试并分析响应
        """
        url = endpoint['url']
        method = endpoint.get('method', 'GET')
        
        results = []
        
        # 提取ID
        ids = self.extract_ids_from_url(url)
        
        for original_id in ids:
            # 生成测试ID
            test_ids = self.generate_test_ids(original_id, range_size)
            
            for test_id in test_ids:
                # 构造测试URL
                test_url = self._replace_id(url, original_id['value'], test_id)
                
                # 发送请求
                response = self._send_request(test_url, method, auth_token)
                
                # 分析结果
                finding = self._analyze_idor_response(
                    original_url=url,
                    test_url=test_url,
                    original_id=original_id,
                    test_id=test_id,
                    response=response
                )
                
                if finding['vulnerable']:
                    results.append(finding)
        
        return results
    
    def _replace_id(self, url: str, original: str, new: str) -> str:
        """替换URL中的ID值"""
        # 替换路径中的ID
        new_url = url.replace(f'/{original}/', f'/{new}/')
        new_url = new_url.replace(f'/{original}', f'/{new}')
        
        # 替换查询参数中的ID
        new_url = re.sub(f'=({re.escape(original)})(&|$)', f'={new}\2', new_url)
        
        return new_url
    
    def _send_request(self, url: str, method: str, auth_token: str = None) -> requests.Response:
        """发送请求"""
        # 缓存键
        cache_key = f"{method}:{url}:{auth_token}"
        
        # 检查缓存
        if cache_key in self.request_cache:
            return self.request_cache[cache_key]
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        if auth_token:
            headers['Authorization'] = f'Bearer {auth_token}'
        
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
    
    def _analyze_idor_response(self, 
                               original_url: str, 
                               test_url: str, 
                               original_id: Dict, 
                               test_id: str, 
                               response: requests.Response) -> Dict:
        """分析IDOR测试响应"""
        finding = {
            'original_url': original_url,
            'test_url': test_url,
            'original_id': original_id,
            'test_id': test_id,
            'vulnerable': False,
            'status_code': response.status_code if response else 0,
            'confidence': 0.0,
            'details': {}
        }
        
        if not response:
            finding['details']['error'] = 'No response'
            return finding
        
        # 分析响应
        if response.status_code == 200:
            # 200状态码可能表示越权访问成功
            finding['vulnerable'] = True
            finding['confidence'] = 0.8
            finding['details']['reason'] = '200 OK response'
        elif response.status_code == 302:
            # 302重定向可能表示越权访问被重定向
            finding['vulnerable'] = True
            finding['confidence'] = 0.6
            finding['details']['reason'] = '302 Redirect'
            finding['details']['location'] = response.headers.get('Location', '')
        elif response.status_code == 401 or response.status_code == 403:
            # 401/403表示未授权，不是越权漏洞
            finding['vulnerable'] = False
            finding['confidence'] = 0.9
            finding['details']['reason'] = 'Access denied'
        elif response.status_code == 404:
            # 404表示资源不存在，不是越权漏洞
            finding['vulnerable'] = False
            finding['confidence'] = 0.8
            finding['details']['reason'] = 'Resource not found'
        else:
            # 其他状态码需要进一步分析
            finding['vulnerable'] = True
            finding['confidence'] = 0.5
            finding['details']['reason'] = f'Unexpected status code: {response.status_code}'
        
        return finding
