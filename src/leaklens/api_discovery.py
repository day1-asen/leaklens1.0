import re
import json
import requests
from typing import List, Dict, Set, Optional
from urllib.parse import urljoin, urlparse
import yaml


class APIEndpointDiscovery:
    """API端点发现器"""
    
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.discovered_endpoints = []
        
    def discover_from_crawler(self, base_url: str, html_content: str) -> List[Dict]:
        """
        从爬虫发现的页面中提取API端点
        参考Autoswagger的实现思路：扫描页面中的API路径
        """
        endpoints = []
        
        # API路径正则模式（优化版）
        api_patterns = [
            r'["\'](/api/v\d+/[\w/]+)["\']',           # /api/v1/users
            r'["\'](/rest/[\w/]+)["\']',                # /rest/user/profile
            r'["\'](/graphql)["\']',                    # GraphQL端点
            r'["\'](/\w+\.(do|action|php|asp))["\']',   # 常见动作型接口
            r'url:\s*["\'](/[\w/]+)["\']',               # AJAX请求中的url
            r'fetch\(["\'](/[\w/]+)["\']\)',             # fetch API
            r'<a\s+href=["\'](/[\w/]+)["\']',           # HTML链接
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                # 处理元组返回的情况
                path = match[0] if isinstance(match, tuple) else match
                
                # 构建完整URL
                if path.startswith('http'):
                    full_url = path
                else:
                    full_url = urljoin(base_url, path)
                
                endpoints.append({
                    'url': full_url,
                    'method': self._guess_method(html_content, path),
                    'source': 'crawler',
                    'params': self._extract_params(html_content, path)
                })
        
        return endpoints
    
    def discover_from_js(self, base_url: str, js_content: str) -> List[Dict]:
        """
        从JavaScript文件中提取API端点
        参考FLUX工具的JS敏感信息收集功能
        """
        endpoints = []
        
        # 更全面的JS中API模式（优化版）
        js_patterns = [
            # Axios/fetch调用
            r'(?:axios|fetch)\([\'"](/api/[^\'"\s]+)[\'"]',
            # $.ajax
            r'\$\.(?:get|post)\([\'"](/[^\'"\s]+)[\'"]',
            # 常量定义
            r'const\s+\w+_URL\s*=\s*["\'](/[\w/]+)["\']',
            # 对象属性中的API
            r'url:\s*["\'](/[\w/]+)["\']',
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                path = match if isinstance(match, str) else match[0]
                
                if path.startswith('http'):
                    full_url = path
                else:
                    full_url = urljoin(base_url, path)
                
                # 提取路径参数
                path_params = re.findall(r':(\w+)', path)
                
                endpoints.append({
                    'url': full_url,
                    'method': self._guess_method_from_js(js_content, path),
                    'source': 'javascript',
                    'path_params': path_params,
                    'query_params': self._extract_query_params(js_content, path)
                })
        
        return endpoints
    
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.discovered_endpoints = []
        self.swagger_cache = set()  # 缓存已检查的Swagger路径
        self.session.mount('http://', requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10))
        self.session.mount('https://', requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10))
    
    def discover_from_swagger(self, base_url: str) -> List[Dict]:
        """
        从Swagger/OpenAPI文档中发现API端点
        参考Autoswagger的实现：扫描OpenAPI文档页面
        """
        endpoints = []
        
        # 常见的Swagger文档路径
        swagger_paths = [
            '/swagger.json',
            '/openapi.json',
            '/api-docs',
            '/v2/api-docs',
            '/v3/api-docs',
            '/swagger-ui.html',
        ]
        
        # 提取基础URL，避免重复检查
        parsed_url = urlparse(base_url)
        base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        for path in swagger_paths:
            swagger_url = urljoin(base_domain, path)
            
            # 避免重复检查
            if swagger_url in self.swagger_cache:
                continue
            
            self.swagger_cache.add(swagger_url)
            
            try:
                response = self.session.get(swagger_url, timeout=3, verify=False, allow_redirects=False)
                
                if response.status_code == 200:
                    # 解析Swagger文档
                    if path.endswith('.json'):
                        try:
                            spec = response.json()
                            endpoints.extend(self._parse_openapi_spec(spec, base_domain))
                        except json.JSONDecodeError:
                            pass
                    elif path.endswith('.yaml'):
                        try:
                            spec = yaml.safe_load(response.text)
                            endpoints.extend(self._parse_openapi_spec(spec, base_domain))
                        except:
                            pass
                    elif 'swagger-ui' in path:
                        # 对于UI页面，尝试提取API路径
                        endpoints.extend(self._extract_from_swagger_ui(response.text, base_domain))
                        
            except Exception as e:
                continue
        
        return endpoints
    
    def _parse_openapi_spec(self, spec: Dict, base_url: str) -> List[Dict]:
        """解析OpenAPI规范"""
        endpoints = []
        
        # OpenAPI 3.0格式
        paths = spec.get('paths', {})
        
        for path, methods in paths.items():
            for method, details in methods.items():
                # 提取参数信息
                params = []
                if 'parameters' in details:
                    for param in details['parameters']:
                        params.append({
                            'name': param.get('name'),
                            'in': param.get('in'),
                            'type': param.get('type') or param.get('schema', {}).get('type'),
                            'required': param.get('required', False)
                        })
                
                # 构建完整URL
                full_url = urljoin(base_url, path)
                
                endpoints.append({
                    'url': full_url,
                    'method': method.upper(),
                    'source': 'swagger',
                    'params': params,
                    'description': details.get('summary') or details.get('description'),
                    'tags': details.get('tags', [])
                })
        
        return endpoints
    
    def _extract_from_swagger_ui(self, html_content: str, base_url: str) -> List[Dict]:
        """从Swagger UI页面提取API端点"""
        endpoints = []
        
        # 提取API路径
        api_patterns = [
            r'path:\s*["\']([^"\']+)["\']',
            r'\/[a-zA-Z0-9_\-\/]+',
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, html_content)
            for match in matches:
                path = match
                if path.startswith('/'):
                    full_url = urljoin(base_url, path)
                    endpoints.append({
                        'url': full_url,
                        'method': 'GET',  # 默认方法
                        'source': 'swagger-ui',
                        'params': []
                    })
        
        return endpoints
    
    def _guess_method(self, content: str, path: str) -> str:
        """根据上下文猜测HTTP方法"""
        # 简单的方法猜测
        if 'post' in content.lower() and path in content:
            return 'POST'
        elif 'put' in content.lower() and path in content:
            return 'PUT'
        elif 'delete' in content.lower() and path in content:
            return 'DELETE'
        else:
            return 'GET'
    
    def _guess_method_from_js(self, js_content: str, path: str) -> str:
        """从JS代码中猜测HTTP方法"""
        # 检查常见的HTTP方法调用
        if f'post({path}' in js_content.lower() or f'post("{path}' in js_content.lower():
            return 'POST'
        elif f'put({path}' in js_content.lower() or f'put("{path}' in js_content.lower():
            return 'PUT'
        elif f'delete({path}' in js_content.lower() or f'delete("{path}' in js_content.lower():
            return 'DELETE'
        else:
            return 'GET'
    
    def _extract_params(self, content: str, path: str) -> List[Dict]:
        """提取参数信息"""
        params = []
        # 简单的参数提取
        param_patterns = [
            r'\b\w+\s*=\s*["\']?([^"\'\s]+)["\']?\s*;',
            r'\b\w+\s*:\s*["\']?([^"\'\s]+)["\']?',
        ]
        
        for pattern in param_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                params.append({'name': match, 'value': ''})
        
        return params
    
    def _extract_query_params(self, js_content: str, path: str) -> List[Dict]:
        """从JS代码中提取查询参数"""
        params = []
        # 提取URL中的查询参数
        query_patterns = [
            r'\b\w+\s*=\s*["\']?([^"\'\s]+)["\']?',
            r'params:\s*\{([^\}]+)\}',
        ]
        
        for pattern in query_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if isinstance(match, str):
                    param_pairs = re.findall(r'(\w+)\s*:\s*["\']?([^"\',]+)["\']?', match)
                    for param_name, param_value in param_pairs:
                        params.append({'name': param_name, 'value': param_value})
        
        return params
    
    def discover_all(self, base_url: str, html_content: str = None, js_content: str = None) -> List[Dict]:
        """
        从所有来源发现API端点
        """
        all_endpoints = []
        
        # 从爬虫发现
        if html_content:
            all_endpoints.extend(self.discover_from_crawler(base_url, html_content))
        
        # 从JS文件发现
        if js_content:
            all_endpoints.extend(self.discover_from_js(base_url, js_content))
        
        # 从Swagger文档发现
        all_endpoints.extend(self.discover_from_swagger(base_url))
        
        # 去重
        seen_urls = set()
        unique_endpoints = []
        for endpoint in all_endpoints:
            if endpoint['url'] not in seen_urls:
                seen_urls.add(endpoint['url'])
                unique_endpoints.append(endpoint)
        
        self.discovered_endpoints = unique_endpoints
        return unique_endpoints
