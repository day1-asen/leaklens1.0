from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import sys
import json
from pathlib import Path

# 添加src目录到Python路径
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from leaklens.facade import CrawlerFacade, FileScannerFacade
from leaklens.config import settings
from leaklens.config.报告主控 import DualStagePipeline

app = Flask(__name__)
CORS(app)

# 全局变量存储扫描结果
scan_results = {}

# 全局变量存储当前结果ID
current_result_id = None

@app.route('/')
def index():
    """首页"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    """执行扫描"""
    try:
        data = request.json
        url = data.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # 准备扫描参数
        custom_settings = {
            'url': url,
            'max_depth': data.get('max_depth', 1),
            'max_page': data.get('max_page', 100000),
            'follow_redirects': data.get('follow_redirects', False),
            'hide_regex': data.get('hide_regex', False),
            'detail': data.get('detail', True),
            'validate': data.get('validate', False),
            'api_detection': data.get('api_detection', True),
            'auth_detection': data.get('auth_detection', False),
            'idor_detection': data.get('idor_detection', False),
            'jwt_detection': data.get('jwt_detection', False),
            'auth_token': data.get('auth_token', None)
        }
        
        # 执行扫描
        class PrintCollector:
            def __init__(self):
                self.output = []
            def __call__(self, text, **kwargs):
                self.output.append(text)
        
        print_collector = PrintCollector()
        
        # 为当前线程创建事件循环
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        facade = CrawlerFacade(settings, custom_settings, print_func=print_collector)
        facade.start()
        
        # 收集结果
        # 转换对象为可序列化格式
        def serialize_data(data):
            if isinstance(data, dict):
                # 确保键是字符串类型
                serialized = {}
                for k, v in data.items():
                    # 如果键不是基本类型，转换为字符串
                    key = str(k) if not isinstance(k, (str, int, float, bool, type(None))) else k
                    serialized[key] = serialize_data(v)
                return serialized
            elif hasattr(data, '__dict__'):
                serialized = {}
                for key, value in data.__dict__.items():
                    if key.startswith('_'):
                        continue
                    serialized[key] = serialize_data(value)
                return serialized
            elif isinstance(data, (list, tuple)):
                return [serialize_data(item) for item in data]
            elif isinstance(data, set):
                # 将集合转换为列表
                return [serialize_data(item) for item in data]
            else:
                return data
        
        # 构建结果
        result = {
            'output': print_collector.output,
            'urls': serialize_data(dict(facade.crawler.url_dict)),
            'secrets': serialize_data(dict(facade.crawler.url_secrets)),
            'js': serialize_data(dict(facade.crawler.js_dict)),
            'api_endpoints': serialize_data(facade.crawler.api_endpoints),
            'auth_results': serialize_data(facade.crawler.auth_results if hasattr(facade.crawler, 'auth_results') else []),
            'idor_results': serialize_data(facade.crawler.idor_results if hasattr(facade.crawler, 'idor_results') else []),
            'jwt_results': serialize_data(facade.crawler.jwt_results if hasattr(facade.crawler, 'jwt_results') else []),
            'found_urls': list(facade.crawler.found_urls)
        }
        
        # 生成结果ID
        import uuid
        result_id = str(uuid.uuid4())
        scan_results[result_id] = result
        
        # 保存当前结果ID到全局变量，供前端使用
        global current_result_id
        current_result_id = result_id
        
        return jsonify({'result_id': result_id, 'message': 'Scan completed'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/result/<result_id>', methods=['GET'])
def get_result(result_id):
    """获取扫描结果"""
    if result_id in scan_results:
        import json
        from flask import Response
        
        # 序列化函数
        def serialize_data(data):
            if isinstance(data, dict):
                # 确保键是字符串类型
                serialized = {}
                for k, v in data.items():
                    # 如果键不是基本类型，转换为字符串
                    key = str(k) if not isinstance(k, (str, int, float, bool, type(None))) else k
                    serialized[key] = serialize_data(v)
                return serialized
            elif hasattr(data, '__dict__'):
                serialized = {}
                for key, value in data.__dict__.items():
                    if key.startswith('_'):
                        continue
                    serialized[key] = serialize_data(value)
                return serialized
            elif isinstance(data, (list, tuple)):
                return [serialize_data(item) for item in data]
            elif isinstance(data, set):
                # 将集合转换为列表
                return [serialize_data(item) for item in data]
            else:
                return data
        
        # 构建响应
        serialized_result = serialize_data(scan_results[result_id])
        json_data = json.dumps(serialized_result, sort_keys=False)
        return Response(json_data, mimetype='application/json')
    else:
        from flask import Response
        import json
        return Response(json.dumps({'error': 'Result not found'}), status=404, mimetype='application/json')

@app.route('/api/generate-report', methods=['POST'])
def generate_report():
    """生成报告"""
    try:
        data = request.json
        result_id = data.get('result_id')
        if not result_id or result_id not in scan_results:
            return jsonify({'error': 'Invalid result ID'}), 400
        
        # 获取扫描结果
        result = scan_results[result_id]
        
        # 提取敏感信息发现
        secrets = []
        for url_node, secret_set in result.get('secrets', {}).items():
            for secret in secret_set:
                # 处理secret可能是对象的情况
                if hasattr(secret, '__dict__'):
                    secret_dict = {
                        'type': getattr(secret, 'type', 'unknown'),
                        'category': getattr(secret, 'category', 'unknown'),
                        'matched_text': getattr(secret, 'value', ''),
                        'location': url_node,
                        'confidence': getattr(secret, 'confidence', 0.5),
                        'entropy': getattr(secret, 'entropy', 0)
                    }
                elif isinstance(secret, dict):
                    secret_dict = {
                        'type': secret.get('type', 'unknown'),
                        'category': secret.get('category', 'unknown'),
                        'matched_text': secret.get('value', secret.get('matched_text', '')),
                        'location': url_node,
                        'confidence': secret.get('confidence', 0.5),
                        'entropy': secret.get('entropy', 0)
                    }
                else:
                    continue
                secrets.append(secret_dict)
        
        # 生成报告
        pipeline = DualStagePipeline(use_deep_analysis=False)
        context = {
            'url': list(result.get('urls', {}).keys())[0] if result.get('urls', {}) else 'unknown',
            'environment': 'production',
            'surrounding_text': 'Web scan results'
        }
        report_result = pipeline.run(secrets, context)
        
        return jsonify({'message': 'Report generated successfully', 'report_result': report_result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deep-analysis', methods=['POST'])
def deep_analysis():
    """执行深度分析"""
    try:
        data = request.json
        result_id = data.get('result_id')
        if not result_id or result_id not in scan_results:
            return jsonify({'error': 'Invalid result ID'}), 400
        
        # 获取扫描结果
        result = scan_results[result_id]
        
        # 提取敏感信息发现
        secrets = []
        for url_node, secret_set in result.get('secrets', {}).items():
            for secret in secret_set:
                # 处理secret可能是对象的情况
                if hasattr(secret, '__dict__'):
                    secret_dict = {
                        'type': getattr(secret, 'type', 'unknown'),
                        'category': getattr(secret, 'category', 'unknown'),
                        'matched_text': getattr(secret, 'value', ''),
                        'location': url_node,
                        'confidence': getattr(secret, 'confidence', 0.5),
                        'entropy': getattr(secret, 'entropy', 0)
                    }
                elif isinstance(secret, dict):
                    secret_dict = {
                        'type': secret.get('type', 'unknown'),
                        'category': secret.get('category', 'unknown'),
                        'matched_text': secret.get('value', secret.get('matched_text', '')),
                        'location': url_node,
                        'confidence': secret.get('confidence', 0.5),
                        'entropy': secret.get('entropy', 0)
                    }
                else:
                    continue
                secrets.append(secret_dict)
        
        # 执行深度分析
        pipeline = DualStagePipeline(use_deep_analysis=True)
        context = {
            'url': list(result.get('urls', {}).keys())[0] if result.get('urls', {}) else 'unknown',
            'environment': 'production',
            'surrounding_text': 'Web scan results'
        }
        analysis_result = pipeline.run(secrets, context)
        
        return jsonify({'message': 'Deep analysis completed', 'analysis_result': analysis_result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports', methods=['GET'])
def get_reports():
    """获取报告列表"""
    try:
        reports_dir = Path(__file__).parent / 'reports'
        if not reports_dir.exists():
            return jsonify({'reports': []})
        
        reports = []
        for file in reports_dir.iterdir():
            if file.is_file():
                reports.append({
                    'name': file.name,
                    'path': str(file.relative_to(Path(__file__).parent)),
                    'size': file.stat().st_size,
                    'mtime': file.stat().st_mtime
                })
        
        # 按修改时间排序，最新的在前
        reports.sort(key=lambda x: x['mtime'], reverse=True)
        
        return jsonify({'reports': reports})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<path:report_path>', methods=['GET'])
def get_report(report_path):
    """获取报告内容"""
    try:
        report_file = Path(__file__).parent / report_path
        if not report_file.exists() or not report_file.is_file():
            return jsonify({'error': 'Report not found'}), 404
        
        # 读取报告内容
        with open(report_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return jsonify({'content': content, 'name': report_file.name})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # 创建templates目录
    templates_dir = Path(__file__).parent / 'templates'
    templates_dir.mkdir(exist_ok=True)
    
    # 创建静态文件目录
    static_dir = Path(__file__).parent / 'static'
    static_dir.mkdir(exist_ok=True)
    
    # 创建reports目录
    reports_dir = Path(__file__).parent / 'reports'
    reports_dir.mkdir(exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
