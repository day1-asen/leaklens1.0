# 报告生成.py
import json
from datetime import datetime
from typing import Dict, List
import markdown  # 用于转换HTML
import os

class ReportGenerator:
    """报告生成器（支持双版本）"""
    
    def __init__(self):
        # 创建报告目录
        self.report_dir = 'reports'
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_simple_report(self, data: Dict) -> Dict:
        """
        生成简易报告（阶段一输出）
        格式：JSON + Markdown
        """
        simple = data.get('report', {})
        
        # 生成文件名
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        json_path = os.path.join(self.report_dir, f'report_simple_{timestamp}.json')
        markdown_path = os.path.join(self.report_dir, f'report_simple_{timestamp}.md')
        
        # 保存JSON
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(simple['json'], f, ensure_ascii=False, indent=2)
        
        # 保存Markdown
        with open(markdown_path, 'w', encoding='utf-8') as f:
            f.write(simple['markdown'])
        
        return {
            'json_path': json_path,
            'markdown_path': markdown_path
        }
    
    def generate_detailed_report(self, 
                                 simple_data: Dict, 
                                 deep_analysis: List[Dict],
                                 context: Dict = None) -> Dict:
        """
        生成详细报告（阶段二输出）
        格式：HTML可视化报告
        """
        findings = simple_data.get('findings', [])
        stats = simple_data.get('stats', {})
        
        # 生成文件名
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        html_path = os.path.join(self.report_dir, f'report_detailed_{timestamp}.html')
        
        # 获取检测的URL
        target_url = context.get('url', '未知URL') if context else '未知URL'
        
        # 构建HTML内容
        html = []
        html.append("""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>敏感信息深度分析报告</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .critical { background-color: #8B0000; color: white; }
                .high { background-color: #FF4500; color: white; }
                .medium { background-color: #FFA500; }
                .low { background-color: #FFD700; }
                .info { background-color: #90EE90; }
                .finding { border: 1px solid #ddd; margin: 10px 0; padding: 10px; }
                .test-data { background-color: #f0f0f0; color: #888; }
                .ai-analysis { margin-top: 10px; padding: 10px; background-color: #f9f9f9; border-left: 4px solid #0066cc; }
            </style>
        </head>
        <body>
        """)
        
        # 标题和统计
        html.append(f"<h1>敏感信息深度分析报告</h1>")
        html.append(f"<p>生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        html.append(f"<p>检测URL：{target_url}</p>")
        html.append(f"<p>总发现数：{stats.get('total', 0)} | 高风险：{stats.get('high_risk_count', 0)}</p>")
        
        # AI增强的发现列表
        html.append("<h2>AI深度分析结果</h2>")
        
        # 合并AI分析结果
        ai_map = {a['id']: a for a in deep_analysis}
        
        for f in findings:
            f_id = f['id']
            css_class = f['severity'].lower()
            
            # 如果被AI判定为测试数据，特殊标记
            if f_id in ai_map and ai_map[f_id].get('ai_verdict') == 'test_data':
                css_class = 'test-data'
            
            html.append(f'<div class="finding {css_class}">')
            html.append(f'<h3>[{f["severity"]}] {f["type"]} - {f["matched_text"]}</h3>')
            html.append(f'<p>位置：{f["location"]} | 置信度：{f["confidence"]} | 熵值：{f["entropy"]}</p>')
            
            # 添加AI分析内容
            if f_id in ai_map:
                ai = ai_map[f_id]
                html.append('<div class="ai-analysis">')
                if ai.get('ai_verdict') == 'test_data':
                    html.append(f'<p><strong>⚠️ AI判定为测试数据</strong>：{ai.get("ai_reason", "")}</p>')
                else:
                    html.append('<h4>AI语义分析</h4>')
                    semantic = ai.get('ai_semantic', {})
                    real_type = semantic.get('type', '未知')
                    confidence = semantic.get('confidence', '未知')
                    html.append(f'<p>真实类型：{real_type} | 置信度：{confidence}</p>')
                    
                    html.append('<h4>风险链</h4>')
                    risk_chain = ai.get('ai_risk_chain', [])
                    if risk_chain:
                        for step in risk_chain:
                            step_num = step.get('step', '未知')
                            action = step.get('action', '未知')
                            likelihood = step.get('likelihood', '未知')
                            html.append(f'<p>步骤{step_num}：{action}（可能性：{likelihood}）</p>')
                    else:
                        html.append('<p>暂无风险链分析</p>')
                    
                    html.append('<h4>修复建议</h4>')
                    remediation = ai.get('ai_remediation', '暂无修复建议')
                    html.append(f'<p>{remediation.replace(chr(10), "<br/>")}</p>')
                html.append('</div>')
            
            html.append('</div>')
        
        html.append("</body></html>")
        
        # 保存HTML
        html_content = '\n'.join(html)
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return {'html_path': html_path}
