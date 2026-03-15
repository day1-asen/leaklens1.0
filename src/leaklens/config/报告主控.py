# 报告主控.py
from typing import List, Dict
from leaklens.config.分级 import QuickGrader
from leaklens.config.深度分析 import DeepAnalyzer
from leaklens.config.报告生成 import ReportGenerator

class DualStagePipeline:
    """双阶段报告生成流水线"""
    
    def __init__(self, use_deep_analysis=True):
        self.grader = QuickGrader()
        self.analyzer = DeepAnalyzer() if use_deep_analysis else None
        self.reporter = ReportGenerator()
    
    def run(self, raw_findings: List[Dict], context: Dict = None):
        """
        执行完整流水线
        """
        print("阶段一：快速整理分级...")
        stage1_result = self.grader.process(raw_findings)
        
        # 生成简易报告
        simple_report = self.reporter.generate_simple_report(stage1_result)
        print(f"简易报告已生成：{simple_report}")
        
        # 存储报告路径
        report_paths = {
            'simple_report': simple_report
        }
        
        # 如果需要深度分析
        if self.analyzer:
            candidates = stage1_result.get('candidates_for_deep_analysis', [])
            if candidates:
                print(f"阶段二：深度分析 {len(candidates)} 条模糊/高风险发现...")
                deep_results = self.analyzer.analyze_batch(candidates, context or {})
                
                # 生成详细报告
                detailed_report = self.reporter.generate_detailed_report(
                    stage1_result, 
                    deep_results,
                    context
                )
                print(f"详细报告已生成：{detailed_report}")
                report_paths['detailed_report'] = detailed_report
            else:
                print("无需要深度分析的发现")
        
        # 将报告路径添加到返回结果中
        stage1_result['report_paths'] = report_paths
        return stage1_result


# 使用示例
if __name__ == "__main__":
    # 模拟原始检测数据
    raw_findings = [
        {
            'type': 'id_card',
            'category': 'Personal',
            'matched_text': '110101199001011234',
            'location': 'https://example.com/index.html',
            'confidence': 0.9,
            'entropy': 2.08
        },
        {
            'type': 'api_key',
            'category': 'Credentials',
            'matched_text': 'example_api_key_123',
            'location': 'https://api.example.com/config',
            'confidence': 0.85,
            'entropy': 4.54
        }
    ]
    
    context = {
        'url': 'https://example.com',
        'environment': 'production',
        'surrounding_text': 'API configuration for production'
    }
    
    pipeline = DualStagePipeline(use_deep_analysis=True)
    result = pipeline.run(raw_findings, context)
