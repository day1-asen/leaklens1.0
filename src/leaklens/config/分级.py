# 分级.py
import json
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import dataclass, asdict

@dataclass
class SimpleFinding:
    """简易发现数据格式"""
    id: str
    type: str  # id_card, phone, api_key等
    category: str  # Personal, Credentials, Technical等
    matched_text: str  # 已脱敏
    location: str  # URL或文件路径
    severity: str  # CRITICAL/HIGH/MEDIUM/LOW/INFO
    confidence: float
    entropy: float
    timestamp: str

class QuickGrader:
    """快速整理分级系统"""
    
    def __init__(self):
        # 参考新国标模板的敏感等级定义[citation:2]
        self.severity_rules = {
            'id_card': {'base': 'HIGH', 'entropy_threshold': 3.5},
            'phone': {'base': 'MEDIUM', 'entropy_threshold': 3.2},
            'email': {'base': 'LOW', 'entropy_threshold': 3.0},
            'api_key': {'base': 'HIGH', 'entropy_threshold': 4.0},
            'jwt_token': {'base': 'HIGH', 'entropy_threshold': 4.5},
            'password': {'base': 'HIGH', 'entropy_threshold': 3.5},
            'credit_card': {'base': 'CRITICAL', 'entropy_threshold': 3.0},
            'database_conn': {'base': 'CRITICAL', 'entropy_threshold': 4.0},
            'default': {'base': 'MEDIUM', 'entropy_threshold': 3.0}
        }
    
    def process(self, raw_findings: List[Dict]) -> Dict:
        """
        快速处理原始检测数据
        输出：标准化数据 + 简易报告
        """
        # 1. 数据标准化
        normalized = []
        for idx, f in enumerate(raw_findings):
            finding = self._normalize(f, idx)
            normalized.append(finding)
        
        # 2. 规则分级（不调模型，纯规则）
        for finding in normalized:
            self._apply_quick_grade(finding)
        
        # 3. 生成统计信息
        stats = self._generate_stats(normalized)
        
        # 4. 生成简易报告（JSON/Markdown）
        report = self._generate_simple_report(normalized, stats)
        
        return {
            'findings': [asdict(f) for f in normalized],
            'stats': stats,
            'report': report,
            'candidates_for_deep_analysis': self._select_for_deep_analysis(normalized)
        }
    
    def _normalize(self, raw: Dict, idx: int) -> SimpleFinding:
        """标准化单个发现"""
        return SimpleFinding(
            id=f"F{idx:04d}",
            type=raw.get('type', 'unknown'),
            category=raw.get('category', 'unknown'),
            matched_text=raw.get('matched_text', ''),
            location=raw.get('location', 'unknown'),
            severity='MEDIUM',  # 默认，后续覆盖
            confidence=raw.get('confidence', 0.5),
            entropy=raw.get('entropy', 0),
            timestamp=datetime.now().isoformat()
        )
    
    def _apply_quick_grade(self, finding: SimpleFinding):
        """应用快速分级规则"""
        rule = self.severity_rules.get(
            finding.type, 
            self.severity_rules['default']
        )
        
        # 熵值过低，降级
        if finding.entropy < rule['entropy_threshold']:
            finding.severity = 'INFO'
            finding.confidence *= 0.5
        else:
            finding.severity = rule['base']
    
    def _generate_stats(self, findings: List[SimpleFinding]) -> Dict:
        """生成统计信息"""
        stats = {
            'total': len(findings),
            'by_severity': {},
            'by_type': {},
            'avg_confidence': 0,
            'high_risk_count': 0
        }
        
        total_conf = 0
        for f in findings:
            stats['by_severity'][f.severity] = stats['by_severity'].get(f.severity, 0) + 1
            stats['by_type'][f.type] = stats['by_type'].get(f.type, 0) + 1
            total_conf += f.confidence
            if f.severity in ['CRITICAL', 'HIGH']:
                stats['high_risk_count'] += 1
        
        stats['avg_confidence'] = total_conf / len(findings) if findings else 0
        return stats
    
    def _generate_simple_report(self, findings: List[SimpleFinding], stats: Dict) -> Dict:
        """生成简易报告（JSON/Markdown两版）"""
        
        # JSON版本（供CI/CD消费）
        json_report = {
            'summary': stats,
            'findings': [asdict(f) for f in findings],
            'generated_at': datetime.now().isoformat(),
            'version': '1.0-simple'
        }
        
        # Markdown版本（供快速阅读）
        md_lines = []
        md_lines.append("# 敏感信息检测简易报告\n")
        md_lines.append(f"**生成时间**：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        md_lines.append(f"**总发现数**：{stats['total']}\n")
        md_lines.append("## 风险统计\n")
        for sev, count in stats['by_severity'].items():
            md_lines.append(f"- {sev}: {count}")
        md_lines.append("\n## 发现列表\n")
        for f in findings[:10]:  # 只展示前10条
            # 确保显示具体的IP地址或其他敏感信息
            matched_text = f.matched_text if f.matched_text else '未知'
            md_lines.append(f"- [{f.severity}] {f.type}: {matched_text}")
        
        markdown_report = '\n'.join(md_lines)
        
        return {
            'json': json_report,
            'markdown': markdown_report
        }
    
    def _select_for_deep_analysis(self, findings: List[SimpleFinding]) -> List[Dict]:
        """选择需要深度分析的发现（模糊/高风险）"""
        candidates = []
        # 选择所有发现进行深度分析
        for f in findings:
            candidates.append(asdict(f))
        
        # 确保至少有一个候选者
        if not candidates and findings:
            candidates.append(asdict(findings[0]))
        
        return candidates
