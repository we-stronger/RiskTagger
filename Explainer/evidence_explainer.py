import os
import json
import re
import ast
from pathlib import Path
from typing import Optional
from openai import OpenAI

import os

from project_config import (
    EXPLAINER_OUTPUT_ROOT, get_case_profile_path, get_event_name,
    get_module_settings, require_environment,
)
from Explainer.inputs import prepare_evidence_inputs

SETTINGS = get_module_settings("explainer")

# ==========================================
# 核心执行器类：支持多模态文本解析与 Markdown 报告生成
# ==========================================
class RiskTaggerEvidenceExplainer:
    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None, model_name: Optional[str] = None):
        """初始化推理引擎（使用实验表现最优的 Qwen3-Max）"""
        llm_settings = SETTINGS["llm"]
        self.client = OpenAI(
            api_key=api_key or require_environment(llm_settings["api_key_env"]),
            base_url=base_url or llm_settings["base_url"],
        )
        self.model_name = model_name or llm_settings["model"]

    def _normalize_risk_label(self, label: str) -> str:
        """
        【用户修正规则】：消除空格和 "Risk" 单词的影响，确保 "High Risk" 与 "High" 语义匹配
        """
        if not label:
            return 'None'
        cleaned = re.sub(r'\s+', '', str(label).lower()).replace('risk', '')
        if cleaned in ['high', 'h']:
            return 'High'
        elif cleaned in ['medium', 'med', 'm']:
            return 'Medium'
        elif cleaned in ['low', 'l']:
            return 'Low'
        else:
            return 'None'

    def _parse_statistics_summary(self, content: str) -> dict:
        """
        专门解析 hack_statistics_summary.txt 这种纯文本表格排版的报告
        将其转换为结构化的字典供 LLM 理解宏观趋势
        """
        result = {
            "layer_totals": {},
            "global_risk_totals": {},
            "layer_risk_matrix": {}
        }

        sections = re.split(r'\d+\.\s+', content)

        for sec in sections:
            if "每层地址总数" in sec:
                matches = re.findall(r'Layer(\d+)\s+(\d+)', sec)
                for layer, count in matches:
                    result["layer_totals"][f"Layer{layer}"] = int(count)

            elif "风险等级地址总数" in sec:
                matches = re.findall(r'(High|Low|Medium)\s+(\d+)', sec)
                for risk, count in matches:
                    result["global_risk_totals"][risk] = int(count)

            elif "每层风险分布矩阵" in sec:
                matches = re.findall(r'Layer(\d+)\s+(\d+)\s+(\d+)\s+(\d+)', sec)
                for layer, high, med, low in matches:
                    result["layer_risk_matrix"][f"Layer{layer}"] = {
                        "High": int(high),
                        "Medium": int(med),
                        "Low": int(low)
                    }

        return result

    def _parse_reasoner_log(self, content: str) -> list:
        """
        专门用于解析带有分割线和 'Account Address:' 的抽样推理日志。
        通过查找第一个 '{' 和最后一个 '}' 来精确提取 JSON 块，彻底解决正则嵌套截断。
        """
        results = []
        blocks = content.split("Account Address:")

        for block in blocks:
            if not block.strip():
                continue

            addr_match = re.search(r'\s*(0x[a-fA-F0-9]+)', block)
            if not addr_match:
                continue
            address = addr_match.group(1)

            start_idx = block.find('{')
            end_idx = block.rfind('}')

            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                json_block = block[start_idx:end_idx + 1]
                try:
                    data = json.loads(json_block)
                except json.JSONDecodeError:
                    try:
                        data = ast.literal_eval(json_block)
                    except Exception:
                        continue

                rationale_parts = []
                for key in ["a_transaction_patterns", "b_fund_flows", "c_associated_addresses",
                            "d_temporal_behavioral_signs"]:
                    if key in data and isinstance(data[key], dict):
                        rationale_parts.append(f"[{key}]: {data[key].get('evidence', '')}")

                results.append({
                    "address": address,
                    "layer": data.get("layer", "Unknown"),
                    "risk_level": data.get("suspicion_level", "None"),
                    "cot_rationale": " | ".join(rationale_parts)
                })

        return results

    def _load_file_robustly(self, file_path: str):
        """
        全能文件读取器：支持 JSON、Python 字典字面量、统计报表以及抽样推理日志
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"未找到指定的输入文件: {file_path}")

        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return {}

        if "洗钱追踪地址统计结果" in content or "每层地址总数" in content:
            print(f"📄 检测到纯文本统计报表 [{os.path.basename(file_path)}]，启动专用报表解析器...")
            return self._parse_statistics_summary(content)

        if "Account Address: 0x" in content and "suspicion_level" in content:
            print(f"📄 检测到 Reasoner 抽样日志 [{os.path.basename(file_path)}]，启动正则块提取器...")
            return self._parse_reasoner_log(content)

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            print(f"⚠️ 文件 [{os.path.basename(file_path)}] 不是标准 JSON，尝试 Python 字典解析...")
            try:
                return ast.literal_eval(content)
            except Exception as e:
                raise ValueError(f"❌ 无法解析文件 {file_path}。错误: {e}")

    def generate_markdown_report(self,
                                 case_profile_path: str,
                                 distribution_path: str,
                                 reasoner_path: str,
                                 cross_case_path: str = None) -> str:
        """
        读取输入文件，组装上下文，并调用 LLM 生成学术级 Markdown 报告文本
        """
        print("正在加载并清洗输入文件数据...")
        key_clues = self._load_file_robustly(case_profile_path)
        layer_dist = self._load_file_robustly(distribution_path)

        raw_judgments = self._load_file_robustly(reasoner_path)
        if isinstance(raw_judgments, dict) and "results" in raw_judgments:
            raw_judgments = raw_judgments["results"]

        cross_case_knowledge = {}
        if cross_case_path and os.path.exists(cross_case_path):
            cross_case_knowledge = self._load_file_robustly(cross_case_path)

        # 标签对齐与清洗
        risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'None': 0}
        filtered_rationales = []

        for item in raw_judgments:
            raw_label = item.get('risk_level', 'None')
            norm_label = self._normalize_risk_label(raw_label)
            risk_counts[norm_label] += 1

            if norm_label in ['High', 'Medium'] and item.get('cot_rationale'):
                filtered_rationales.append({
                    "address": item.get("address"),
                    "layer": item.get("layer"),
                    "label": norm_label,
                    "rationale": item.get("cot_rationale")
                })

        # 组装高浓度 Context
        context_data = {
            "incident_initial_clues": key_clues,
            "account_layer_distribution": layer_dist,
            "global_risk_statistics_from_sample": risk_counts,
            "cross_case_historical_infrastructure": cross_case_knowledge,
            "backbone_laundering_rationales_sample": filtered_rationales[:40]
        }

        # 构建高标准的 Markdown 生成 Prompt
        system_prompt = (
            "你是一个精通 Web3 账本取证与区块链反洗钱（AML）的资深安全科学家。你的任务是将输入的多源取证数据"
            "整合成一份具有顶级安全会议（如 NDSS、USENIX Security）学术深度的自动化事件取证与洗钱模式分析报告。\n\n"
            "请直接输出标准的 Markdown 文本，严格遵循以下结构和学术深度要求：\n"
            "# 加密货币安全事件自动化取证与洗钱网络深度分析报告\n\n"
            "## 1. 案件摘要汇总 (Case Summary)\n"
            "结合外部提供的案件初始背景（链名称、受害者、损失金额、攻击手法等），对该安全事件进行系统性叙述。\n\n"
            "## 2. 洗钱图谱宏观统计与风险分布 (Risk Statistics & Matrix)\n"
            "分析全量标签归一化后的高、中、低风险账户精确统计。必须使用 Markdown 表格形式呈现每层的风险分布矩阵。\n\n"
            "## 3. 资金网络动态演进分析 (Dynamic Evolution Analysis)\n"
            "依据账户层级分布数据，深度解构资金在多跳流转中的时空演进规律。重点分析是否存在“多阶段脉冲现象”（例如早期原生代币激增，后期稳定币清算等双峰或多峰趋势）。\n\n"
            "## 4. 核心安全洞察 (Automated Security Insights)\n"
            "提炼出 3-4 个战术或策略层面的深度洞察，每个 Insight 必须包含以下标准化二级子标题：\n"
            "### Security Insight X: [标题名称]\n"
            "- **Observed Pattern (现象描述)**: 结合具体层级、时间特征和代币类型的行为模式描述。\n"
            "- **Evidence Support (数据证据)**: 列举支撑该发现的微观核心证据或代表性地址的行为指纹。\n"
            "- **Security Implication (安全内涵)**: 阐述攻击者的对抗性取证（Anti-forensic）意图以及对传统监控系统的逃逸影响。\n\n"
            "（提示：至少包含‘延迟触发的休眠-爆发策略’以及‘盲中继与脚本化同质行为’；如果提供了跨案例知识，必须增加‘跨案例基础设施复用’的深入对比）。\n\n"
            "## 5. 面向执法与安全审计的取证建议 (Forensic Recommendations)\n"
            "针对本案暴露的高级对抗手法，为审计机构或执法单位提出具体的资产追回、合规追溯及防范逃逸的实操建议。\n\n"
            "注意：不要输出任何关于 JSON 结构的代码或解释，直接开始编写 Markdown 报告体。"
        )

        user_content = f"请读取并分析以下输入文件组装的上下文，生成 Markdown 格式的综合事件分析报告:\n{json.dumps(context_data, ensure_ascii=False)}"

        print("数据组装完毕，正在调用 Qwen3-Max 进行学术 Markdown 报告流式生成...")

        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            temperature=0.3  # 低温度确保司法级取证证据的严密性与确定性
        )

        return response.choices[0].message.content


# ==========================================
# 3. Pipeline 运行入口
# ==========================================
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate an evidence report from a supplied case profile and saved Tracer results.")
    parser.add_argument("--case-profile", type=Path, help="Default: data/cases/<event>/case_profile.json")
    parser.add_argument("--distribution", type=Path, help="Optional statistics JSON/text (must accompany --reasoner)")
    parser.add_argument("--reasoner", type=Path, help="Optional reasoning JSON/text (must accompany --distribution)")
    parser.add_argument("--cross-case", type=Path)
    args = parser.parse_args()
    if bool(args.distribution) != bool(args.reasoner):
        parser.error("Provide --distribution and --reasoner together")
    event = get_event_name()
    profile = args.case_profile or get_case_profile_path(event)
    if not profile.is_file():
        parser.error(f"Supplied case profile not found: {profile}")
    distribution, reasoner = (args.distribution, args.reasoner) if args.distribution else prepare_evidence_inputs(event)
    explainer = RiskTaggerEvidenceExplainer()
    report = explainer.generate_markdown_report(profile, distribution, reasoner, args.cross_case)
    output = EXPLAINER_OUTPUT_ROOT / event / f"{event}_comprehensive_evidence_report.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"Evidence report saved: {output}")


if __name__ == "__main__":
    main()
