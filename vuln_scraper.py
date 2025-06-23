import os
import time
import json
from datetime import datetime
from utils import logger, format_markdown
from cisa import fetch_cisa_vulns
from oscs import fetch_oscs_vulns
from qianxin import fetch_qianxin_vulns
from threatbook import fetch_threatbook_vulns

class VulnScraper:
    def __init__(self, config_path='vuln_crawler_config.json'):
        self.config = self.load_config(config_path)
        self.output_dir = self.config.get('output_dir', 'vulnerability_reports')
        self.vuln_sources = {
            'CISA': fetch_cisa_vulns,
            'OSCS': fetch_oscs_vulns,
            'Qianxin': fetch_qianxin_vulns,
            'ThreatBook': fetch_threatbook_vulns
        }
        # 创建输出目录
        os.makedirs(self.output_dir, exist_ok=True)

    def load_config(self, config_path):
        """加载配置文件"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"配置文件 {config_path} 未找到，使用默认配置")
            return {}
        except json.JSONDecodeError:
            logger.error(f"配置文件 {config_path} 格式错误")
            return {}

    def fetch_all_vulns(self):
        """从所有数据源获取漏洞信息"""
        all_vulns = {}
        for source_name, fetcher in self.vuln_sources.items():
            try:
                logger.info(f"开始从 {source_name} 获取漏洞信息")
                vulns = fetcher()
                if vulns:
                    all_vulns[source_name] = vulns
                    logger.info(f"成功获取 {source_name} 漏洞信息 {len(vulns)} 条")
                else:
                    logger.warning(f"未获取到 {source_name} 漏洞信息")
            except Exception as e:
                logger.error(f"获取 {source_name} 漏洞信息失败: {str(e)}")
            # 添加延迟避免请求过于频繁
            time.sleep(2)
        return all_vulns

    def generate_markdown_report(self, vulns, report_date=None):
        """生成Markdown格式的漏洞报告"""
        if not report_date:
            report_date = datetime.now().strftime('%Y-%m-%d')

        md_content = f"# 漏洞情报报告 - {report_date}\n\n"
        md_content += f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        md_content += "## 目录\n"

        # 添加目录
        for source_name in vulns.keys():
            md_content += f"- [{source_name}](#{source_name.lower()})\n"
        md_content += "\n---\n"

        # 添加各来源漏洞详情
        for source_name, vuln_list in vulns.items():
            md_content += f"## {source_name}\n\n"
            if not vuln_list:
                md_content += "暂无漏洞信息\n\n"
                continue

            # 按严重程度排序（假设漏洞信息中有'severity'字段）
            sorted_vulns = sorted(vuln_list, key=lambda x: x.get('severity', 'medium'), reverse=True)

            for idx, vuln in enumerate(sorted_vulns, 1):
                md_content += format_markdown(vuln, idx)
                md_content += "\n---\n"

        return md_content

    def save_report(self, content, report_date=None):
        """保存Markdown报告到文件"""
        if not report_date:
            report_date = datetime.now().strftime('%Y-%m-%d')
        filename = f"vulnerability_report_{report_date}.md"
        file_path = os.path.join(self.output_dir, filename)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

        logger.info(f"漏洞报告已保存至: {file_path}")
        return file_path

    def run(self):
        """执行完整的爬取和报告生成流程"""
        logger.info("===== 开始漏洞信息爬取流程 ====")
        vulns = self.fetch_all_vulns()
        if not vulns:
            logger.error("未获取到任何漏洞信息，无法生成报告")
            return None

        logger.info("开始生成Markdown报告")
        report_content = self.generate_markdown_report(vulns)
        report_path = self.save_report(report_content)

        logger.info("===== 漏洞信息爬取流程完成 ====")
        return report_path

if __name__ == "__main__":
    scraper = VulnScraper()
    scraper.run()