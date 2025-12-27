#!/usr/bin/env python3
"""
Report Generator for Banner Grabber Results
Comprehensive analysis and reporting module
"""

import json
import csv
import argparse
from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict, Counter
import statistics

class ReportGenerator:
    """Generate comprehensive reports from banner grabber results"""

    def __init__(self, results_file: str):
        self.results_file = results_file
        self.results = self._load_results()
        self.analysis = self._analyze_results()

    def _load_results(self) -> List[Dict]:
        """Load results from JSON file"""
        try:
            with open(self.results_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading results: {e}")
            return []

    def _analyze_results(self) -> Dict[str, Any]:
        """Perform comprehensive analysis of results"""
        if not self.results:
            return {}

        analysis = {
            "summary": self._generate_summary(),
            "security_analysis": self._analyze_security(),
            "service_distribution": self._analyze_services(),
            "waf_analysis": self._analyze_waf(),
            "version_analysis": self._analyze_versions(),
            "error_analysis": self._analyze_errors(),
            "recommendations": self._generate_recommendations()
        }

        return analysis

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        total_scans = len(self.results)
        successful_scans = len([r for r in self.results if not r.get('error')])
        error_scans = total_scans - successful_scans

        targets = set(r.get('target') for r in self.results)
        ports_scanned = set(r.get('port') for r in self.results)

        return {
            "total_scans": total_scans,
            "successful_scans": successful_scans,
            "error_scans": error_scans,
            "success_rate": successful_scans / total_scans if total_scans > 0 else 0,
            "unique_targets": len(targets),
            "ports_scanned": len(ports_scanned),
            "scan_timestamp": datetime.now().isoformat()
        }

    def _analyze_security(self) -> Dict[str, Any]:
        """Analyze security posture"""
        security_findings = {
            "exposed_services": [],
            "waf_protected": [],
            "outdated_versions": [],
            "insecure_protocols": [],
            "risk_score": 0
        }

        for result in self.results:
            if result.get('error'):
                continue

            port = result.get('port')
            server_info = result.get('server_info', {})

            # Check for high-risk exposed services
            high_risk_ports = [21, 22, 23, 25, 53, 110, 143, 3306, 3389]
            if port in high_risk_ports and not server_info.get('waf'):
                security_findings["exposed_services"].append({
                    "port": port,
                    "service": server_info.get('server', 'Unknown'),
                    "target": result.get('target')
                })

            # Check WAF protection
            if server_info.get('waf'):
                security_findings["waf_protected"].append({
                    "target": result.get('target'),
                    "port": port,
                    "waf": server_info['waf']
                })

            # Check for outdated versions (basic check)
            version = server_info.get('version', '')
            if version and any(old in version.lower() for old in ['1.', '2.', '3.']):
                security_findings["outdated_versions"].append({
                    "service": server_info.get('server'),
                    "version": version,
                    "target": result.get('target'),
                    "port": port
                })

        # Calculate risk score
        risk_factors = len(security_findings["exposed_services"]) * 2 + \
                      len(security_findings["outdated_versions"]) * 1
        security_findings["risk_score"] = min(risk_factors, 10)  # Scale 0-10

        return security_findings

    def _analyze_services(self) -> Dict[str, Any]:
        """Analyze service distribution"""
        services = Counter()
        protocols = Counter()

        for result in self.results:
            if not result.get('error'):
                protocol = result.get('protocol', 'Unknown')
                server_info = result.get('server_info', {})
                service = server_info.get('server', 'Unknown')

                protocols[protocol] += 1
                services[service] += 1

        return {
            "service_distribution": dict(services.most_common()),
            "protocol_distribution": dict(protocols.most_common()),
            "total_unique_services": len(services),
            "most_common_service": services.most_common(1)[0][0] if services else "None"
        }

    def _analyze_waf(self) -> Dict[str, Any]:
        """Analyze WAF detection results"""
        waf_stats = Counter()
        protected_targets = set()

        for result in self.results:
            server_info = result.get('server_info', {})
            waf = server_info.get('waf')

            if waf:
                waf_stats[waf] += 1
                protected_targets.add(result.get('target'))

        return {
            "waf_distribution": dict(waf_stats.most_common()),
            "protected_targets": len(protected_targets),
            "protection_rate": len(protected_targets) / len(set(r.get('target') for r in self.results)) if self.results else 0,
            "most_common_waf": waf_stats.most_common(1)[0][0] if waf_stats else "None"
        }

    def _analyze_versions(self) -> Dict[str, Any]:
        """Analyze version information"""
        versions = {}
        version_stats = Counter()

        for result in self.results:
            if not result.get('error'):
                server_info = result.get('server_info', {})
                service = server_info.get('server', 'Unknown')
                version = server_info.get('version', '')

                if version:
                    if service not in versions:
                        versions[service] = []
                    versions[service].append(version)
                    version_stats[service] += 1

        # Analyze version diversity
        version_diversity = {}
        for service, vers in versions.items():
            unique_versions = set(vers)
            version_diversity[service] = {
                "unique_versions": len(unique_versions),
                "total_instances": len(vers),
                "versions": list(unique_versions)[:5]  # Top 5
            }

        return {
            "services_with_versions": dict(version_stats.most_common()),
            "version_diversity": version_diversity,
            "version_detection_rate": version_stats.total() / len([r for r in self.results if not r.get('error')]) if self.results else 0
        }

    def _analyze_errors(self) -> Dict[str, Any]:
        """Analyze error patterns"""
        errors = Counter()
        error_by_port = defaultdict(Counter)
        error_by_target = defaultdict(Counter)

        for result in self.results:
            error = result.get('error')
            if error:
                # Categorize errors
                if "timed out" in error.lower():
                    error_cat = "Timeout"
                elif "connection refused" in error.lower():
                    error_cat = "Connection Refused"
                elif "unavailable" in error.lower():
                    error_cat = "Service Unavailable"
                elif "blocked" in error.lower():
                    error_cat = "Blocked"
                else:
                    error_cat = "Other"

                errors[error_cat] += 1
                error_by_port[result.get('port')][error_cat] += 1
                error_by_target[result.get('target')][error_cat] += 1

        return {
            "error_distribution": dict(errors.most_common()),
            "error_by_port": dict(error_by_port),
            "error_by_target": dict(error_by_target),
            "total_errors": sum(errors.values()),
            "error_rate": sum(errors.values()) / len(self.results) if self.results else 0
        }

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        security = self.analysis.get('security_analysis', {})
        waf = self.analysis.get('waf_analysis', {})
        errors = self.analysis.get('error_analysis', {})

        # WAF recommendations
        if waf.get('protection_rate', 0) < 0.5:
            recommendations.append("Consider implementing WAF protection for better security")

        # Exposed services recommendations
        exposed = security.get('exposed_services', [])
        if exposed:
            recommendations.append(f"Review exposure of {len(exposed)} high-risk services")

        # Version recommendations
        versions = self.analysis.get('version_analysis', {})
        if versions.get('version_detection_rate', 0) < 0.3:
            recommendations.append("Improve version detection for better vulnerability assessment")

        # Error recommendations
        if errors.get('error_rate', 0) > 0.5:
            recommendations.append("High error rate detected - investigate connectivity issues")

        return recommendations

    def generate_text_report(self) -> str:
        """Generate human-readable text report"""
        report = []
        report.append("=" * 60)
        report.append("BANNER GRABBER ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Results File: {self.results_file}")
        report.append("")

        # Summary
        summary = self.analysis.get('summary', {})
        report.append("SCAN SUMMARY")
        report.append("-" * 20)
        report.append(f"Total Scans: {summary.get('total_scans', 0)}")
        report.append(f"Successful: {summary.get('successful_scans', 0)}")
        report.append(f"Errors: {summary.get('error_scans', 0)}")
        report.append(f"Success Rate: {summary.get('success_rate', 0):.1%}")
        report.append("")

        # Security Analysis
        security = self.analysis.get('security_analysis', {})
        report.append("SECURITY ANALYSIS")
        report.append("-" * 20)
        report.append(f"Risk Score: {security.get('risk_score', 0)}/10")

        exposed = security.get('exposed_services', [])
        if exposed:
            report.append(f"⚠️  Exposed High-Risk Services: {len(exposed)}")
            for service in exposed[:5]:  # Show top 5
                report.append(f"   • {service['target']}:{service['port']} ({service['service']})")

        waf_protected = security.get('waf_protected', [])
        if waf_protected:
            report.append(f"✅ WAF Protected Targets: {len(waf_protected)}")

        outdated = security.get('outdated_versions', [])
        if outdated:
            report.append(f"⚠️  Outdated Versions: {len(outdated)}")
        report.append("")

        # Service Analysis
        services = self.analysis.get('service_distribution', {})
        report.append("SERVICE DISTRIBUTION")
        report.append("-" * 20)
        for service, count in services.get('service_distribution', {}).items():
            report.append(f"{service}: {count}")
        report.append("")

        # WAF Analysis
        waf = self.analysis.get('waf_analysis', {})
        report.append("WAF ANALYSIS")
        report.append("-" * 20)
        report.append(f"Protection Rate: {waf.get('protection_rate', 0):.1%}")
        for waf_type, count in waf.get('waf_distribution', {}).items():
            report.append(f"{waf_type}: {count}")
        report.append("")

        # Recommendations
        recommendations = self.analysis.get('recommendations', [])
        if recommendations:
            report.append("RECOMMENDATIONS")
            report.append("-" * 20)
            for rec in recommendations:
                report.append(f"• {rec}")
            report.append("")

        return "\n".join(report)

    def export_json_report(self, output_file: str):
        """Export detailed JSON report"""
        report = {
            "metadata": {
                "generated": datetime.now().isoformat(),
                "results_file": self.results_file,
                "analyzer_version": "1.0"
            },
            "analysis": self.analysis,
            "raw_results": self.results
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

    def export_csv_report(self, output_file: str):
        """Export CSV summary report"""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)

            # Write summary
            writer.writerow(["Section", "Metric", "Value"])
            summary = self.analysis.get('summary', {})
            for key, value in summary.items():
                writer.writerow(["Summary", key, value])

            writer.writerow([])

            # Write security findings
            security = self.analysis.get('security_analysis', {})
            writer.writerow(["Security", "Risk Score", security.get('risk_score', 0)])

            for service in security.get('exposed_services', []):
                writer.writerow(["Security", "Exposed Service",
                               f"{service['target']}:{service['port']} ({service['service']})"])

def main():
    """Command-line interface for report generation"""
    parser = argparse.ArgumentParser(description="Banner Grabber Report Generator")
    parser.add_argument("results_file", help="JSON results file from banner grabber")
    parser.add_argument("-o", "--output", help="Output file (auto-generated if not specified)")
    parser.add_argument("-f", "--format", choices=['text', 'json', 'csv'], default='text',
                       help="Output format")
    parser.add_argument("--summary-only", action="store_true",
                       help="Generate summary only (for text format)")

    args = parser.parse_args()

    generator = ReportGenerator(args.results_file)

    if args.format == 'json':
        output_file = args.output or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        generator.export_json_report(output_file)
        print(f"JSON report exported to: {output_file}")

    elif args.format == 'csv':
        output_file = args.output or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        generator.export_csv_report(output_file)
        print(f"CSV report exported to: {output_file}")

    else:  # text
        report = generator.generate_text_report()
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"Text report exported to: {args.output}")
        else:
            print(report)

if __name__ == "__main__":
    main()