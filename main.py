#!/usr/bin/env python3
"""
MITRE ATT&CK Vulnerability Risk Analysis Platform
Enterprise-grade security analysis with advanced threat modeling
"""

import sys
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional
import pandas as pd
import yaml
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
import spacy
from dataclasses import field
import plotly.express as px

# Import our modules
from src.core.mitre_mapper import MITREMapper, VulnerabilityMapping
from src.core.risk_calculator import RiskCalculator, RiskAssessment
from src.analysis.heatmap_generator import AdvancedHeatmapGenerator
from src.core.data_processor import DataProcessor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('mitre_analysis.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Initialize Rich console
console = Console()

class MITREVulnerabilityAnalyzer:
    """
    Main application class for MITRE ATT&CK vulnerability analysis
    """
    
    def __init__(self, config_path: str = "config/settings.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        
        # Initialize components
        self.mitre_mapper = MITREMapper()
        self.risk_calculator = RiskCalculator()
        self.heatmap_generator = AdvancedHeatmapGenerator()
        self.data_processor = DataProcessor()
        
        console.print(Panel.fit(
            "[bold blue]MITRE ATT&CK Vulnerability Risk Analysis Platform[/bold blue]\n"
            "[italic]Enterprise-grade security analysis with advanced threat modeling[/italic]",
            border_style="blue"
        ))
    
    def _load_config(self) -> Dict:
        """Load configuration from YAML file"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    return yaml.safe_load(f)
            except Exception as e:
                logger.warning(f"Error loading config: {e}")
        
        # Default configuration
        return {
            'output_dir': 'output',
            'risk_weights': {
                'cvss_score': 0.25,
                'exploitability': 0.20,
                'business_impact': 0.25,
                'threat_landscape': 0.15,
                'asset_criticality': 0.10,
                'control_effectiveness': 0.05
            },
            'visualization': {
                'dpi': 300,
                'figsize': [12, 8],
                'style': 'seaborn-v0_8'
            }
        }
    
    def analyze_vulnerabilities(self, input_file: str, output_dir: str = "output") -> Dict:
        """
        Main analysis pipeline
        """
        console.print(f"\n[bold green]Starting MITRE ATT&CK Vulnerability Analysis[/bold green]")
        console.print(f"Input file: {input_file}")
        console.print(f"Output directory: {output_dir}")
        
        results = {
            'input_file': input_file,
            'output_dir': output_dir,
            'analysis_date': pd.Timestamp.now().isoformat(),
            'vulnerabilities_analyzed': 0,
            'ttp_mappings': [],
            'risk_assessments': [],
            'visualizations': {},
            'summary': {}
        }
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                
                # Step 1: Load and process data
                task1 = progress.add_task("Loading vulnerability data...", total=None)
                df = self.data_processor.load_data(input_file)
                if df is None or df.empty:
                    console.print("[red]Error: No data loaded or file is empty[/red]")
                    return results
                
                # Print count by severity (or Not Mentioned)
                severity_col = None
                for col in df.columns:
                    if col.lower() == 'severity':
                        severity_col = col
                        break
                if severity_col:
                    severity_counts = df[severity_col].fillna('Not Mentioned').replace('', 'Not Mentioned').value_counts(dropna=False)
                else:
                    severity_counts = pd.Series({'Not Mentioned': len(df)})
                console.print("[bold yellow]Vulnerabilities by Severity (raw input):[/bold yellow]")
                for sev, count in severity_counts.items():
                    console.print(f"  [cyan]{sev}[/cyan]: {count}")
                
                df_clean, key_columns = self.data_processor.clean_and_identify_columns(df)
                if not key_columns:
                    console.print("[red]Error: Could not identify required columns[/red]")
                    console.print(f"Available columns: {list(df_clean.columns)}")
                    return results
                
                progress.update(task1, description="Data loaded successfully")
                
                # Step 2: MITRE TTP Mapping
                task2 = progress.add_task("Mapping vulnerabilities to MITRE ATT&CK...", total=len(df_clean))
                
                vulnerability_mappings = []
                for idx, row in df_clean.iterrows():
                    vuln_text = self._extract_vulnerability_text(row, key_columns)
                    vuln_name = self._extract_vulnerability_name(row, key_columns)
                    
                    if vuln_text:
                        mapping = self.mitre_mapper.map_vulnerability(vuln_text, vuln_name)
                        vulnerability_mappings.append(mapping)
                    
                    progress.advance(task2)
                
                progress.update(task2, description="MITRE TTP mapping completed")
                
                # Step 3: Risk Assessment
                task3 = progress.add_task("Performing risk assessment...", total=len(vulnerability_mappings))
                
                risk_assessments = []
                for mapping in vulnerability_mappings:
                    vuln_data = self._prepare_vulnerability_data(mapping, df_clean, key_columns)
                    asset_context = self._get_asset_context(mapping, df_clean, key_columns)
                    market_context = self._get_market_context(mapping, df_clean, key_columns)
                    
                    risk_assessment = self.risk_calculator.calculate_risk(
                        vuln_data, mapping.ttp_mappings, asset_context, market_context
                    )
                    risk_assessments.append(risk_assessment)
                    
                    progress.advance(task3)
                
                progress.update(task3, description="Risk assessment completed")
                
                # Step 4: Create analysis DataFrame
                task4 = progress.add_task("Creating analysis dataset...", total=None)
                
                analysis_df = self._create_analysis_dataframe(vulnerability_mappings, risk_assessments, df_clean, key_columns)
                
                # Ensure numeric types for risk_score and confidence_score
                for col in ['risk_score', 'confidence_score']:
                    if col in analysis_df.columns:
                        analysis_df[col] = pd.to_numeric(analysis_df[col], errors='coerce')
                # Print dtypes and sample values for diagnostics
                console.print("[bold yellow]Diagnostics: analysis_df column types and sample values[/bold yellow]")
                console.print(str(analysis_df.dtypes))
                for col in ['risk_score', 'confidence_score']:
                    if col in analysis_df.columns:
                        non_numeric = analysis_df[analysis_df[col].isna() | ~analysis_df[col].apply(lambda x: isinstance(x, (int, float)) or pd.isna(x))]
                        if not non_numeric.empty:
                            console.print(f"[red]Non-numeric values found in {col} column before dropping NaNs:[/red]")
                            if isinstance(non_numeric, pd.DataFrame):
                                console.print(str(non_numeric[[col]].head(10)))
                            else:
                                console.print(str(list(non_numeric[[col]])[:10]))
                # Drop rows with NaN in these columns
                analysis_df = analysis_df.dropna(subset=['risk_score', 'confidence_score'])
                if analysis_df.empty:
                    console.print("[red]All rows dropped after ensuring numeric risk_score and confidence_score. Check your input data for non-numeric or missing values in these columns.[/red]")
                    return results
                
                progress.update(task4, description="Analysis dataset created")
                
                # Step 5: Generate visualizations
                task5 = progress.add_task("Generating visualizations...", total=None)
                
                visualizations = self.heatmap_generator.generate_all_visualizations(analysis_df)
                executive_summary = self.heatmap_generator.create_executive_summary_chart(analysis_df)
                
                progress.update(task5, description="Visualizations completed")
                
                # Step 6: Generate reports
                task6 = progress.add_task("Generating reports...", total=None)
                
                reports = self._generate_reports(analysis_df, vulnerability_mappings, risk_assessments, output_dir)
                
                progress.update(task6, description="Reports generated")
            
            # Update results
            results['vulnerabilities_analyzed'] = len(analysis_df)
            results['ttp_mappings'] = vulnerability_mappings
            results['risk_assessments'] = risk_assessments
            results['visualizations'] = visualizations
            results['visualizations']['executive_summary'] = executive_summary
            results['reports'] = reports
            results['summary'] = self._create_summary(analysis_df, vulnerability_mappings, risk_assessments)
            
            # Display results
            self._display_results(results)
            
            console.print(f"\n[bold green]Analysis completed successfully![/bold green]")
            console.print(f"Check the '{output_dir}' directory for detailed results.")
            
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            console.print(f"[red]Error during analysis: {e}[/red]")
        
        return results
    
    def _extract_vulnerability_text(self, row: pd.Series, key_columns: Dict) -> str:
        """Extract vulnerability text from row"""
        vuln_col = key_columns.get('vulnerability') or key_columns.get('description')
        if vuln_col and vuln_col in row:
            return str(row[vuln_col])
        return ""
    
    def _extract_vulnerability_name(self, row: pd.Series, key_columns: Dict) -> str:
        """Extract vulnerability name/ID from row"""
        cve_col = key_columns.get('cve')
        if cve_col and cve_col in row:
            return str(row[cve_col])
        return f"VULN_{row.name}"
    
    def _prepare_vulnerability_data(self, mapping: VulnerabilityMapping, df: pd.DataFrame, key_columns: Dict) -> Dict:
        """Prepare vulnerability data for risk assessment"""
        vuln_data = {
            'id': mapping.vulnerability_id,
            'name': mapping.vulnerability_name,
            'type': self._infer_vulnerability_type(mapping.vulnerability_name),
            'cvss_score': 7.0,  # Default, should be extracted from data
            'cvss_vector': '',  # Should be extracted from data
            'public_exploit_available': False,
            'metasploit_module': False,
            'proof_of_concept': False,
            'actively_exploited': False,
            'patch_available': True,
            'age_days': 365,
            'financial_impact': 'medium',
            'operational_impact': 'medium',
            'reputational_impact': 'medium',
            'regulatory_impact': 'medium'
        }
        
        # Try to extract more data from the original row
        if mapping.vulnerability_id in df.index:
            row = df.loc[mapping.vulnerability_id]
            # Extract additional fields if available
            pass
        
        return vuln_data
    
    def _infer_vulnerability_type(self, vuln_name: str) -> str:
        """Infer vulnerability type from name/description"""
        vuln_name_lower = vuln_name.lower()
        
        if any(word in vuln_name_lower for word in ['sql', 'injection']):
            return 'sql_injection'
        elif any(word in vuln_name_lower for word in ['xss', 'cross-site']):
            return 'xss'
        elif any(word in vuln_name_lower for word in ['rce', 'remote code']):
            return 'rce'
        elif any(word in vuln_name_lower for word in ['privilege', 'escalation']):
            return 'privilege_escalation'
        elif any(word in vuln_name_lower for word in ['auth', 'bypass']):
            return 'authentication_bypass'
        else:
            return 'general'
    
    def _get_asset_context(self, mapping: VulnerabilityMapping, df: pd.DataFrame, key_columns: Dict) -> Dict:
        """Get asset context for risk assessment"""
        return {
            'type': 'general',
            'data_sensitivity': 'medium',
            'business_function': 'general',
            'security_controls': ['waf', 'ids_ips', 'monitoring']
        }
    
    def _get_market_context(self, mapping: VulnerabilityMapping, df: pd.DataFrame, key_columns: Dict) -> Dict:
        """Get market context for risk assessment"""
        return {
            'region': 'global',
            'industry': 'general',
            'regulatory_environment': 'standard'
        }
    
    def _create_analysis_dataframe(self, vulnerability_mappings: List[VulnerabilityMapping], 
                                 risk_assessments: List[RiskAssessment],
                                 original_df: pd.DataFrame, key_columns: Dict) -> pd.DataFrame:
        """Create comprehensive analysis DataFrame"""
        analysis_data = []
        
        for i, (mapping, risk_assessment) in enumerate(zip(vulnerability_mappings, risk_assessments)):
            # Get original row data
            original_row = original_df.iloc[i] if i < len(original_df) else pd.Series()
            
            analysis_row = {
                'vulnerability_id': mapping.vulnerability_id,
                'vulnerability_name': mapping.vulnerability_name,
                'description': mapping.vulnerability_name,  # Use name as description for now
                'severity': self._extract_severity(original_row, key_columns),
                'market': self._extract_market(original_row, key_columns),
                'cve': mapping.vulnerability_id,
                'ttps': [m.technique_id for m in mapping.ttp_mappings],
                'ttp_count': len(mapping.ttp_mappings),
                'attack_chain': mapping.attack_chain,
                'risk_level': mapping.risk_level,
                'risk_score': risk_assessment.overall_risk_score,
                'confidence_score': risk_assessment.confidence_score,
                'business_impact_score': risk_assessment.business_impact_score,
                'technical_risk_score': risk_assessment.technical_risk_score,
                'mitigation_priority': risk_assessment.mitigation_priority,
                'recommendations': '; '.join(risk_assessment.recommendations)
            }
            
            analysis_data.append(analysis_row)
        
        return pd.DataFrame(analysis_data)
    
    def _extract_severity(self, row: pd.Series, key_columns: Dict) -> str:
        """Extract severity from row"""
        severity_col = key_columns.get('severity')
        if severity_col and severity_col in row:
            return str(row[severity_col])
        return 'Medium'
    
    def _extract_market(self, row: pd.Series, key_columns: Dict) -> str:
        """Extract market from row, with improved logic."""
        market_col = key_columns.get('market')
        if market_col and market_col in row and pd.notnull(row[market_col]) and str(row[market_col]).strip():
            return str(row[market_col]).strip()
        # Try to infer from other columns if possible
        for alt_col in ['business_unit', 'asset_group', 'description']:
            if alt_col in row and pd.notnull(row[alt_col]) and str(row[alt_col]).strip():
                return str(row[alt_col]).strip()
        return 'Unknown'
    
    def _generate_reports(self, analysis_df: pd.DataFrame, 
                         vulnerability_mappings: List[VulnerabilityMapping],
                         risk_assessments: List[RiskAssessment],
                         output_dir: str) -> Dict:
        """Generate comprehensive reports"""
        reports = {}
        
        # Export analysis results to CSV
        csv_path = Path(output_dir) / "vulnerability_analysis_results.csv"
        analysis_df.to_csv(csv_path, index=False)
        reports['csv_results'] = str(csv_path)
        
        # Generate executive summary report
        exec_report = self._generate_executive_report(analysis_df, vulnerability_mappings, risk_assessments)
        exec_report_path = Path(output_dir) / "executive_summary_report.txt"
        with open(exec_report_path, 'w') as f:
            f.write(exec_report)
        reports['executive_report'] = str(exec_report_path)
        
        # Generate technical report
        tech_report = self._generate_technical_report(analysis_df, vulnerability_mappings, risk_assessments)
        tech_report_path = Path(output_dir) / "technical_analysis_report.txt"
        with open(tech_report_path, 'w') as f:
            f.write(tech_report)
        reports['technical_report'] = str(tech_report_path)
        
        return reports
    
    def _generate_executive_report(self, analysis_df: pd.DataFrame,
                                 vulnerability_mappings: List[VulnerabilityMapping],
                                 risk_assessments: List[RiskAssessment]) -> str:
        """Generate executive summary report"""
        report = []
        report.append("MITRE ATT&CK VULNERABILITY ANALYSIS - EXECUTIVE SUMMARY")
        report.append("=" * 60)
        report.append(f"Report Date: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Key metrics
        total_vulns = len(analysis_df)
        critical_vulns = len(analysis_df[analysis_df['risk_level'] == 'Critical'])
        high_vulns = len(analysis_df[analysis_df['risk_level'] == 'High'])
        avg_risk_score = analysis_df['risk_score'].mean()
        
        report.append("KEY FINDINGS")
        report.append("-" * 20)
        report.append(f"Total Vulnerabilities Analyzed: {total_vulns}")
        report.append(f"Critical Risk Vulnerabilities: {critical_vulns}")
        report.append(f"High Risk Vulnerabilities: {high_vulns}")
        report.append(f"Average Risk Score: {avg_risk_score:.2f}")
        report.append("")
        
        # Top risks by market
        report.append("TOP RISKS BY MARKET")
        report.append("-" * 20)
        market_risk = analysis_df.groupby('market')['risk_score'].mean().sort_values(ascending=False)
        for market, risk in market_risk.head(5).items():
            report.append(f"{market}: {risk:.2f}")
        report.append("")
        
        # Recommendations
        report.append("EXECUTIVE RECOMMENDATIONS")
        report.append("-" * 20)
        report.append("1. Prioritize remediation of Critical and High-risk vulnerabilities")
        report.append("2. Focus on markets with highest average risk scores")
        report.append("3. Enhance security controls for identified attack patterns")
        report.append("4. Implement continuous monitoring for MITRE ATT&CK techniques")
        report.append("5. Regular threat intelligence updates and analysis")
        
        return '\n'.join(report)
    
    def _generate_technical_report(self, analysis_df: pd.DataFrame,
                                 vulnerability_mappings: List[VulnerabilityMapping],
                                 risk_assessments: List[RiskAssessment]) -> str:
        """Generate technical analysis report"""
        report = []
        report.append("MITRE ATT&CK VULNERABILITY ANALYSIS - TECHNICAL REPORT")
        report.append("=" * 60)
        report.append(f"Report Date: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Detailed analysis
        report.append("DETAILED ANALYSIS")
        report.append("-" * 20)
        
        for i, (_, row) in enumerate(analysis_df.iterrows()):
            report.append(f"Vulnerability {i+1}: {row['vulnerability_name']}")
            report.append(f"  - Risk Level: {row['risk_level']}")
            report.append(f"  - Risk Score: {row['risk_score']:.2f}")
            report.append(f"  - Market: {row['market']}")
            report.append(f"  - TTPs: {', '.join(row['ttps'])}")
            report.append(f"  - Attack Chain: {' -> '.join(row['attack_chain'])}")
            report.append(f"  - Mitigation Priority: {row['mitigation_priority']}")
            report.append("")
        
        return '\n'.join(report)
    
    def _create_summary(self, analysis_df: pd.DataFrame,
                       vulnerability_mappings: List[VulnerabilityMapping],
                       risk_assessments: List[RiskAssessment]) -> Dict:
        """Create analysis summary"""
        return {
            'total_vulnerabilities': len(analysis_df),
            'critical_vulnerabilities': len(analysis_df[analysis_df['risk_level'] == 'Critical']),
            'high_vulnerabilities': len(analysis_df[analysis_df['risk_level'] == 'High']),
            'average_risk_score': analysis_df['risk_score'].mean(),
            'average_confidence': analysis_df['confidence_score'].mean(),
            'total_ttps_mapped': sum(len(mapping.ttp_mappings) for mapping in vulnerability_mappings),
            'unique_ttps': len(set(ttp for mapping in vulnerability_mappings for ttp in mapping.ttp_mappings)),
            'markets_analyzed': analysis_df['market'].nunique()
        }
    
    def _display_results(self, results: Dict):
        """Display analysis results in console"""
        summary = results['summary']
        
        # Create summary table
        table = Table(title="Analysis Summary")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")
        
        table.add_row("Total Vulnerabilities", str(summary['total_vulnerabilities']))
        table.add_row("Critical Risk", str(summary['critical_vulnerabilities']))
        table.add_row("High Risk", str(summary['high_vulnerabilities']))
        table.add_row("Average Risk Score", f"{summary['average_risk_score']:.2f}")
        table.add_row("Average Confidence", f"{summary['average_confidence']:.2f}")
        table.add_row("Total TTPs Mapped", str(summary['total_ttps_mapped']))
        table.add_row("Unique TTPs", str(summary['unique_ttps']))
        table.add_row("Markets Analyzed", str(summary['markets_analyzed']))
        
        console.print(table)
        
        # Display generated files
        console.print("\n[bold]Generated Files:[/bold]")
        for file_type, file_path in results['visualizations'].items():
            console.print(f"  📊 {file_type}: {file_path}")
        
        for report_type, report_path in results['reports'].items():
            console.print(f"  📄 {report_type}: {report_path}")

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK Vulnerability Risk Analysis Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py vulnerabilities.xlsx
  python main.py data.csv --output reports/
  python main.py --input vulns.xlsx --output analysis/
        """
    )
    
    parser.add_argument('input_file', nargs='?', help='Input vulnerability file (Excel/CSV)')
    parser.add_argument('--input', '-i', help='Input vulnerability file (Excel/CSV)')
    parser.add_argument('--output', '-o', default='output', help='Output directory (default: output)')
    parser.add_argument('--config', '-c', default='config/settings.yaml', help='Configuration file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Determine input file
    input_file = args.input_file or args.input
    if not input_file:
        console.print("[red]Error: Input file is required[/red]")
        parser.print_help()
        return 1
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize analyzer
        analyzer = MITREVulnerabilityAnalyzer(args.config)
        
        # Run analysis
        results = analyzer.analyze_vulnerabilities(input_file, args.output)
        
        if results['vulnerabilities_analyzed'] > 0:
            console.print(f"\n[bold green]✅ Analysis completed successfully![/bold green]")
            console.print(f"📊 Analyzed {results['vulnerabilities_analyzed']} vulnerabilities")
            console.print(f"📁 Results saved to: {args.output}/")
            return 0
        else:
            console.print(f"\n[red]❌ No vulnerabilities were analyzed[/red]")
            return 1
            
    except FileNotFoundError:
        console.print(f"[red]Error: Input file '{input_file}' not found[/red]")
        return 1
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.error(f"Application error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())

# Example: simple scatter plot
fig = px.scatter(x=[1, 2, 3], y=[4, 5, 6])
fig.show()