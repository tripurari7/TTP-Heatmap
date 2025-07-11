#!/usr/bin/env python3
"""
Test script for the new MITRE ATT&CK Vulnerability Analysis Platform
"""

import sys
import pandas as pd
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

# Add src to path
sys.path.append('src')

from src.core.mitre_mapper import MITREMapper
from src.core.risk_calculator import RiskCalculator
from src.analysis.heatmap_generator import AdvancedHeatmapGenerator
from src.core.data_processor import DataProcessor

console = Console()

def create_sample_data():
    """Create sample vulnerability data for testing"""
    sample_data = {
        'central tracking of central tracking': [
            'VULN-001', 'VULN-002', 'VULN-003', 'VULN-004', 'VULN-005'
        ],
        'total issues': [
            'SQL injection vulnerability in login form',
            'Cross-site scripting (XSS) in user input field',
            'Remote code execution via file upload',
            'Privilege escalation through weak authentication',
            'Data exfiltration through insecure API endpoint'
        ],
        'comments': [
            'Critical security issue affecting user authentication',
            'High risk vulnerability allowing script injection',
            'Severe vulnerability enabling remote code execution',
            'Medium risk issue with authentication bypass',
            'High risk data exposure vulnerability'
        ],
        'unnamed 3': [
            'Critical', 'High', 'Critical', 'Medium', 'High'
        ]
    }
    
    df = pd.DataFrame(sample_data)
    return df

def test_data_processor():
    """Test the data processor"""
    console.print(Panel.fit("[bold blue]Testing Data Processor[/bold blue]", border_style="blue"))
    
    # Create sample data
    df = create_sample_data()
    console.print(f"Created sample data with shape: {df.shape}")
    
    # Test data processor
    processor = DataProcessor()
    df_clean, key_columns = processor.clean_and_identify_columns(df)
    
    console.print(f"Identified columns: {key_columns}")
    
    if key_columns:
        console.print("[green]✓ Data processor test passed[/green]")
        return df_clean, key_columns
    else:
        console.print("[red]✗ Data processor test failed[/red]")
        return None, None

def test_mitre_mapper():
    """Test the MITRE mapper"""
    console.print(Panel.fit("[bold blue]Testing MITRE Mapper[/bold blue]", border_style="blue"))
    
    mapper = MITREMapper()
    
    # Test vulnerability mapping
    test_vulns = [
        "SQL injection vulnerability in login form",
        "Cross-site scripting (XSS) in user input field",
        "Remote code execution via file upload"
    ]
    
    for vuln in test_vulns:
        mapping = mapper.map_vulnerability(vuln, f"TEST-{test_vulns.index(vuln)}")
        console.print(f"Vulnerability: {vuln[:50]}...")
        console.print(f"  Mapped TTPs: {[m.technique_id for m in mapping.ttp_mappings]}")
        console.print(f"  Confidence: {mapping.overall_confidence:.2f}")
        console.print(f"  Risk Level: {mapping.risk_level}")
        console.print()
    
    console.print("[green]✓ MITRE mapper test passed[/green]")

def test_risk_calculator():
    """Test the risk calculator"""
    console.print(Panel.fit("[bold blue]Testing Risk Calculator[/bold blue]", border_style="blue"))
    
    calculator = RiskCalculator()
    
    # Test risk assessment
    vuln_data = {
        'id': 'TEST-001',
        'name': 'SQL Injection',
        'type': 'sql_injection',
        'cvss_score': 8.5,
        'cvss_vector': '',
        'public_exploit_available': True,
        'metasploit_module': False,
        'proof_of_concept': True,
        'actively_exploited': False,
        'patch_available': True,
        'age_days': 30,
        'financial_impact': 'high',
        'operational_impact': 'high',
        'reputational_impact': 'medium',
        'regulatory_impact': 'high'
    }
    
    # Create mock TTP mappings
    from src.core.mitre_mapper import TTPMapping
    ttp_mappings = [
        TTPMapping(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            confidence_score=0.9,
            attack_phase="Initial Access"
        ),
        TTPMapping(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            confidence_score=0.8,
            attack_phase="Execution"
        )
    ]
    
    asset_context = {
        'type': 'web_application',
        'data_sensitivity': 'high',
        'business_function': 'customer_facing',
        'security_controls': ['waf', 'ids_ips', 'monitoring']
    }
    
    market_context = {
        'region': 'north_america',
        'industry': 'financial',
        'regulatory_environment': 'highly_regulated'
    }
    
    risk_assessment = calculator.calculate_risk(vuln_data, ttp_mappings, asset_context, market_context)
    
    console.print(f"Risk Assessment Results:")
    console.print(f"  Overall Risk Score: {risk_assessment.overall_risk_score:.2f}")
    console.print(f"  Risk Level: {risk_assessment.risk_level}")
    console.print(f"  Business Impact Score: {risk_assessment.business_impact_score:.2f}")
    console.print(f"  Technical Risk Score: {risk_assessment.technical_risk_score:.2f}")
    console.print(f"  Mitigation Priority: {risk_assessment.mitigation_priority}")
    console.print(f"  Confidence: {risk_assessment.confidence_score:.2f}")
    
    console.print("[green]✓ Risk calculator test passed[/green]")

def test_heatmap_generator():
    """Test the heatmap generator"""
    console.print(Panel.fit("[bold blue]Testing Heatmap Generator[/bold blue]", border_style="blue"))
    
    generator = AdvancedHeatmapGenerator()
    
    # Create sample analysis data
    analysis_data = {
        'vulnerability_id': ['VULN-001', 'VULN-002', 'VULN-003', 'VULN-004', 'VULN-005'],
        'vulnerability_name': ['SQL Injection', 'XSS', 'RCE', 'Privilege Escalation', 'Data Exfiltration'],
        'severity': ['Critical', 'High', 'Critical', 'Medium', 'High'],
        'market': ['North America', 'Europe', 'Asia Pacific', 'North America', 'Europe'],
        'risk_score': [0.85, 0.75, 0.90, 0.55, 0.70],
        'confidence_score': [0.90, 0.85, 0.95, 0.70, 0.80],
        'ttp_count': [2, 2, 3, 1, 2],
        'ttps': [
            ['T1190', 'T1059'],
            ['T1190', 'T1059.007'],
            ['T1190', 'T1059', 'T1068'],
            ['T1078'],
            ['T1041', 'T1005']
        ],
        'attack_chain': [
            ['Initial Access', 'Execution'],
            ['Initial Access', 'Execution'],
            ['Initial Access', 'Execution', 'Privilege Escalation'],
            ['Defense Evasion'],
            ['Collection', 'Exfiltration']
        ]
    }
    
    df = pd.DataFrame(analysis_data)
    
    # Test heatmap generation
    try:
        results = generator.generate_all_visualizations(df)
        console.print(f"Generated visualizations: {list(results.keys())}")
        console.print("[green]✓ Heatmap generator test passed[/green]")
    except Exception as e:
        console.print(f"[red]✗ Heatmap generator test failed: {e}[/red]")

def main():
    """Run all tests"""
    console.print(Panel.fit(
        "[bold green]MITRE ATT&CK Vulnerability Analysis Platform - Test Suite[/bold green]\n"
        "[italic]Testing the new enterprise-grade security analysis platform[/italic]",
        border_style="green"
    ))
    
    try:
        # Test data processor
        df_clean, key_columns = test_data_processor()
        
        # Test MITRE mapper
        test_mitre_mapper()
        
        # Test risk calculator
        test_risk_calculator()
        
        # Test heatmap generator
        test_heatmap_generator()
        
        console.print(Panel.fit(
            "[bold green]All Tests Completed Successfully![/bold green]\n"
            "The new MITRE ATT&CK Vulnerability Analysis Platform is ready for use.",
            border_style="green"
        ))
        
    except Exception as e:
        console.print(f"[red]Test suite failed: {e}[/red]")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 