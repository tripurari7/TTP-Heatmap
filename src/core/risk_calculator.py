"""
Advanced Risk Assessment Engine
Multi-factor risk calculation with business impact analysis
"""

import json
import math
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import logging
from datetime import datetime, timedelta
import cvss

logger = logging.getLogger(__name__)

@dataclass
class RiskFactors:
    """Risk factors for vulnerability assessment"""
    cvss_score: float = 0.0
    exploitability: float = 0.0
    business_impact: float = 0.0
    threat_landscape: float = 0.0
    asset_criticality: float = 0.0
    control_effectiveness: float = 0.0
    temporal_factors: float = 0.0
    market_specific: float = 0.0

@dataclass
class RiskAssessment:
    """Complete risk assessment result"""
    vulnerability_id: str
    overall_risk_score: float
    risk_level: str
    risk_factors: RiskFactors
    confidence_score: float
    mitigation_priority: str
    business_impact_score: float
    technical_risk_score: float
    recommendations: List[str]
    assessment_date: datetime

class RiskCalculator:
    """
    Advanced multi-factor risk assessment engine
    """
    
    def __init__(self, config_path: str = "config/risk_config.json"):
        self.config_path = Path(config_path)
        self.risk_weights = self._load_risk_weights()
        self.threat_intelligence = self._load_threat_intelligence()
        self.business_impact_matrix = self._load_business_impact_matrix()
        self.control_effectiveness = self._load_control_effectiveness()
        
        logger.info("Risk Calculator initialized successfully")
    
    def _load_risk_weights(self) -> Dict:
        """Load risk calculation weights"""
        config_path = Path("config/risk_weights.json")
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Error loading risk weights: {e}")
        
        # Default risk weights
        return {
            "cvss_score": 0.25,
            "exploitability": 0.20,
            "business_impact": 0.25,
            "threat_landscape": 0.15,
            "asset_criticality": 0.10,
            "control_effectiveness": 0.05
        }
    
    def _load_threat_intelligence(self) -> Dict:
        """Load threat intelligence data"""
        return {
            "active_threats": {
                "sql_injection": 0.85,
                "xss": 0.75,
                "rce": 0.90,
                "privilege_escalation": 0.80,
                "authentication_bypass": 0.70,
                "data_exfiltration": 0.85
            },
            "threat_actors": {
                "apt_groups": ["APT28", "APT29", "APT41"],
                "cybercriminals": ["FIN7", "Lazarus Group"],
                "hacktivists": ["Anonymous", "LulzSec"]
            },
            "exploit_availability": {
                "public_exploits": 0.90,
                "metasploit_modules": 0.85,
                "proof_of_concept": 0.70,
                "theoretical": 0.30
            }
        }
    
    def _load_business_impact_matrix(self) -> Dict:
        """Load business impact assessment matrix"""
        return {
            "financial_impact": {
                "critical": 1.0,
                "high": 0.75,
                "medium": 0.50,
                "low": 0.25,
                "minimal": 0.10
            },
            "operational_impact": {
                "critical": 1.0,
                "high": 0.80,
                "medium": 0.60,
                "low": 0.30,
                "minimal": 0.15
            },
            "reputational_impact": {
                "critical": 1.0,
                "high": 0.85,
                "medium": 0.65,
                "low": 0.40,
                "minimal": 0.20
            },
            "regulatory_impact": {
                "critical": 1.0,
                "high": 0.90,
                "medium": 0.70,
                "low": 0.45,
                "minimal": 0.25
            }
        }
    
    def _load_control_effectiveness(self) -> Dict:
        """Load security control effectiveness data"""
        return {
            "waf": 0.85,
            "ids_ips": 0.80,
            "endpoint_protection": 0.75,
            "network_segmentation": 0.70,
            "access_controls": 0.90,
            "encryption": 0.85,
            "monitoring": 0.80,
            "backup": 0.75
        }
    
    def calculate_risk(self, 
                      vulnerability_data: Dict,
                      ttp_mappings: List,
                      asset_context: Dict = None,
                      market_context: Dict = None) -> RiskAssessment:
        """
        Calculate comprehensive risk assessment for a vulnerability
        """
        # Initialize risk factors
        risk_factors = RiskFactors()
        
        # Calculate CVSS-based risk
        risk_factors.cvss_score = self._calculate_cvss_risk(vulnerability_data)
        
        # Calculate exploitability
        risk_factors.exploitability = self._calculate_exploitability(vulnerability_data, ttp_mappings)
        
        # Calculate business impact
        risk_factors.business_impact = self._calculate_business_impact(vulnerability_data, asset_context)
        
        # Calculate threat landscape
        risk_factors.threat_landscape = self._calculate_threat_landscape(vulnerability_data, ttp_mappings)
        
        # Calculate asset criticality
        risk_factors.asset_criticality = self._calculate_asset_criticality(asset_context)
        
        # Calculate control effectiveness
        risk_factors.control_effectiveness = self._calculate_control_effectiveness(asset_context)
        
        # Calculate temporal factors
        risk_factors.temporal_factors = self._calculate_temporal_factors(vulnerability_data)
        
        # Calculate market-specific factors
        risk_factors.market_specific = self._calculate_market_factors(market_context)
        
        # Calculate overall risk score
        overall_risk_score = self._calculate_overall_risk(risk_factors)
        
        # Determine risk level
        risk_level = self._determine_risk_level(overall_risk_score)
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(vulnerability_data, ttp_mappings)
        
        # Determine mitigation priority
        mitigation_priority = self._determine_mitigation_priority(overall_risk_score, risk_factors)
        
        # Calculate business impact score
        business_impact_score = self._calculate_business_impact_score(risk_factors)
        
        # Calculate technical risk score
        technical_risk_score = self._calculate_technical_risk_score(risk_factors)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(risk_factors, ttp_mappings)
        
        return RiskAssessment(
            vulnerability_id=vulnerability_data.get('id', ''),
            overall_risk_score=overall_risk_score,
            risk_level=risk_level,
            risk_factors=risk_factors,
            confidence_score=confidence_score,
            mitigation_priority=mitigation_priority,
            business_impact_score=business_impact_score,
            technical_risk_score=technical_risk_score,
            recommendations=recommendations,
            assessment_date=datetime.now()
        )
    
    def _calculate_cvss_risk(self, vulnerability_data: Dict) -> float:
        """Calculate CVSS-based risk score"""
        cvss_vector = vulnerability_data.get('cvss_vector', '')
        cvss_score = vulnerability_data.get('cvss_score', 0.0)
        
        if cvss_vector:
            try:
                # Parse CVSS vector and calculate score
                cvss_obj = cvss.CVSS3(cvss_vector)
                return cvss_obj.base_score / 10.0
            except Exception as e:
                logger.warning(f"Error parsing CVSS vector: {e}")
        
        # Fallback to provided score
        return min(cvss_score / 10.0, 1.0)
    
    def _calculate_exploitability(self, vulnerability_data: Dict, ttp_mappings: List) -> float:
        """Calculate exploitability score"""
        exploitability_score = 0.0
        
        # Check for public exploits
        if vulnerability_data.get('public_exploit_available', False):
            exploitability_score += 0.4
        
        # Check for metasploit modules
        if vulnerability_data.get('metasploit_module', False):
            exploitability_score += 0.3
        
        # Check for proof of concept
        if vulnerability_data.get('proof_of_concept', False):
            exploitability_score += 0.2
        
        # Check TTP complexity
        ttp_complexity = self._assess_ttp_complexity(ttp_mappings)
        exploitability_score += ttp_complexity * 0.1
        
        return min(exploitability_score, 1.0)
    
    def _assess_ttp_complexity(self, ttp_mappings: List) -> float:
        """Assess the complexity of mapped TTPs"""
        if not ttp_mappings:
            return 0.5
        
        # Calculate average confidence as complexity indicator
        avg_confidence = sum(mapping.confidence_score for mapping in ttp_mappings) / len(ttp_mappings)
        
        # Higher confidence often indicates simpler/more direct attack paths
        return 1.0 - avg_confidence
    
    def _calculate_business_impact(self, vulnerability_data: Dict, asset_context: Dict) -> float:
        """Calculate business impact score"""
        impact_score = 0.0
        
        # Financial impact
        financial_impact = vulnerability_data.get('financial_impact', 'medium')
        impact_score += self.business_impact_matrix['financial_impact'].get(financial_impact, 0.5) * 0.3
        
        # Operational impact
        operational_impact = vulnerability_data.get('operational_impact', 'medium')
        impact_score += self.business_impact_matrix['operational_impact'].get(operational_impact, 0.6) * 0.3
        
        # Reputational impact
        reputational_impact = vulnerability_data.get('reputational_impact', 'medium')
        impact_score += self.business_impact_matrix['reputational_impact'].get(reputational_impact, 0.65) * 0.2
        
        # Regulatory impact
        regulatory_impact = vulnerability_data.get('regulatory_impact', 'medium')
        impact_score += self.business_impact_matrix['regulatory_impact'].get(regulatory_impact, 0.7) * 0.2
        
        return impact_score
    
    def _calculate_threat_landscape(self, vulnerability_data: Dict, ttp_mappings: List) -> float:
        """Calculate threat landscape score"""
        threat_score = 0.0
        
        # Check for active threats
        vuln_type = vulnerability_data.get('type', '').lower()
        if vuln_type in self.threat_intelligence['active_threats']:
            threat_score += self.threat_intelligence['active_threats'][vuln_type] * 0.4
        
        # Check exploit availability
        exploit_availability = vulnerability_data.get('exploit_availability', 'theoretical')
        if exploit_availability in self.threat_intelligence['exploit_availability']:
            threat_score += self.threat_intelligence['exploit_availability'][exploit_availability] * 0.3
        
        # Check for threat actor targeting
        if vulnerability_data.get('threat_actor_targeting', False):
            threat_score += 0.3
        
        return min(threat_score, 1.0)
    
    def _calculate_asset_criticality(self, asset_context: Dict) -> float:
        """Calculate asset criticality score"""
        if not asset_context:
            return 0.5
        
        criticality_score = 0.0
        
        # Asset type criticality
        asset_type = asset_context.get('type', 'general')
        type_criticality = {
            'critical_infrastructure': 1.0,
            'financial_system': 0.95,
            'healthcare_system': 0.90,
            'customer_data': 0.85,
            'production_system': 0.80,
            'development_system': 0.60,
            'test_system': 0.40,
            'general': 0.50
        }
        criticality_score += type_criticality.get(asset_type, 0.5) * 0.4
        
        # Data sensitivity
        data_sensitivity = asset_context.get('data_sensitivity', 'medium')
        sensitivity_scores = {
            'public': 0.2,
            'internal': 0.5,
            'confidential': 0.8,
            'restricted': 0.9,
            'secret': 1.0
        }
        criticality_score += sensitivity_scores.get(data_sensitivity, 0.5) * 0.3
        
        # Business function criticality
        business_function = asset_context.get('business_function', 'general')
        function_criticality = {
            'core_business': 1.0,
            'customer_facing': 0.9,
            'internal_operations': 0.7,
            'support': 0.5,
            'general': 0.5
        }
        criticality_score += function_criticality.get(business_function, 0.5) * 0.3
        
        return min(criticality_score, 1.0)
    
    def _calculate_control_effectiveness(self, asset_context: Dict) -> float:
        """Calculate security control effectiveness"""
        if not asset_context:
            return 0.5
        
        controls = asset_context.get('security_controls', [])
        if not controls:
            return 0.3
        
        total_effectiveness = 0.0
        for control in controls:
            total_effectiveness += self.control_effectiveness.get(control, 0.5)
        
        avg_effectiveness = total_effectiveness / len(controls)
        
        # Return inverse (higher control effectiveness = lower risk)
        return 1.0 - avg_effectiveness
    
    def _calculate_temporal_factors(self, vulnerability_data: Dict) -> float:
        """Calculate temporal risk factors"""
        temporal_score = 0.0
        
        # Age of vulnerability
        vuln_age_days = vulnerability_data.get('age_days', 365)
        if vuln_age_days < 30:
            temporal_score += 0.3  # New vulnerabilities are higher risk
        elif vuln_age_days < 90:
            temporal_score += 0.2
        elif vuln_age_days < 365:
            temporal_score += 0.1
        
        # Patch availability
        if not vulnerability_data.get('patch_available', True):
            temporal_score += 0.4
        
        # Active exploitation
        if vulnerability_data.get('actively_exploited', False):
            temporal_score += 0.3
        
        return min(temporal_score, 1.0)
    
    def _calculate_market_factors(self, market_context: Dict) -> float:
        """Calculate market-specific risk factors"""
        if not market_context:
            return 0.5
        
        market_score = 0.0
        
        # Regional threat landscape
        region = market_context.get('region', 'global')
        regional_threats = {
            'north_america': 0.7,
            'europe': 0.6,
            'asia_pacific': 0.8,
            'middle_east': 0.9,
            'africa': 0.8,
            'latin_america': 0.7,
            'global': 0.5
        }
        market_score += regional_threats.get(region, 0.5) * 0.4
        
        # Industry-specific threats
        industry = market_context.get('industry', 'general')
        industry_threats = {
            'financial': 0.9,
            'healthcare': 0.8,
            'government': 0.9,
            'technology': 0.7,
            'retail': 0.6,
            'manufacturing': 0.5,
            'general': 0.5
        }
        market_score += industry_threats.get(industry, 0.5) * 0.3
        
        # Regulatory environment
        regulatory_environment = market_context.get('regulatory_environment', 'standard')
        regulatory_scores = {
            'highly_regulated': 0.9,
            'regulated': 0.7,
            'standard': 0.5,
            'minimal': 0.3
        }
        market_score += regulatory_scores.get(regulatory_environment, 0.5) * 0.3
        
        return min(market_score, 1.0)
    
    def _calculate_overall_risk(self, risk_factors: RiskFactors) -> float:
        """Calculate overall risk score using weighted factors"""
        overall_score = (
            risk_factors.cvss_score * self.risk_weights['cvss_score'] +
            risk_factors.exploitability * self.risk_weights['exploitability'] +
            risk_factors.business_impact * self.risk_weights['business_impact'] +
            risk_factors.threat_landscape * self.risk_weights['threat_landscape'] +
            risk_factors.asset_criticality * self.risk_weights['asset_criticality'] +
            risk_factors.control_effectiveness * self.risk_weights['control_effectiveness']
        )
        
        # Apply temporal and market factors as multipliers
        temporal_multiplier = 1.0 + (risk_factors.temporal_factors * 0.2)
        market_multiplier = 1.0 + (risk_factors.market_specific * 0.1)
        
        return min(overall_score * temporal_multiplier * market_multiplier, 1.0)
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score"""
        if risk_score >= 0.8:
            return "Critical"
        elif risk_score >= 0.6:
            return "High"
        elif risk_score >= 0.4:
            return "Medium"
        elif risk_score >= 0.2:
            return "Low"
        else:
            return "Minimal"
    
    def _calculate_confidence_score(self, vulnerability_data: Dict, ttp_mappings: List) -> float:
        """Calculate confidence in the risk assessment"""
        confidence_factors = []
        
        # Data completeness
        required_fields = ['cvss_score', 'type', 'description']
        completeness = sum(1 for field in required_fields if vulnerability_data.get(field)) / len(required_fields)
        confidence_factors.append(completeness)
        
        # TTP mapping confidence
        if ttp_mappings:
            avg_ttp_confidence = sum(mapping.confidence_score for mapping in ttp_mappings) / len(ttp_mappings)
            confidence_factors.append(avg_ttp_confidence)
        else:
            confidence_factors.append(0.3)
        
        # Asset context availability
        asset_context_score = 0.5 if vulnerability_data.get('asset_context') else 0.3
        confidence_factors.append(asset_context_score)
        
        return sum(confidence_factors) / len(confidence_factors)
    
    def _determine_mitigation_priority(self, risk_score: float, risk_factors: RiskFactors) -> str:
        """Determine mitigation priority"""
        if risk_score >= 0.8 or risk_factors.business_impact >= 0.8:
            return "Immediate"
        elif risk_score >= 0.6 or risk_factors.business_impact >= 0.6:
            return "High"
        elif risk_score >= 0.4:
            return "Medium"
        else:
            return "Low"
    
    def _calculate_business_impact_score(self, risk_factors: RiskFactors) -> float:
        """Calculate business impact score"""
        return risk_factors.business_impact
    
    def _calculate_technical_risk_score(self, risk_factors: RiskFactors) -> float:
        """Calculate technical risk score"""
        return (risk_factors.cvss_score + risk_factors.exploitability + risk_factors.threat_landscape) / 3.0
    
    def _generate_recommendations(self, risk_factors: RiskFactors, ttp_mappings: List) -> List[str]:
        """Generate risk mitigation recommendations"""
        recommendations = []
        
        # High CVSS score recommendations
        if risk_factors.cvss_score > 0.7:
            recommendations.append("Apply security patches immediately")
            recommendations.append("Implement additional network segmentation")
        
        # High exploitability recommendations
        if risk_factors.exploitability > 0.7:
            recommendations.append("Deploy intrusion detection/prevention systems")
            recommendations.append("Implement application security controls")
        
        # High business impact recommendations
        if risk_factors.business_impact > 0.7:
            recommendations.append("Prioritize business continuity planning")
            recommendations.append("Implement enhanced monitoring and alerting")
        
        # High threat landscape recommendations
        if risk_factors.threat_landscape > 0.7:
            recommendations.append("Enhance threat intelligence monitoring")
            recommendations.append("Implement advanced threat detection")
        
        # Low control effectiveness recommendations
        if risk_factors.control_effectiveness > 0.7:
            recommendations.append("Strengthen security controls")
            recommendations.append("Implement defense in depth strategy")
        
        # TTP-specific recommendations
        for mapping in ttp_mappings:
            if mapping.technique_id == "T1190":
                recommendations.append("Implement web application firewall")
            elif mapping.technique_id == "T1078":
                recommendations.append("Strengthen access controls and authentication")
            elif mapping.technique_id == "T1059":
                recommendations.append("Implement command execution monitoring")
        
        return list(set(recommendations))  # Remove duplicates
    
    def update_risk_weights(self, new_weights: Dict):
        """Update risk calculation weights"""
        self.risk_weights.update(new_weights)
        logger.info("Risk weights updated")
    
    def export_risk_assessment(self, assessment: RiskAssessment, output_path: str):
        """Export risk assessment to JSON"""
        assessment_data = {
            "vulnerability_id": assessment.vulnerability_id,
            "overall_risk_score": assessment.overall_risk_score,
            "risk_level": assessment.risk_level,
            "risk_factors": {
                "cvss_score": assessment.risk_factors.cvss_score,
                "exploitability": assessment.risk_factors.exploitability,
                "business_impact": assessment.risk_factors.business_impact,
                "threat_landscape": assessment.risk_factors.threat_landscape,
                "asset_criticality": assessment.risk_factors.asset_criticality,
                "control_effectiveness": assessment.risk_factors.control_effectiveness,
                "temporal_factors": assessment.risk_factors.temporal_factors,
                "market_specific": assessment.risk_factors.market_specific
            },
            "confidence_score": assessment.confidence_score,
            "mitigation_priority": assessment.mitigation_priority,
            "business_impact_score": assessment.business_impact_score,
            "technical_risk_score": assessment.technical_risk_score,
            "recommendations": assessment.recommendations,
            "assessment_date": assessment.assessment_date.isoformat()
        }
        
        with open(output_path, 'w') as f:
            json.dump(assessment_data, f, indent=2)
        
        logger.info(f"Risk assessment exported to {output_path}") 