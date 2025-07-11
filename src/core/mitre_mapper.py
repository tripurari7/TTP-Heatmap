"""
MITRE ATT&CK Mapping Engine
Advanced vulnerability to TTP mapping with confidence scoring
"""

import json
import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from pathlib import Path
import logging
from textblob import TextBlob
import spacy
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class TTPMapping:
    """Represents a MITRE TTP mapping with confidence score"""
    technique_id: str
    technique_name: str
    sub_technique_id: Optional[str] = None
    sub_technique_name: Optional[str] = None
    confidence_score: float = 0.0
    mapping_reason: str = ""
    attack_phase: str = ""
    impact_level: str = ""

@dataclass
class VulnerabilityMapping:
    """Complete vulnerability to TTP mapping"""
    vulnerability_id: str
    vulnerability_name: str
    ttp_mappings: List[TTPMapping]
    overall_confidence: float = 0.0
    attack_chain: List[str] = field(default_factory=list)
    risk_level: str = ""

class MITREMapper:
    """
    Advanced MITRE ATT&CK mapping engine with AI-powered analysis
    """
    
    def __init__(self, config_path: str = "config/mitre_config.json"):
        self.config_path = Path(config_path)
        self.nlp = spacy.load("en_core_web_sm")
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        
        # Load MITRE ATT&CK data
        self.techniques = self._load_mitre_techniques()
        self.tactics = self._load_mitre_tactics()
        
        # Load custom mappings
        self.custom_mappings = self._load_custom_mappings()
        
        # Initialize TF-IDF vectors for techniques
        self.technique_vectors = self._initialize_technique_vectors()
        
        logger.info("MITRE Mapper initialized successfully")
    
    def _load_mitre_techniques(self) -> Dict:
        """Load MITRE ATT&CK techniques from local cache or API"""
        try:
            # Try to load from local cache first
            cache_path = Path("data/mitre_techniques.json")
            if cache_path.exists():
                with open(cache_path, 'r') as f:
                    return json.load(f)
            
            # Fallback to embedded data
            return self._get_embedded_techniques()
            
        except Exception as e:
            logger.error(f"Error loading MITRE techniques: {e}")
            return self._get_embedded_techniques()
    
    def _get_embedded_techniques(self) -> Dict:
        """Embedded MITRE ATT&CK techniques for offline use"""
        return {
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.",
                "sub_techniques": {
                    "T1190.001": "Exploit Public-Facing Application - Exploitation for Client Execution",
                    "T1190.002": "Exploit Public-Facing Application - Exploitation for Privilege Escalation"
                }
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                "sub_techniques": {
                    "T1059.001": "Command and Scripting Interpreter - PowerShell",
                    "T1059.002": "Command and Scripting Interpreter - AppleScript",
                    "T1059.003": "Command and Scripting Interpreter - Windows Command Shell",
                    "T1059.004": "Command and Scripting Interpreter - Unix Shell",
                    "T1059.005": "Command and Scripting Interpreter - Visual Basic",
                    "T1059.006": "Command and Scripting Interpreter - Python",
                    "T1059.007": "Command and Scripting Interpreter - JavaScript"
                }
            },
            "T1068": {
                "name": "Exploitation for Privilege Escalation",
                "tactic": "Privilege Escalation",
                "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.",
                "sub_techniques": {}
            },
            "T1078": {
                "name": "Valid Accounts",
                "tactic": "Defense Evasion",
                "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
                "sub_techniques": {
                    "T1078.001": "Valid Accounts - Default Accounts",
                    "T1078.002": "Valid Accounts - Domain Accounts",
                    "T1078.003": "Valid Accounts - Local Accounts",
                    "T1078.004": "Valid Accounts - Cloud Accounts"
                }
            },
            "T1083": {
                "name": "File and Directory Discovery",
                "tactic": "Discovery",
                "description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.",
                "sub_techniques": {}
            },
            "T1005": {
                "name": "Data from Local System",
                "tactic": "Collection",
                "description": "Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files of interest and sensitive data prior to Exfiltration.",
                "sub_techniques": {}
            },
            "T1499": {
                "name": "Endpoint Denial of Service",
                "tactic": "Impact",
                "description": "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users.",
                "sub_techniques": {}
            },
            "T1566": {
                "name": "Phishing",
                "tactic": "Initial Access",
                "description": "Adversaries may send phishing messages to gain access to victim systems.",
                "sub_techniques": {
                    "T1566.001": "Phishing - Spearphishing Attachment",
                    "T1566.002": "Phishing - Spearphishing Link",
                    "T1566.003": "Phishing - Spearphishing via Service"
                }
            },
            "T1105": {
                "name": "Ingress Tool Transfer",
                "tactic": "Command and Control",
                "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.",
                "sub_techniques": {}
            },
            "T1539": {
                "name": "Steal Web Session Cookie",
                "tactic": "Credential Access",
                "description": "Adversaries may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without proper credentials.",
                "sub_techniques": {}
            },
            "T1552": {
                "name": "Unsecured Credentials",
                "tactic": "Credential Access",
                "description": "Adversaries may search compromised systems to find and obtain insecurely stored credentials.",
                "sub_techniques": {
                    "T1552.001": "Unsecured Credentials - Credentials In Files",
                    "T1552.002": "Unsecured Credentials - Credentials in Registry",
                    "T1552.003": "Unsecured Credentials - Bash History",
                    "T1552.004": "Unsecured Credentials - Private Keys",
                    "T1552.005": "Unsecured Credentials - Cloud Instance Metadata API",
                    "T1552.006": "Unsecured Credentials - Group Policy Preferences"
                }
            },
            "T1040": {
                "name": "Network Sniffing",
                "tactic": "Collection",
                "description": "Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network.",
                "sub_techniques": {}
            },
            "T1110": {
                "name": "Brute Force",
                "tactic": "Credential Access",
                "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
                "sub_techniques": {
                    "T1110.001": "Brute Force - Password Guessing",
                    "T1110.002": "Brute Force - Password Cracking",
                    "T1110.003": "Brute Force - Password Spraying",
                    "T1110.004": "Brute Force - Credential Stuffing"
                }
            },
            "T1557": {
                "name": "Adversary-in-the-Middle",
                "tactic": "Collection",
                "description": "Adversaries may attempt to position themselves between network devices to collect and/or modify data in transit between them.",
                "sub_techniques": {
                    "T1557.001": "Adversary-in-the-Middle - LLMNR/NBT-NS Poisoning and SMB Relay",
                    "T1557.002": "Adversary-in-the-Middle - ARP Cache Poisoning",
                    "T1557.003": "Adversary-in-the-Middle - DHCP Spoofing"
                }
            },
            "T1486": {
                "name": "Data Encrypted for Impact",
                "tactic": "Impact",
                "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.",
                "sub_techniques": {}
            },
            "T1505": {
                "name": "Server Software Component",
                "tactic": "Persistence",
                "description": "Adversaries may abuse legitimate software deployment and management tools to deploy malicious code to systems.",
                "sub_techniques": {
                    "T1505.001": "Server Software Component - SQL Stored Procedures",
                    "T1505.002": "Server Software Component - Transport Agent",
                    "T1505.003": "Server Software Component - Web Shell",
                    "T1505.004": "Server Software Component - IIS Components",
                    "T1505.005": "Server Software Component - Terminal Services DLL"
                }
            },
            "T1056": {
                "name": "Input Capture",
                "tactic": "Collection",
                "description": "Adversaries may use methods of capturing user input to obtain credentials or collect information.",
                "sub_techniques": {
                    "T1056.001": "Input Capture - Keylogging",
                    "T1056.002": "Input Capture - GUI Input Capture",
                    "T1056.003": "Input Capture - Web Portal Capture",
                    "T1056.004": "Input Capture - Credential API Hooking",
                    "T1056.005": "Input Capture - Clipboard Capture"
                }
            },
            "T1014": {
                "name": "Rootkit",
                "tactic": "Defense Evasion",
                "description": "Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components.",
                "sub_techniques": {}
            },
            "T1055": {
                "name": "Process Injection",
                "tactic": "Defense Evasion",
                "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
                "sub_techniques": {
                    "T1055.001": "Process Injection - Dynamic-link Library Injection",
                    "T1055.002": "Process Injection - Portable Executable Injection",
                    "T1055.003": "Process Injection - Thread Execution Hijacking",
                    "T1055.004": "Process Injection - Asynchronous Procedure Call",
                    "T1055.008": "Process Injection - Ptrace System Calls",
                    "T1055.009": "Process Injection - Proc Memory",
                    "T1055.011": "Process Injection - Extra Window Memory Injection",
                    "T1055.012": "Process Injection - Process Hollowing",
                    "T1055.013": "Process Injection - Process Doppelgänging",
                    "T1055.014": "Process Injection - VDSO Hijacking",
                    "T1055.015": "Process Injection - ListPlanting"
                }
            },
            "T1021": {
                "name": "Remote Services",
                "tactic": "Lateral Movement",
                "description": "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC.",
                "sub_techniques": {
                    "T1021.001": "Remote Services - Remote Desktop Protocol",
                    "T1021.002": "Remote Services - SMB/Windows Admin Shares",
                    "T1021.003": "Remote Services - Distributed Component Object Model",
                    "T1021.004": "Remote Services - SSH",
                    "T1021.005": "Remote Services - VNC",
                    "T1021.006": "Remote Services - Windows Remote Management"
                }
            },
            "T1041": {
                "name": "Exfiltration Over C2 Channel",
                "tactic": "Exfiltration",
                "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
                "sub_techniques": {}
            }
        }
    
    def _load_mitre_tactics(self) -> Dict:
        """Load MITRE ATT&CK tactics"""
        return {
            "Initial Access": ["T1190", "T1566"],
            "Execution": ["T1059"],
            "Persistence": ["T1505"],
            "Privilege Escalation": ["T1068"],
            "Defense Evasion": ["T1078", "T1014", "T1055"],
            "Credential Access": ["T1539", "T1552", "T1110"],
            "Discovery": ["T1083"],
            "Lateral Movement": ["T1021"],
            "Collection": ["T1005", "T1040", "T1056", "T1557"],
            "Command and Control": ["T1105"],
            "Exfiltration": ["T1041"],
            "Impact": ["T1499", "T1486"]
        }
    
    def _load_custom_mappings(self) -> Dict:
        """Load custom vulnerability to TTP mappings"""
        custom_path = Path("data/custom_ttp_mappings.json")
        if custom_path.exists():
            try:
                with open(custom_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Error loading custom mappings: {e}")
        
        # Default custom mappings
        return {
            "sql injection": {
                "primary_ttps": ["T1190", "T1059"],
                "confidence": 0.95,
                "attack_chain": ["Initial Access", "Execution"],
                "keywords": ["sql", "injection", "database", "query"]
            },
            "xss": {
                "primary_ttps": ["T1190", "T1059.007"],
                "confidence": 0.90,
                "attack_chain": ["Initial Access", "Execution"],
                "keywords": ["xss", "cross-site", "scripting", "javascript"]
            },
            "rce": {
                "primary_ttps": ["T1190", "T1059"],
                "confidence": 0.95,
                "attack_chain": ["Initial Access", "Execution"],
                "keywords": ["rce", "remote code", "execution", "command"]
            },
            "privilege escalation": {
                "primary_ttps": ["T1068", "T1134"],
                "confidence": 0.85,
                "attack_chain": ["Privilege Escalation"],
                "keywords": ["privilege", "escalation", "elevation", "admin"]
            },
            "authentication bypass": {
                "primary_ttps": ["T1078", "T1190"],
                "confidence": 0.80,
                "attack_chain": ["Defense Evasion", "Initial Access"],
                "keywords": ["auth", "bypass", "authentication", "login"]
            },
            "data exfiltration": {
                "primary_ttps": ["T1041", "T1005"],
                "confidence": 0.85,
                "attack_chain": ["Collection", "Exfiltration"],
                "keywords": ["exfiltration", "data", "theft", "extract"]
            }
        }
    
    def _initialize_technique_vectors(self) -> Dict:
        """Initialize TF-IDF vectors for technique descriptions"""
        technique_texts = []
        technique_ids = []
        
        for tech_id, tech_data in self.techniques.items():
            text = f"{tech_data['name']} {tech_data['description']}"
            if tech_data.get('sub_techniques'):
                for sub_id, sub_name in tech_data['sub_techniques'].items():
                    text += f" {sub_name}"
            
            technique_texts.append(text)
            technique_ids.append(tech_id)
        
        # Fit vectorizer and transform
        vectors = self.vectorizer.fit_transform(technique_texts)
        
        return {
            'vectors': vectors,
            'ids': technique_ids,
            'vectorizer': self.vectorizer
        }
    
    def map_vulnerability(self, vulnerability_text: str, vulnerability_name: str = "") -> VulnerabilityMapping:
        """
        Map a vulnerability to MITRE ATT&CK techniques with confidence scoring
        """
        if not vulnerability_text:
            return VulnerabilityMapping(
                vulnerability_id="",
                vulnerability_name=vulnerability_name,
                ttp_mappings=[],
                overall_confidence=0.0
            )
        
        # Normalize text
        normalized_text = self._normalize_text(vulnerability_text)
        
        # Get mappings using multiple approaches
        keyword_mappings = self._keyword_based_mapping(normalized_text)
        semantic_mappings = self._semantic_based_mapping(normalized_text)
        custom_mappings = self._custom_mapping_lookup(normalized_text)
        
        # Combine and rank mappings
        all_mappings = self._combine_mappings(keyword_mappings, semantic_mappings, custom_mappings)
        
        # Calculate overall confidence
        overall_confidence = self._calculate_overall_confidence(all_mappings)
        
        # Determine attack chain
        attack_chain = self._determine_attack_chain(all_mappings)
        
        # Determine risk level
        risk_level = self._determine_risk_level(all_mappings, overall_confidence)
        
        return VulnerabilityMapping(
            vulnerability_id=vulnerability_name,
            vulnerability_name=vulnerability_name,
            ttp_mappings=all_mappings,
            overall_confidence=overall_confidence,
            attack_chain=attack_chain,
            risk_level=risk_level
        )
    
    def _normalize_text(self, text: str) -> str:
        """Normalize vulnerability text for analysis"""
        # Convert to lowercase
        text = text.lower()
        
        # Remove special characters but keep important ones
        text = re.sub(r'[^\w\s\-\.]', ' ', text)
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def _keyword_based_mapping(self, text: str) -> List[TTPMapping]:
        """Map based on keyword matching"""
        mappings = []
        
        for tech_id, tech_data in self.techniques.items():
            confidence = 0.0
            reasons = []
            
            # Check technique name
            if tech_data['name'].lower() in text:
                confidence += 0.3
                reasons.append(f"Technique name match: {tech_data['name']}")
            
            # Check description keywords
            desc_words = set(tech_data['description'].lower().split())
            text_words = set(text.split())
            common_words = desc_words.intersection(text_words)
            
            if len(common_words) > 0:
                confidence += min(0.4, len(common_words) * 0.1)
                reasons.append(f"Description keyword matches: {', '.join(common_words)}")
            
            # Check sub-techniques
            for sub_id, sub_name in tech_data.get('sub_techniques', {}).items():
                if sub_name.lower() in text:
                    confidence += 0.2
                    reasons.append(f"Sub-technique match: {sub_name}")
                    
                    mappings.append(TTPMapping(
                        technique_id=tech_id,
                        technique_name=tech_data['name'],
                        sub_technique_id=sub_id,
                        sub_technique_name=sub_name,
                        confidence_score=confidence,
                        mapping_reason="; ".join(reasons),
                        attack_phase=tech_data['tactic']
                    ))
            
            # Add main technique if confidence is high enough
            if confidence >= 0.2:
                mappings.append(TTPMapping(
                    technique_id=tech_id,
                    technique_name=tech_data['name'],
                    confidence_score=confidence,
                    mapping_reason="; ".join(reasons),
                    attack_phase=tech_data['tactic']
                ))
        
        return mappings
    
    def _semantic_based_mapping(self, text: str) -> List[TTPMapping]:
        """Map based on semantic similarity using TF-IDF"""
        mappings = []
        
        # Transform input text
        text_vector = self.technique_vectors['vectorizer'].transform([text])
        
        # Calculate similarities
        similarities = cosine_similarity(text_vector, self.technique_vectors['vectors']).flatten()
        
        # Get top matches
        top_indices = similarities.argsort()[-5:][::-1]  # Top 5 matches
        
        for idx in top_indices:
            if similarities[idx] > 0.1:  # Threshold for semantic similarity
                tech_id = self.technique_vectors['ids'][idx]
                tech_data = self.techniques[tech_id]
                
                mappings.append(TTPMapping(
                    technique_id=tech_id,
                    technique_name=tech_data['name'],
                    confidence_score=similarities[idx],
                    mapping_reason=f"Semantic similarity: {similarities[idx]:.3f}",
                    attack_phase=tech_data['tactic']
                ))
        
        return mappings
    
    def _custom_mapping_lookup(self, text: str) -> List[TTPMapping]:
        """Look up custom mappings for known vulnerability types"""
        mappings = []
        
        for vuln_type, mapping_data in self.custom_mappings.items():
            if vuln_type in text:
                for ttp_id in mapping_data['primary_ttps']:
                    if ttp_id in self.techniques:
                        tech_data = self.techniques[ttp_id]
                        
                        mappings.append(TTPMapping(
                            technique_id=ttp_id,
                            technique_name=tech_data['name'],
                            confidence_score=mapping_data['confidence'],
                            mapping_reason=f"Custom mapping for {vuln_type}",
                            attack_phase=tech_data['tactic']
                        ))
        
        return mappings
    
    def _combine_mappings(self, keyword_mappings: List[TTPMapping], 
                         semantic_mappings: List[TTPMapping], 
                         custom_mappings: List[TTPMapping]) -> List[TTPMapping]:
        """Combine and deduplicate mappings"""
        all_mappings = {}
        
        # Process keyword mappings
        for mapping in keyword_mappings:
            key = mapping.technique_id
            if key not in all_mappings or mapping.confidence_score > all_mappings[key].confidence_score:
                all_mappings[key] = mapping
        
        # Process semantic mappings
        for mapping in semantic_mappings:
            key = mapping.technique_id
            if key not in all_mappings or mapping.confidence_score > all_mappings[key].confidence_score:
                all_mappings[key] = mapping
        
        # Process custom mappings (highest priority)
        for mapping in custom_mappings:
            key = mapping.technique_id
            if key not in all_mappings or mapping.confidence_score > all_mappings[key].confidence_score:
                all_mappings[key] = mapping
        
        # Sort by confidence score
        return sorted(all_mappings.values(), key=lambda x: x.confidence_score, reverse=True)
    
    def _calculate_overall_confidence(self, mappings: List[TTPMapping]) -> float:
        """Calculate overall confidence score for the vulnerability mapping"""
        if not mappings:
            return 0.0
        
        # Weighted average based on confidence scores
        total_weight = sum(mapping.confidence_score for mapping in mappings)
        return total_weight / len(mappings)
    
    def _determine_attack_chain(self, mappings: List[TTPMapping]) -> List[str]:
        """Determine the attack chain based on mapped techniques"""
        phases = set()
        for mapping in mappings:
            if mapping.attack_phase:
                phases.add(mapping.attack_phase)
        
        # Order phases according to typical attack flow
        phase_order = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact"
        ]
        
        ordered_phases = [phase for phase in phase_order if phase in phases]
        return ordered_phases
    
    def _determine_risk_level(self, mappings: List[TTPMapping], confidence: float) -> str:
        """Determine risk level based on mappings and confidence"""
        if not mappings:
            return "Unknown"
        
        # Count high-impact techniques
        high_impact_techniques = ["T1190", "T1068", "T1078", "T1552", "T1041", "T1486"]
        high_impact_count = sum(1 for mapping in mappings if mapping.technique_id in high_impact_techniques)
        
        # Determine risk level
        if high_impact_count >= 3 and confidence >= 0.8:
            return "Critical"
        elif high_impact_count >= 2 and confidence >= 0.6:
            return "High"
        elif high_impact_count >= 1 and confidence >= 0.4:
            return "Medium"
        else:
            return "Low"
    
    def get_technique_details(self, technique_id: str) -> Optional[Dict]:
        """Get detailed information about a specific technique"""
        return self.techniques.get(technique_id)
    
    def get_tactic_techniques(self, tactic: str) -> List[str]:
        """Get all techniques for a specific tactic"""
        return self.tactics.get(tactic, [])
    
    def export_mappings(self, output_path: str):
        """Export current mappings to JSON file"""
        export_data = {
            "techniques": self.techniques,
            "tactics": self.tactics,
            "custom_mappings": self.custom_mappings
        }
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Mappings exported to {output_path}") 