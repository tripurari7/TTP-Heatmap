"""
Data Processor Module
Advanced data ingestion and cleaning for vulnerability analysis
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import logging
import re
from rich.console import Console

logger = logging.getLogger(__name__)
console = Console()

class DataProcessor:
    """
    Advanced data processor for vulnerability analysis
    """
    
    def __init__(self):
        self.supported_formats = ['.xlsx', '.xls', '.csv']
        self.column_patterns = self._initialize_column_patterns()
        
    def _initialize_column_patterns(self) -> Dict:
        """Initialize column identification patterns"""
        return {
            'cve': {
                'keywords': ['cve', 'id', 'tracking', 'reference'],
                'patterns': [r'CVE-\d{4}-\d+', r'\b[A-Z]{2,}-\d+\b'],
                'priority': 1
            },
            'vulnerability': {
                'keywords': ['vuln', 'issue', 'problem', 'finding', 'weakness'],
                'patterns': [],
                'priority': 2
            },
            'description': {
                'keywords': ['desc', 'detail', 'summary', 'comment', 'note', 'explanation'],
                'patterns': [],
                'priority': 3
            },
            'severity': {
                'keywords': ['sever', 'priority', 'risk', 'level', 'critical', 'high', 'medium', 'low'],
                'patterns': [],
                'priority': 4
            },
            'market': {
                'keywords': ['market', 'region', 'business', 'area', 'location', 'country'],
                'patterns': [],
                'priority': 5
            }
        }
    
    def load_data(self, file_path: str) -> Optional[pd.DataFrame]:
        """
        Load data from various file formats
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            console.print(f"[red]Error: File not found - {file_path}[/red]")
            return None
        
        if file_path.suffix.lower() not in self.supported_formats:
            console.print(f"[red]Error: Unsupported file format - {file_path.suffix}[/red]")
            console.print(f"Supported formats: {', '.join(self.supported_formats)}")
            return None
        
        try:
            if file_path.suffix.lower() in ['.xlsx', '.xls']:
                df = pd.read_excel(file_path, sheet_name=0)
            elif file_path.suffix.lower() == '.csv':
                df = pd.read_csv(file_path)
            else:
                console.print(f"[red]Error: Unsupported file format[/red]")
                return None
            
            console.print(f"[green]✓ Successfully loaded {file_path}[/green]")
            console.print(f"   Shape: {df.shape}")
            console.print(f"   Columns: {list(df.columns)}")
            
            return df
            
        except Exception as e:
            console.print(f"[red]Error loading file: {e}[/red]")
            logger.error(f"Error loading file {file_path}: {e}")
            return None
    
    def clean_and_identify_columns(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict]:
        """
        Clean data and identify key columns
        """
        if df is None or df.empty:
            return df, {}
        
        # Remove completely empty rows and columns
        df = df.dropna(how='all').dropna(axis=1, how='all')
        
        # Clean column names
        df.columns = self._clean_column_names(df.columns)
        
        # Identify key columns
        key_columns = self._identify_columns(df)
        
        # If no columns identified, try content-based identification
        if not key_columns:
            key_columns = self._content_based_identification(df)
        
        # If still no columns, use fallback strategy
        if not key_columns:
            key_columns = self._fallback_identification(df)
        
        console.print(f"[blue]Identified columns: {key_columns}[/blue]")
        
        return df, key_columns
    
    def _clean_column_names(self, columns: pd.Index) -> pd.Index:
        """Clean column names"""
        cleaned_columns = []
        
        for col in columns:
            # Convert to string and clean
            col_str = str(col).strip()
            
            # Remove trailing colons and special characters
            col_str = re.sub(r':+$', '', col_str)
            col_str = re.sub(r'[^\w\s\-\.]', ' ', col_str)
            
            # Remove extra whitespace
            col_str = re.sub(r'\s+', ' ', col_str).strip()
            
            # Convert to lowercase
            col_str = col_str.lower()
            
            cleaned_columns.append(col_str)
        
        return pd.Index(cleaned_columns)
    
    def _identify_columns(self, df: pd.DataFrame) -> Dict:
        """Identify columns using pattern matching"""
        key_columns = {}
        
        for col in df.columns:
            col_lower = col.lower()
            best_match = None
            best_score = 0
            
            for col_type, patterns in self.column_patterns.items():
                score = self._calculate_column_score(col_lower, patterns)
                
                if score > best_score and score > 0.3:  # Threshold for matching
                    best_score = score
                    best_match = col_type
            
            if best_match and best_match not in key_columns:
                key_columns[best_match] = col
        
        return key_columns
    
    def _calculate_column_score(self, column_name: str, patterns: Dict) -> float:
        """Calculate how well a column matches a pattern"""
        score = 0.0
        
        # Check keywords
        for keyword in patterns['keywords']:
            if keyword in column_name:
                score += 0.4
        
        # Check regex patterns
        for pattern in patterns['patterns']:
            if re.search(pattern, column_name, re.IGNORECASE):
                score += 0.6
        
        # Bonus for exact matches
        if any(keyword == column_name for keyword in patterns['keywords']):
            score += 0.2
        
        return min(score, 1.0)
    
    def _content_based_identification(self, df: pd.DataFrame) -> Dict:
        """Identify columns based on content analysis"""
        console.print("[yellow]Attempting content-based column identification...[/yellow]")
        
        key_columns = {}
        
        for col in df.columns:
            # Sample non-null values
            sample_values = df[col].dropna().head(20).astype(str)
            if len(sample_values) == 0:
                continue
            
            sample_text = ' '.join(sample_values).lower()
            
            # Check for CVE patterns
            if re.search(r'CVE-\d{4}-\d+', sample_text):
                key_columns['cve'] = col
                continue
            
            # Check for severity indicators
            severity_indicators = ['critical', 'high', 'medium', 'low', 'info']
            if any(indicator in sample_text for indicator in severity_indicators):
                key_columns['severity'] = col
                continue
            
            # Check for vulnerability descriptions (longer text)
            if len(sample_text) > 100:
                key_columns['description'] = col
                continue
            
            # Check for market/region indicators
            market_indicators = ['market', 'region', 'country', 'area', 'location']
            if any(indicator in sample_text for indicator in market_indicators):
                key_columns['market'] = col
                continue
        
        return key_columns
    
    def _fallback_identification(self, df: pd.DataFrame) -> Dict:
        """Fallback column identification strategy"""
        console.print("[yellow]Using fallback column identification...[/yellow]")
        
        key_columns = {}
        
        # Use first non-empty column as description
        for col in df.columns:
            if not df[col].isna().all():
                key_columns['description'] = col
                break
        
        # Try to identify other columns by position or name similarity
        for col in df.columns:
            col_lower = col.lower()
            
            # Look for ID-like columns
            if any(word in col_lower for word in ['id', 'tracking', 'reference']):
                key_columns['cve'] = col
            
            # Look for severity-like columns
            elif any(word in col_lower for word in ['sever', 'priority', 'risk']):
                key_columns['severity'] = col
            
            # Look for market-like columns
            elif any(word in col_lower for word in ['market', 'region', 'area']):
                key_columns['market'] = col
        
        return key_columns
    
    def validate_data(self, df: pd.DataFrame, key_columns: Dict) -> Dict:
        """Validate data quality and completeness"""
        validation_results = {
            'total_rows': len(df),
            'non_empty_rows': len(df.dropna(how='all')),
            'missing_columns': [],
            'data_quality_issues': [],
            'recommendations': []
        }
        
        # Check for required columns
        required_columns = ['description', 'severity']
        for col_type in required_columns:
            if col_type not in key_columns:
                validation_results['missing_columns'].append(col_type)
        
        # Check data quality
        for col_type, col_name in key_columns.items():
            if col_name in df.columns:
                # Check for empty values
                empty_count = df[col_name].isna().sum()
                empty_percentage = (empty_count / len(df)) * 100
                
                if empty_percentage > 50:
                    validation_results['data_quality_issues'].append(
                        f"Column '{col_name}' has {empty_percentage:.1f}% empty values"
                    )
        
        # Generate recommendations
        if validation_results['missing_columns']:
            validation_results['recommendations'].append(
                f"Add columns for: {', '.join(validation_results['missing_columns'])}"
            )
        
        if validation_results['data_quality_issues']:
            validation_results['recommendations'].append(
                "Review and clean data quality issues"
            )
        
        return validation_results
    
    def preprocess_data(self, df: pd.DataFrame, key_columns: Dict) -> pd.DataFrame:
        """Preprocess data for analysis"""
        df_processed = df.copy()
        
        # Fill missing values
        for col_type, col_name in key_columns.items():
            if col_name in df_processed.columns:
                if col_type == 'severity':
                    df_processed[col_name] = df_processed[col_name].fillna('Medium')
                elif col_type == 'market':
                    df_processed[col_name] = df_processed[col_name].fillna('Unknown')
                else:
                    df_processed[col_name] = df_processed[col_name].fillna('')
        
        # Standardize severity values
        severity_col = key_columns.get('severity')
        if severity_col and severity_col in df_processed.columns:
            df_processed[severity_col] = df_processed[severity_col].apply(self._standardize_severity)
        
        # Clean text fields
        desc_col = key_columns.get('description')
        if desc_col and desc_col in df_processed.columns:
            df_processed[desc_col] = df_processed[desc_col].astype(str).apply(self._clean_text)
        
        return df_processed
    
    def _standardize_severity(self, severity: str) -> str:
        """Standardize severity values"""
        if pd.isna(severity):
            return 'Medium'
        
        severity_str = str(severity).lower().strip()
        
        severity_mapping = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'moderate': 'Medium',
            'low': 'Low',
            'info': 'Info',
            'information': 'Info'
        }
        
        return severity_mapping.get(severity_str, 'Medium')
    
    def _clean_text(self, text: str) -> str:
        """Clean text fields"""
        if pd.isna(text):
            return ""
        
        # Convert to string and clean
        text_str = str(text).strip()
        
        # Remove extra whitespace
        text_str = re.sub(r'\s+', ' ', text_str)
        
        return text_str
    
    def export_processed_data(self, df: pd.DataFrame, key_columns: Dict, output_path: str):
        """Export processed data with column mapping"""
        # Create metadata
        metadata = {
            'column_mapping': key_columns,
            'processing_date': pd.Timestamp.now().isoformat(),
            'total_rows': len(df),
            'columns_identified': len(key_columns)
        }
        
        # Export data
        df.to_csv(f"{output_path}_processed.csv", index=False)
        
        # Export metadata
        import json
        with open(f"{output_path}_metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        console.print(f"[green]✓ Processed data exported to {output_path}_processed.csv[/green]")
        console.print(f"[green]✓ Metadata exported to {output_path}_metadata.json[/green]") 