"""
Advanced Heatmap Generator
Multi-dimensional vulnerability analysis visualizations
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import logging
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

class AdvancedHeatmapGenerator:
    """
    Advanced heatmap generator with multiple visualization types
    """
    
    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Set style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
        logger.info("Advanced Heatmap Generator initialized")
    
    def generate_ttp_frequency_heatmap(self, analysis_df: pd.DataFrame, 
                                     save_path: Optional[str] = None) -> str:
        """
        Generate TTP frequency heatmap by market
        """
        if analysis_df.empty:
            logger.warning("No data available for TTP frequency heatmap")
            return ""
        
        # Prepare data
        ttp_market_data = []
        for _, row in analysis_df.iterrows():
            market = row.get('market', 'Unknown')
            ttps = row.get('ttps', [])
            for ttp in ttps:
                ttp_market_data.append({'market': market, 'ttp': ttp})
        
        if not ttp_market_data:
            logger.warning("No TTP data available")
            return ""
        
        ttp_df = pd.DataFrame(ttp_market_data)
        ttp_pivot = ttp_df.groupby(['market', 'ttp']).size().unstack(fill_value=0)
        
        # Create heatmap
        plt.figure(figsize=(16, 10))
        
        # Create custom colormap
        colors = ['#f7fbff', '#deebf7', '#c6dbef', '#9ecae1', '#6baed6', '#3182bd', '#08519c']
        cmap = sns.blend_palette(colors, as_cmap=True)
        
        # Generate heatmap
        sns.heatmap(ttp_pivot, 
                   annot=True, 
                   fmt='d', 
                   cmap=cmap,
                   cbar_kws={'label': 'TTP Frequency', 'shrink': 0.8},
                   linewidths=0.5,
                   square=False)
        
        plt.title('MITRE ATT&CK TTP Frequency by Market\nVulnerability Analysis', 
                 fontsize=16, fontweight='bold', pad=20)
        plt.xlabel('MITRE ATT&CK Techniques', fontsize=12, fontweight='bold')
        plt.ylabel('Market/Region', fontsize=12, fontweight='bold')
        plt.xticks(rotation=45, ha='right')
        plt.yticks(rotation=0)
        
        # Add timestamp
        plt.figtext(0.99, 0.01, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}', 
                   ha='right', va='bottom', fontsize=8, style='italic')
        
        plt.tight_layout()
        
        # Save plot
        if save_path is None:
            save_path = self.output_dir / "ttp_frequency_heatmap.png"
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        
        logger.info(f"TTP frequency heatmap saved to {save_path}")
        return str(save_path)
    
    def generate_risk_score_heatmap(self, analysis_df: pd.DataFrame,
                                  save_path: Optional[str] = None) -> str:
        """
        Generate risk score heatmap by market and severity
        """
        if analysis_df.empty:
            logger.warning("No data available for risk score heatmap")
            return ""
        
        # Prepare data
        risk_pivot = analysis_df.groupby(['market', 'severity'])['risk_score'].mean().unstack(fill_value=0)
        
        if risk_pivot.empty:
            logger.warning("No risk score data available")
            return ""
        
        # Create heatmap
        plt.figure(figsize=(14, 8))
        
        # Create custom colormap for risk scores
        colors = ['#fee5d9', '#fcae91', '#fb6a4a', '#de2d26', '#a50f15']
        cmap = sns.blend_palette(colors, as_cmap=True)
        
        # Generate heatmap
        sns.heatmap(risk_pivot, 
                   annot=True, 
                   fmt='.2f', 
                   cmap=cmap,
                   cbar_kws={'label': 'Average Risk Score', 'shrink': 0.8},
                   linewidths=0.5,
                   square=False)
        
        plt.title('Average Risk Score by Market and Severity\nVulnerability Risk Analysis', 
                 fontsize=16, fontweight='bold', pad=20)
        plt.xlabel('Severity Level', fontsize=12, fontweight='bold')
        plt.ylabel('Market/Region', fontsize=12, fontweight='bold')
        plt.xticks(rotation=0)
        plt.yticks(rotation=0)
        
        # Add timestamp
        plt.figtext(0.99, 0.01, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}', 
                   ha='right', va='bottom', fontsize=8, style='italic')
        
        plt.tight_layout()
        
        # Save plot
        if save_path is None:
            save_path = self.output_dir / "risk_score_heatmap.png"
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        
        logger.info(f"Risk score heatmap saved to {save_path}")
        return str(save_path)
    
    def generate_attack_chain_heatmap(self, analysis_df: pd.DataFrame,
                                    save_path: Optional[str] = None) -> str:
        """
        Generate attack chain heatmap showing tactic progression
        """
        if analysis_df.empty:
            logger.warning("No data available for attack chain heatmap")
            return ""
        
        # Prepare attack chain data
        attack_chain_data = []
        for _, row in analysis_df.iterrows():
            attack_chain = row.get('attack_chain', [])
            if attack_chain:
                for i, tactic in enumerate(attack_chain):
                    attack_chain_data.append({
                        'market': row.get('market', 'Unknown'),
                        'tactic': tactic,
                        'position': i,
                        'count': 1
                    })
        
        if not attack_chain_data:
            logger.warning("No attack chain data available")
            return ""
        
        chain_df = pd.DataFrame(attack_chain_data)
        chain_pivot = chain_df.groupby(['market', 'tactic'])['count'].sum().unstack(fill_value=0)
        
        # Create heatmap
        plt.figure(figsize=(18, 10))
        
        # Create custom colormap
        colors = ['#f7fcf5', '#e5f5e0', '#c7e9c0', '#a1d99b', '#74c476', '#41ab5d', '#238b45']
        cmap = sns.blend_palette(colors, as_cmap=True)
        
        # Generate heatmap
        sns.heatmap(chain_pivot, 
                   annot=True, 
                   fmt='d', 
                   cmap=cmap,
                   cbar_kws={'label': 'Attack Chain Frequency', 'shrink': 0.8},
                   linewidths=0.5,
                   square=False)
        
        plt.title('MITRE ATT&CK Attack Chain Analysis by Market\nTactic Progression Heatmap', 
                 fontsize=16, fontweight='bold', pad=20)
        plt.xlabel('MITRE ATT&CK Tactics', fontsize=12, fontweight='bold')
        plt.ylabel('Market/Region', fontsize=12, fontweight='bold')
        plt.xticks(rotation=45, ha='right')
        plt.yticks(rotation=0)
        
        # Add timestamp
        plt.figtext(0.99, 0.01, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}', 
                   ha='right', va='bottom', fontsize=8, style='italic')
        
        plt.tight_layout()
        
        # Save plot
        if save_path is None:
            save_path = self.output_dir / "attack_chain_heatmap.png"
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        
        logger.info(f"Attack chain heatmap saved to {save_path}")
        return str(save_path)
    
    def generate_confidence_heatmap(self, analysis_df: pd.DataFrame,
                                  save_path: Optional[str] = None) -> str:
        """
        Generate confidence score heatmap
        """
        if analysis_df.empty:
            logger.warning("No data available for confidence heatmap")
            return ""
        
        # Prepare confidence data
        confidence_pivot = analysis_df.groupby(['market', 'severity'])['confidence_score'].mean().unstack(fill_value=0)
        
        if confidence_pivot.empty:
            logger.warning("No confidence data available")
            return ""
        
        # Create heatmap
        plt.figure(figsize=(14, 8))
        
        # Create custom colormap for confidence
        colors = ['#fee5d9', '#fcae91', '#fb6a4a', '#de2d26', '#a50f15']
        cmap = sns.blend_palette(colors, as_cmap=True)
        
        # Generate heatmap
        sns.heatmap(confidence_pivot, 
                   annot=True, 
                   fmt='.3f', 
                   cmap=cmap,
                   cbar_kws={'label': 'Average Confidence Score', 'shrink': 0.8},
                   linewidths=0.5,
                   square=False)
        
        plt.title('Mapping Confidence by Market and Severity\nTTP Mapping Quality Analysis', 
                 fontsize=16, fontweight='bold', pad=20)
        plt.xlabel('Severity Level', fontsize=12, fontweight='bold')
        plt.ylabel('Market/Region', fontsize=12, fontweight='bold')
        plt.xticks(rotation=0)
        plt.yticks(rotation=0)
        
        # Add timestamp
        plt.figtext(0.99, 0.01, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}', 
                   ha='right', va='bottom', fontsize=8, style='italic')
        
        plt.tight_layout()
        
        # Save plot
        if save_path is None:
            save_path = self.output_dir / "confidence_heatmap.png"
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        
        logger.info(f"Confidence heatmap saved to {save_path}")
        return str(save_path)
    
    def generate_interactive_dashboard(self, analysis_df: pd.DataFrame,
                                     save_path: Optional[str] = None) -> str:
        """
        Generate interactive Plotly dashboard
        """
        if analysis_df.empty:
            logger.warning("No data available for interactive dashboard")
            return ""
        
        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Risk Score by Market', 'TTP Distribution', 
                          'Severity Distribution', 'Confidence Analysis'),
            specs=[[{"type": "bar"}, {"type": "pie"}],
                   [{"type": "bar"}, {"type": "scatter"}]]
        )
        
        # 1. Risk Score by Market
        market_risk = analysis_df.groupby('market')['risk_score'].mean().sort_values(ascending=True)
        fig.add_trace(
            go.Bar(x=market_risk.values, y=market_risk.index, orientation='h', 
                  name='Avg Risk Score', marker_color='crimson'),
            row=1, col=1
        )
        
        # 2. TTP Distribution
        all_ttps = []
        for ttps in analysis_df['ttps']:
            all_ttps.extend(ttps)
        
        if all_ttps:
            ttp_counts = pd.Series(all_ttps).value_counts().head(10)
            fig.add_trace(
                go.Pie(labels=ttp_counts.index, values=ttp_counts.values, name='TTP Distribution'),
                row=1, col=2
            )
        
        # 3. Severity Distribution
        severity_counts = analysis_df['severity'].value_counts()
        fig.add_trace(
            go.Bar(x=severity_counts.index, y=severity_counts.values, 
                  name='Severity Count', marker_color='lightblue'),
            row=2, col=1
        )
        
        # 4. Confidence vs Risk Score
        fig.add_trace(
            go.Scatter(x=analysis_df['risk_score'], y=analysis_df['confidence_score'],
                      mode='markers', name='Confidence vs Risk',
                      marker=dict(size=8, color=analysis_df['risk_score'], 
                                colorscale='Viridis', showscale=True)),
            row=2, col=2
        )
        
        # Update layout
        fig.update_layout(
            title_text="MITRE ATT&CK Vulnerability Analysis Dashboard",
            title_x=0.5,
            height=800,
            showlegend=False
        )
        
        # Update axes labels
        fig.update_xaxes(title_text="Average Risk Score", row=1, col=1)
        fig.update_xaxes(title_text="Severity Level", row=2, col=1)
        fig.update_xaxes(title_text="Risk Score", row=2, col=2)
        
        fig.update_yaxes(title_text="Market", row=1, col=1)
        fig.update_yaxes(title_text="Count", row=2, col=1)
        fig.update_yaxes(title_text="Confidence Score", row=2, col=2)
        
        # Save plot
        if save_path is None:
            save_path = self.output_dir / "interactive_dashboard.html"
        
        fig.write_html(str(save_path))
        
        logger.info(f"Interactive dashboard saved to {save_path}")
        return str(save_path)
    
    def generate_market_risk_overview(self, analysis_df: pd.DataFrame,
                                    save_path: Optional[str] = None) -> str:
        """
        Generate market risk overview chart
        """
        if analysis_df.empty:
            logger.warning("No data available for market risk overview")
            return ""
        
        # Prepare market summary data
        market_summary = analysis_df.groupby('market').agg({
            'risk_score': ['mean', 'sum', 'count'],
            'confidence_score': 'mean',
            'ttp_count': 'sum'
        }).round(3)
        
        # Flatten column names
        market_summary.columns = ['Avg_Risk_Score', 'Total_Risk_Score', 'Vulnerability_Count', 
                                'Avg_Confidence', 'Total_TTPs']
        
        # Create figure with subplots
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        
        # 1. Average Risk Score by Market
        market_summary['Avg_Risk_Score'].plot(kind='bar', ax=ax1, color='coral', alpha=0.8)
        ax1.set_title('Average Risk Score by Market', fontweight='bold', fontsize=14)
        ax1.set_xlabel('Market')
        ax1.set_ylabel('Average Risk Score')
        ax1.tick_params(axis='x', rotation=45)
        
        # 2. Vulnerability Count by Market
        market_summary['Vulnerability_Count'].plot(kind='bar', ax=ax2, color='skyblue', alpha=0.8)
        ax2.set_title('Vulnerability Count by Market', fontweight='bold', fontsize=14)
        ax2.set_xlabel('Market')
        ax2.set_ylabel('Number of Vulnerabilities')
        ax2.tick_params(axis='x', rotation=45)
        
        # 3. Total TTPs by Market
        market_summary['Total_TTPs'].plot(kind='bar', ax=ax3, color='lightgreen', alpha=0.8)
        ax3.set_title('Total MITRE TTPs by Market', fontweight='bold', fontsize=14)
        ax3.set_xlabel('Market')
        ax3.set_ylabel('Total TTPs')
        ax3.tick_params(axis='x', rotation=45)
        
        # 4. Confidence vs Risk Score scatter
        ax4.scatter(market_summary['Avg_Risk_Score'], market_summary['Avg_Confidence'], 
                   s=market_summary['Vulnerability_Count']*10, alpha=0.7, c='purple')
        ax4.set_title('Confidence vs Risk Score by Market', fontweight='bold', fontsize=14)
        ax4.set_xlabel('Average Risk Score')
        ax4.set_ylabel('Average Confidence Score')
        
        # Add market labels to scatter plot
        for idx, market in enumerate(market_summary.index):
            ax4.annotate(market, (market_summary['Avg_Risk_Score'].iloc[idx], 
                                market_summary['Avg_Confidence'].iloc[idx]),
                        xytext=(5, 5), textcoords='offset points', fontsize=8)
        
        plt.suptitle('Market Risk Overview - MITRE ATT&CK Analysis', 
                    fontsize=16, fontweight='bold', y=0.98)
        
        # Add timestamp
        fig.text(0.99, 0.01, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}', 
                ha='right', va='bottom', fontsize=8, style='italic')
        
        plt.tight_layout()
        
        # Save plot
        if save_path is None:
            save_path = self.output_dir / "market_risk_overview.png"
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        
        logger.info(f"Market risk overview saved to {save_path}")
        return str(save_path)
    
    def generate_all_visualizations(self, analysis_df: pd.DataFrame) -> Dict[str, str]:
        """
        Generate all visualizations and return file paths
        """
        logger.info("Generating all visualizations...")
        
        results = {}
        
        try:
            # Generate all heatmaps and charts
            results['ttp_frequency'] = self.generate_ttp_frequency_heatmap(analysis_df)
            results['risk_score'] = self.generate_risk_score_heatmap(analysis_df)
            results['attack_chain'] = self.generate_attack_chain_heatmap(analysis_df)
            results['confidence'] = self.generate_confidence_heatmap(analysis_df)
            results['market_overview'] = self.generate_market_risk_overview(analysis_df)
            results['interactive_dashboard'] = self.generate_interactive_dashboard(analysis_df)
            
            logger.info("All visualizations generated successfully")
            
        except Exception as e:
            logger.error(f"Error generating visualizations: {e}")
        
        return results
    
    def create_executive_summary_chart(self, analysis_df: pd.DataFrame,
                                     save_path: Optional[str] = None) -> str:
        """
        Create executive summary chart for CISO presentation
        """
        if analysis_df.empty:
            logger.warning("No data available for executive summary")
            return ""
        
        # Prepare executive summary data
        total_vulns = len(analysis_df)
        critical_vulns = len(analysis_df[analysis_df['risk_level'] == 'Critical'])
        high_vulns = len(analysis_df[analysis_df['risk_level'] == 'High'])
        avg_risk_score = analysis_df['risk_score'].mean()
        avg_confidence = analysis_df['confidence_score'].mean()
        
        # Create executive summary
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        
        # 1. Risk Level Distribution
        risk_levels = analysis_df['risk_level'].value_counts()
        colors = ['#d62728', '#ff7f0e', '#2ca02c', '#1f77b4']
        ax1.pie(risk_levels.values, labels=risk_levels.index, autopct='%1.1f%%', 
               colors=colors[:len(risk_levels)], startangle=90)
        ax1.set_title('Risk Level Distribution', fontweight='bold', fontsize=14)
        
        # 2. Key Metrics
        metrics = ['Total Vulnerabilities', 'Critical Risk', 'High Risk', 'Avg Risk Score']
        values = [total_vulns, critical_vulns, high_vulns, f"{avg_risk_score:.2f}"]
        colors_metrics = ['#2ecc71', '#e74c3c', '#f39c12', '#3498db']
        
        bars = ax2.bar(metrics, values, color=colors_metrics, alpha=0.8)
        ax2.set_title('Key Security Metrics', fontweight='bold', fontsize=14)
        ax2.set_ylabel('Count/Score')
        
        # Add value labels on bars
        for bar, value in zip(bars, values):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                    f'{value}', ha='center', va='bottom', fontweight='bold')
        
        # 3. Top Markets by Risk
        market_risk = analysis_df.groupby('market')['risk_score'].mean().sort_values(ascending=False).head(5)
        market_risk.plot(kind='bar', ax=ax3, color='crimson', alpha=0.8)
        ax3.set_title('Top 5 Markets by Risk Score', fontweight='bold', fontsize=14)
        ax3.set_xlabel('Market')
        ax3.set_ylabel('Average Risk Score')
        ax3.tick_params(axis='x', rotation=45)
        
        # 4. Confidence vs Risk Scatter
        ax4.scatter(analysis_df['risk_score'], analysis_df['confidence_score'], 
                   alpha=0.6, c=analysis_df['risk_score'], cmap='viridis')
        ax4.set_title('Risk vs Confidence Analysis', fontweight='bold', fontsize=14)
        ax4.set_xlabel('Risk Score')
        ax4.set_ylabel('Confidence Score')
        ax4.grid(True, alpha=0.3)
        
        plt.suptitle('Executive Security Summary - MITRE ATT&CK Analysis', 
                    fontsize=18, fontweight='bold', y=0.98)
        
        # Add timestamp
        fig.text(0.99, 0.01, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}', 
                ha='right', va='bottom', fontsize=8, style='italic')
        
        plt.tight_layout()
        
        # Save plot
        if save_path is None:
            save_path = self.output_dir / "executive_summary.png"
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        
        logger.info(f"Executive summary chart saved to {save_path}")
        return str(save_path) 