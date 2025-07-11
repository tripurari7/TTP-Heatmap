import sys
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import plotly.express as px
from typing import List, Dict, Any


def load_data(file_path: str) -> pd.DataFrame:
    """Load Excel or CSV file into a DataFrame."""
    ext = os.path.splitext(file_path)[-1].lower()
    if ext in ['.xlsx', '.xls']:
        df = pd.read_excel(file_path)
    elif ext == '.csv':
        df = pd.read_csv(file_path)
    else:
        raise ValueError(f"Unsupported file extension: {ext}")
    return df


def analyze_data_quality(df: pd.DataFrame) -> Dict[str, Any]:
    """Analyze data quality issues and return a report."""
    report = {}
    report['shape'] = df.shape
    report['columns'] = list(df.columns)
    report['null_counts'] = df.isnull().sum().to_dict()
    report['blank_counts'] = (df.applymap(lambda x: isinstance(x, str) and x.strip() == '').sum()).to_dict()
    report['dtypes'] = df.dtypes.apply(str).to_dict()
    report['n_duplicates'] = df.duplicated().sum()
    # Outlier detection for numeric columns
    outliers = {}
    for col in df.select_dtypes(include=[np.number]).columns:
        q1 = df[col].quantile(0.25)
        q3 = df[col].quantile(0.75)
        iqr = q3 - q1
        lower = q1 - 1.5 * iqr
        upper = q3 + 1.5 * iqr
        outliers[col] = int(((df[col] < lower) | (df[col] > upper)).sum())
    report['outliers'] = outliers
    return report


def supplement_data(df: pd.DataFrame) -> pd.DataFrame:
    """Supplement missing/incomplete data to make the dataset analysis-ready."""
    # Fill blanks with NaN
    df = df.applymap(lambda x: np.nan if isinstance(x, str) and x.strip() == '' else x)
    # Convert numeric columns
    for col in df.columns:
        if df[col].dtype == object:
            try:
                df[col] = pd.to_numeric(df[col], errors='ignore')
            except Exception:
                pass
    # Fill numeric NaNs with median, categorical with mode
    for col in df.columns:
        if pd.api.types.is_numeric_dtype(df[col]):
            df[col] = pd.to_numeric(df[col], errors='coerce')
            if df[col].isnull().any():
                df[col] = df[col].fillna(df[col].median())
        else:
            if df[col].isnull().any():
                mode = df[col].mode()
                if not mode.empty:
                    df[col] = df[col].fillna(mode[0])
                else:
                    df[col] = df[col].fillna('Unknown')
    # Remove duplicates
    df = df.drop_duplicates()
    return df


def generate_charts(df: pd.DataFrame, output_dir: str = 'output'):
    """Generate example charts/outputs from the cleaned data."""
    os.makedirs(output_dir, exist_ok=True)
    # Example: Histogram of RiskScore if present
    if 'RiskScore' in df.columns:
        plt.figure(figsize=(8, 5))
        df['RiskScore'].hist(bins=20)
        plt.title('Risk Score Distribution')
        plt.xlabel('Risk Score')
        plt.ylabel('Count')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'risk_score_histogram.png'))
        plt.close()
        # Interactive plotly chart
        fig = px.histogram(df, x='RiskScore', title='Risk Score Distribution (Interactive)')
        fig.write_html(os.path.join(output_dir, 'risk_score_histogram.html'))
    # Example: Pie chart of Market if present
    if 'Market' in df.columns:
        plt.figure(figsize=(6, 6))
        df['Market'].value_counts().plot.pie(autopct='%1.1f%%')
        plt.title('Market Distribution')
        plt.ylabel('')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'market_pie_chart.png'))
        plt.close()
        # Interactive plotly chart
        fig = px.pie(df, names='Market', title='Market Distribution (Interactive)')
        fig.write_html(os.path.join(output_dir, 'market_pie_chart.html'))


def print_data_quality_report(report: Dict[str, Any]):
    print("\n=== DATA QUALITY REPORT ===")
    print(f"Shape: {report['shape']}")
    print(f"Columns: {report['columns']}")
    print(f"Null value counts: {report['null_counts']}")
    print(f"Blank value counts: {report['blank_counts']}")
    print(f"Data types: {report['dtypes']}")
    print(f"Duplicate rows: {report['n_duplicates']}")
    print(f"Outliers (numeric columns): {report['outliers']}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python data_quality_analyzer.py <input_file.xlsx|csv>")
        sys.exit(1)
    input_file = sys.argv[1]
    output_dir = 'output'
    print(f"Loading data from: {input_file}")
    df = load_data(input_file)
    report = analyze_data_quality(df)
    print_data_quality_report(report)
    print("\nSupplementing data to make it analysis-ready...")
    df_clean = supplement_data(df)
    print("\nData after supplementation:")
    print(df_clean.head())
    print("\nGenerating charts/outputs...")
    generate_charts(df_clean, output_dir)
    print(f"\nCharts and outputs saved to: {output_dir}/")

if __name__ == "__main__":
    main() 