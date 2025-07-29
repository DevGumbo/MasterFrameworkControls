"""
Report Generator
Generates HTML reports from results
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any


class ReportGenerator:
    """Generates reports from analysis results"""
    
    def generate_html_report(self, results: Dict[str, Any], output_file: str):
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AWS Security Control Analysis Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #333;
        }}
        .summary {{
            background-color: #e8f4f8;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .violation {{
            background-color: #fee;
            padding: 10px;
            margin: 10px 0;
            border-left: 4px solid #f44;
        }}
        .compliant {{
            background-color: #efe;
            padding: 10px;
            margin: 10px 0;
            border-left: 4px solid #4f4;
        }}
        .stats {{
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
        }}
        .stat-box {{
            text-align: center;
            padding: 20px;
            background-color: #f8f8f8;
            border-radius: 5px;
            flex: 1;
            margin: 0 10px;
        }}
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }}
        .stat-label {{
            color: #666;
            margin-top: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f8f8;
            font-weight: bold;
        }}
        .severity-critical {{ color: #d32f2f; font-weight: bold; }}
        .severity-high {{ color: #f57c00; font-weight: bold; }}
        .severity-medium {{ color: #fbc02d; }}
        .severity-low {{ color: #388e3c; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AWS Security Control Analysis Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-value">{results['results']['statistics']['total_controls_checked']}</div>
                    <div class="stat-label">Controls Checked</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{results['results']['statistics']['compliant_controls']}</div>
                    <div class="stat-label">Compliant</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{results['results']['statistics']['controls_with_violations']}</div>
                    <div class="stat-label">With Violations</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{results['results']['statistics']['compliance_percentage']:.1f}%</div>
                    <div class="stat-label">Compliance Rate</div>
                </div>
            </div>
        </div>
        
        <h2>Violations by Service</h2>
"""
        
        # Add violations by service
        for service, service_data in results['results']['by_service'].items():
            if service_data['violations'] > 0:
                html += f"""
        <h3>{service.upper()} - {service_data['violations']} violations</h3>
        <table>
            <tr>
                <th>Control ID</th>
                <th>Control Name</th>
                <th>Severity</th>
                <th>Violations</th>
            </tr>
"""
                
                for detail in service_data['details']:
                    control = detail['control']
                    result = detail['result']
                    violations = result.get('violations', [])
                    
                    if violations:
                        severity_class = f"severity-{control['severity'].lower()}"
                        html += f"""
            <tr>
                <td>{control['control_id']}</td>
                <td>{control['title']}</td>
                <td class="{severity_class}">{control['severity']}</td>
                <td>{len(violations)} violations found</td>
            </tr>
"""
                
                html += "</table>"
        
        html += """
    </div>
</body>
</html>
"""
        
        # Write to file
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            f.write(html)
