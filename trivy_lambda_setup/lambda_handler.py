"""
Trivy Scanner Lambda Handler

This Lambda function runs Trivy scans on container images
and returns vulnerability results via API Gateway.
"""

import json
import subprocess
import os
from datetime import datetime


def handler(event, context):
    """
    Lambda handler for Trivy scans
    
    Expected event body:
    {
        "image": "nginx:latest",
        "severity": "CRITICAL,HIGH,MEDIUM,LOW",  # Optional
        "ignore_unfixed": false  # Optional
    }
    """
    try:
        # Parse request body
        if isinstance(event.get('body'), str):
            body = json.loads(event['body'])
        else:
            body = event.get('body', {}) or {}
        
        image = body.get('image', 'nginx:latest')
        severity = body.get('severity', 'CRITICAL,HIGH,MEDIUM,LOW')
        ignore_unfixed = body.get('ignore_unfixed', False)
        
        # Build Trivy command
        cmd = [
            '/usr/local/bin/trivy',
            'image',
            '--format', 'json',
            '--quiet',
            '--severity', severity,
            '--cache-dir', '/tmp/trivy-cache'
        ]
        
        if ignore_unfixed:
            cmd.append('--ignore-unfixed')
        
        cmd.append(image)
        
        # Run Trivy scan
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=280  # Lambda timeout minus buffer
        )
        
        if result.returncode != 0 and not result.stdout:
            return {
                'statusCode': 500,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'error': f'Trivy scan failed: {result.stderr}',
                    'image': image
                })
            }
        
        # Parse Trivy output
        trivy_output = json.loads(result.stdout) if result.stdout else {}
        
        # Transform to standard format
        vulnerabilities = []
        for target in trivy_output.get('Results', []):
            for vuln in target.get('Vulnerabilities', []):
                vulnerabilities.append({
                    'cve_id': vuln.get('VulnerabilityID', 'N/A'),
                    'package': vuln.get('PkgName', 'Unknown'),
                    'installed_version': vuln.get('InstalledVersion', 'Unknown'),
                    'fixed_version': vuln.get('FixedVersion', 'No fix available'),
                    'severity': vuln.get('Severity', 'UNKNOWN'),
                    'cvss_score': extract_cvss_score(vuln),
                    'description': vuln.get('Description', '')[:500],
                    'layer': target.get('Target', 'Unknown'),
                    'references': vuln.get('References', [])[:3]
                })
        
        # Calculate summary
        summary = {
            'total': len(vulnerabilities),
            'critical': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
            'high': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
            'medium': sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM'),
            'low': sum(1 for v in vulnerabilities if v['severity'] == 'LOW')
        }
        
        response = {
            'scanner': 'Trivy (Lambda)',
            'image': image,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': vulnerabilities,
            'summary': summary,
            'live_data': True,
            'trivy_version': get_trivy_version()
        }
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(response)
        }
        
    except subprocess.TimeoutExpired:
        return {
            'statusCode': 504,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': 'Scan timed out. Try a smaller image or increase Lambda timeout.',
                'image': body.get('image', 'unknown')
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': str(e)
            })
        }


def extract_cvss_score(vuln):
    """Extract CVSS score from vulnerability data"""
    cvss = vuln.get('CVSS', {})
    
    # Try NVD first, then others
    for source in ['nvd', 'redhat', 'ghsa']:
        if source in cvss:
            return cvss[source].get('V3Score', cvss[source].get('V2Score', 0))
    
    return 0


def get_trivy_version():
    """Get installed Trivy version"""
    try:
        result = subprocess.run(
            ['/usr/local/bin/trivy', '--version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout.strip().split('\n')[0]
    except:
        return 'Unknown'


# For local testing
if __name__ == '__main__':
    test_event = {
        'body': json.dumps({
            'image': 'nginx:latest'
        })
    }
    result = handler(test_event, None)
    print(json.dumps(json.loads(result['body']), indent=2))
