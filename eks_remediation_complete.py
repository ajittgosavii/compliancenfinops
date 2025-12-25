"""
🐳 Complete EKS Container Remediation with Kubernetes API
Full implementation for EKS vulnerability remediation via Kubernetes

Features:
- Kubernetes API integration for container updates
- ECR vulnerability scanning integration
- Rolling update strategy
- NIST control mapping for containers
- Confidence scoring for container updates
"""

import boto3
import base64
import json
from typing import Dict, List, Optional
from datetime import datetime
import subprocess
import tempfile
import os

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    KUBERNETES_AVAILABLE = True
except ImportError:
    KUBERNETES_AVAILABLE = False
    print("Warning: kubernetes-python not installed. Install with: pip install kubernetes")


# Container NIST Control Mappings
CONTAINER_NIST_MAP = {
    "CM-2": {  # Baseline Configuration
        "name": "Baseline Configuration",
        "remediation_type": "image_update",
        "confidence": 0.90,
        "auto_remediate": True
    },
    
    "SI-2": {  # Flaw Remediation
        "name": "Flaw Remediation",
        "remediation_type": "image_update",
        "confidence": 0.88,
        "auto_remediate": True
    },
    
    "SI-3": {  # Malicious Code Protection
        "name": "Malicious Code Protection",
        "remediation_type": "image_scan_and_update",
        "confidence": 0.85,
        "auto_remediate": False  # May need manual review
    }
}


class EKSConnector:
    """AWS EKS connector with Kubernetes API integration"""
    
    def __init__(self, cluster_name: str, region: str = 'us-east-1',
                 aws_access_key: Optional[str] = None,
                 aws_secret_key: Optional[str] = None):
        """
        Initialize EKS connector
        
        Args:
            cluster_name: EKS cluster name
            region: AWS region
            aws_access_key: AWS access key (optional)
            aws_secret_key: AWS secret key (optional)
        """
        if not KUBERNETES_AVAILABLE:
            raise Exception("kubernetes-python library not installed")
        
        self.cluster_name = cluster_name
        self.region = region
        
        # Initialize AWS clients
        aws_credentials = {'region_name': region}
        if aws_access_key and aws_secret_key:
            aws_credentials['aws_access_key_id'] = aws_access_key
            aws_credentials['aws_secret_access_key'] = aws_secret_key
        
        self.eks_client = boto3.client('eks', **aws_credentials)
        self.ecr_client = boto3.client('ecr', **aws_credentials)
        self.inspector_client = boto3.client('inspector2', **aws_credentials)
        
        # Initialize Kubernetes client
        self._init_kubernetes_client()
    
    def _init_kubernetes_client(self):
        """Initialize Kubernetes client with EKS credentials"""
        try:
            # Get EKS cluster info
            cluster_info = self.eks_client.describe_cluster(name=self.cluster_name)
            cluster = cluster_info['cluster']
            
            # Get cluster certificate
            ca_cert = base64.b64decode(cluster['certificateAuthority']['data'])
            
            # Get authentication token
            token_response = subprocess.check_output([
                'aws', 'eks', 'get-token',
                '--cluster-name', self.cluster_name,
                '--region', self.region
            ])
            token_data = json.loads(token_response)
            token = token_data['status']['token']
            
            # Write certificate to temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.crt') as cert_file:
                cert_file.write(ca_cert)
                cert_file_path = cert_file.name
            
            # Configure Kubernetes client
            configuration = client.Configuration()
            configuration.host = cluster['endpoint']
            configuration.api_key['authorization'] = token
            configuration.api_key_prefix['authorization'] = 'Bearer'
            configuration.ssl_ca_cert = cert_file_path
            
            # Create API clients
            self.api_client = client.ApiClient(configuration)
            self.core_v1 = client.CoreV1Api(self.api_client)
            self.apps_v1 = client.AppsV1Api(self.api_client)
            
            # Clean up temp certificate file
            os.unlink(cert_file_path)
            
        except Exception as e:
            raise Exception(f"Failed to initialize Kubernetes client: {str(e)}")
    
    def list_clusters(self) -> List[Dict]:
        """List all EKS clusters"""
        try:
            response = self.eks_client.list_clusters()
            clusters = []
            
            for cluster_name in response.get('clusters', []):
                cluster_info = self.eks_client.describe_cluster(name=cluster_name)
                cluster = cluster_info['cluster']
                
                clusters.append({
                    'name': cluster['name'],
                    'status': cluster['status'],
                    'version': cluster['version'],
                    'endpoint': cluster['endpoint'],
                    'created': cluster['createdAt'],
                    'platform_version': cluster['platformVersion']
                })
            
            return clusters
            
        except Exception as e:
            raise Exception(f"Failed to list EKS clusters: {str(e)}")
    
    def list_deployments(self, namespace: str = 'default') -> List[Dict]:
        """List all deployments in namespace"""
        try:
            deployments = self.apps_v1.list_namespaced_deployment(namespace)
            
            result = []
            for dep in deployments.items:
                containers = []
                for container in dep.spec.template.spec.containers:
                    containers.append({
                        'name': container.name,
                        'image': container.image,
                        'image_pull_policy': container.image_pull_policy
                    })
                
                result.append({
                    'name': dep.metadata.name,
                    'namespace': dep.metadata.namespace,
                    'replicas': dep.spec.replicas,
                    'ready_replicas': dep.status.ready_replicas or 0,
                    'containers': containers,
                    'created': dep.metadata.creation_timestamp
                })
            
            return result
            
        except ApiException as e:
            raise Exception(f"Failed to list deployments: {str(e)}")
    
    def list_pods(self, namespace: str = 'default') -> List[Dict]:
        """List all pods in namespace"""
        try:
            pods = self.core_v1.list_namespaced_pod(namespace)
            
            result = []
            for pod in pods.items:
                containers = []
                for container in pod.spec.containers:
                    # Get container status
                    container_status = next(
                        (s for s in pod.status.container_statuses or [] 
                         if s.name == container.name),
                        None
                    )
                    
                    containers.append({
                        'name': container.name,
                        'image': container.image,
                        'ready': container_status.ready if container_status else False,
                        'restart_count': container_status.restart_count if container_status else 0
                    })
                
                result.append({
                    'name': pod.metadata.name,
                    'namespace': pod.metadata.namespace,
                    'status': pod.status.phase,
                    'node': pod.spec.node_name,
                    'containers': containers,
                    'created': pod.metadata.creation_timestamp
                })
            
            return result
            
        except ApiException as e:
            raise Exception(f"Failed to list pods: {str(e)}")
    
    def get_ecr_vulnerabilities(self, repository_name: str, 
                               image_tag: str = 'latest') -> List[Dict]:
        """Get ECR vulnerability scan results"""
        try:
            # Get image scan findings
            response = self.ecr_client.describe_image_scan_findings(
                repositoryName=repository_name,
                imageId={'imageTag': image_tag}
            )
            
            findings = response['imageScanFindings']['findings']
            
            vulnerabilities = []
            for finding in findings:
                vulnerabilities.append({
                    'name': finding.get('name', 'Unknown'),
                    'severity': finding.get('severity', 'MEDIUM'),
                    'description': finding.get('description', ''),
                    'uri': finding.get('uri', ''),
                    'attributes': finding.get('attributes', [])
                })
            
            return vulnerabilities
            
        except Exception as e:
            raise Exception(f"Failed to get ECR vulnerabilities: {str(e)}")
    
    def get_inspector_container_findings(self, cluster_name: Optional[str] = None) -> List[Dict]:
        """Get Inspector v2 findings for containers"""
        try:
            filter_criteria = {
                'resourceType': [{'comparison': 'EQUALS', 'value': 'AWS_ECR_CONTAINER_IMAGE'}],
                'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}]
            }
            
            if cluster_name:
                filter_criteria['resourceTags'] = [{
                    'comparison': 'EQUALS',
                    'key': 'cluster',
                    'value': cluster_name
                }]
            
            response = self.inspector_client.list_findings(
                filterCriteria=filter_criteria,
                maxResults=100
            )
            
            findings = []
            for finding in response.get('findings', []):
                findings.append({
                    'id': finding.get('findingArn', '').split('/')[-1],
                    'title': finding.get('title', 'Unknown'),
                    'severity': finding.get('severity', 'MEDIUM'),
                    'description': finding.get('description', ''),
                    'packageName': finding.get('packageVulnerabilityDetails', {}).get('vulnerablePackages', [{}])[0].get('name', 'Unknown'),
                    'installedVersion': finding.get('packageVulnerabilityDetails', {}).get('vulnerablePackages', [{}])[0].get('version', 'Unknown'),
                    'fixedInVersion': finding.get('packageVulnerabilityDetails', {}).get('vulnerablePackages', [{}])[0].get('fixedInVersion', 'Unknown'),
                    'imageUri': finding.get('resources', [{}])[0].get('id', 'Unknown'),
                    'cvss_score': finding.get('packageVulnerabilityDetails', {}).get('cvss', [{}])[0].get('baseScore', 0.0)
                })
            
            return findings
            
        except Exception as e:
            raise Exception(f"Failed to get Inspector findings: {str(e)}")


class EKSRemediationEngine:
    """EKS remediation engine with Kubernetes rolling updates"""
    
    def __init__(self, connector: EKSConnector):
        self.connector = connector
        self.nist_map = CONTAINER_NIST_MAP
    
    def calculate_confidence_score(self, vulnerability: Dict,
                                   deployment_info: Dict) -> float:
        """Calculate confidence score for container update"""
        base_confidence = 0.80
        
        # Severity factor
        severity = vulnerability.get('severity', 'MEDIUM')
        if severity == 'CRITICAL':
            base_confidence += 0.08
        elif severity == 'HIGH':
            base_confidence += 0.05
        
        # Image source factor
        image = deployment_info.get('current_image', '')
        if any(registry in image for registry in ['ecr.amazonaws.com', 'docker.io/library']):
            base_confidence += 0.07  # Trusted registries
        
        # Replica count factor (more replicas = safer rolling update)
        replicas = deployment_info.get('replicas', 1)
        if replicas >= 3:
            base_confidence += 0.05  # High availability
        elif replicas == 1:
            base_confidence -= 0.08  # Single point of failure
        
        return min(base_confidence, 0.93)
    
    def map_cve_to_nist(self, cve_data: Dict) -> List[str]:
        """Map CVE to applicable NIST controls"""
        title = cve_data.get('title', '').lower()
        
        applicable_controls = []
        
        if 'malware' in title or 'backdoor' in title:
            applicable_controls.append('SI-3')
        elif 'configuration' in title or 'misconfiguration' in title:
            applicable_controls.append('CM-2')
        else:
            applicable_controls.append('SI-2')  # Default to flaw remediation
        
        return applicable_controls
    
    def update_deployment_image(self, namespace: str, deployment_name: str,
                               container_name: str, new_image: str,
                               wait_for_rollout: bool = True) -> Dict:
        """
        Update container image in deployment (triggers rolling update)
        
        Args:
            namespace: Kubernetes namespace
            deployment_name: Deployment name
            container_name: Container name within deployment
            new_image: New container image
            wait_for_rollout: Wait for rollout to complete
        
        Returns:
            Dict with update status
        """
        try:
            # Get current deployment
            deployment = self.connector.apps_v1.read_namespaced_deployment(
                name=deployment_name,
                namespace=namespace
            )
            
            # Find and update container image
            container_found = False
            for container in deployment.spec.template.spec.containers:
                if container.name == container_name:
                    old_image = container.image
                    container.image = new_image
                    container_found = True
                    break
            
            if not container_found:
                return {
                    'success': False,
                    'error': f'Container {container_name} not found in deployment',
                    'timestamp': datetime.now().isoformat()
                }
            
            # Patch deployment
            self.connector.apps_v1.patch_namespaced_deployment(
                name=deployment_name,
                namespace=namespace,
                body=deployment
            )
            
            result = {
                'success': True,
                'deployment': deployment_name,
                'namespace': namespace,
                'container': container_name,
                'old_image': old_image,
                'new_image': new_image,
                'rollout_status': 'In Progress',
                'timestamp': datetime.now().isoformat()
            }
            
            # Wait for rollout if requested
            if wait_for_rollout:
                rollout_status = self._wait_for_rollout(namespace, deployment_name)
                result['rollout_status'] = rollout_status
            
            return result
            
        except ApiException as e:
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _wait_for_rollout(self, namespace: str, deployment_name: str,
                         timeout: int = 300) -> str:
        """Wait for deployment rollout to complete"""
        import time
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                deployment = self.connector.apps_v1.read_namespaced_deployment(
                    name=deployment_name,
                    namespace=namespace
                )
                
                # Check if rollout is complete
                desired = deployment.spec.replicas
                updated = deployment.status.updated_replicas or 0
                ready = deployment.status.ready_replicas or 0
                
                if updated == desired and ready == desired:
                    return 'Complete'
                
                time.sleep(5)
                
            except ApiException:
                return 'Unknown'
        
        return 'Timeout'
    
    def generate_remediation_plan(self, vulnerability: Dict,
                                 deployment_info: Dict) -> Dict:
        """Generate comprehensive remediation plan for container vulnerability"""
        
        nist_controls = self.map_cve_to_nist(vulnerability)
        
        # Extract image information
        current_image = deployment_info.get('current_image', '')
        
        # Determine new image (patched version)
        fixed_version = vulnerability.get('fixedInVersion', '')
        if fixed_version and current_image:
            # Replace version tag with fixed version
            image_parts = current_image.rsplit(':', 1)
            if len(image_parts) == 2:
                new_image = f"{image_parts[0]}:{fixed_version}"
            else:
                new_image = f"{current_image}:{fixed_version}"
        else:
            new_image = current_image + ':latest'
        
        remediation_plan = {
            'vulnerability': vulnerability,
            'deployment_info': deployment_info,
            'nist_controls': nist_controls,
            'current_image': current_image,
            'new_image': new_image,
            'remediation_type': 'rolling_update',
            'strategy': {
                'type': 'RollingUpdate',
                'max_surge': 1,
                'max_unavailable': 0
            },
            'estimated_duration': '5-10 minutes',
            'downtime': 'Zero (rolling update)'
        }
        
        # Calculate confidence
        confidence = self.calculate_confidence_score(vulnerability, deployment_info)
        remediation_plan['confidence_score'] = confidence
        remediation_plan['auto_remediate_recommended'] = confidence >= 0.85
        
        return remediation_plan
    
    def execute_remediation(self, remediation_plan: Dict) -> Dict:
        """Execute container remediation (rolling update)"""
        
        try:
            deployment_info = remediation_plan['deployment_info']
            
            result = self.update_deployment_image(
                namespace=deployment_info.get('namespace', 'default'),
                deployment_name=deployment_info['deployment_name'],
                container_name=deployment_info['container_name'],
                new_image=remediation_plan['new_image'],
                wait_for_rollout=True
            )
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }


# Example usage
if __name__ == "__main__":
    # Initialize connector
    connector = EKSConnector(
        cluster_name='my-eks-cluster',
        region='us-east-1'
    )
    
    # List clusters
    clusters = connector.list_clusters()
    print(f"Found {len(clusters)} EKS clusters")
    
    # List deployments
    deployments = connector.list_deployments(namespace='default')
    print(f"Found {len(deployments)} deployments")
    
    # Initialize remediation engine
    engine = EKSRemediationEngine(connector)
    
    # Test vulnerability
    test_vuln = {
        'id': 'CVE-2024-9999',
        'title': 'Container Image Vulnerability',
        'severity': 'HIGH',
        'packageName': 'nginx',
        'installedVersion': '1.23',
        'fixedInVersion': '1.25'
    }
    
    # Test deployment info
    deployment_info = {
        'deployment_name': 'web-app',
        'namespace': 'production',
        'container_name': 'nginx',
        'current_image': 'nginx:1.23',
        'replicas': 3
    }
    
    # Generate remediation plan
    plan = engine.generate_remediation_plan(test_vuln, deployment_info)
    
    print(f"\nNIST Controls: {plan['nist_controls']}")
    print(f"Confidence Score: {plan['confidence_score']:.2%}")
    print(f"Auto-Remediate: {plan['auto_remediate_recommended']}")
    print(f"New Image: {plan['new_image']}")
    print(f"Strategy: {plan['strategy']}")
    print(f"Downtime: {plan['downtime']}")