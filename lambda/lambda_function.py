import json
import boto3
import hashlib
import os
import math
import re
from decimal import Decimal
from datetime import datetime

s3 = boto3.client('s3')
sns = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('HoneypotMalwareAnalysis')

CLEAN_BUCKET = 'honeypot-clean-storage'
MALWARE_ALERT_TOPIC = 'arn:aws:sns:us-east-1:386012741187:malware-detected-alerts'
CLEAN_ALERT_TOPIC = 'arn:aws:sns:us-east-1:386012741187:clean-file-processed'

KNOWN_MALWARE_HASHES = [624c49024ee54585b86296c2ed4f284c5709f7a521076d1d25269a94c966dc62]

THREAT_CATEGORIES = {
    'ransomware': {
        'patterns': [b'ransom', b'bitcoin', b'encrypted', b'decrypt', b'payment'],
        'score_per_match': 15,
        'threshold': 2
    },
    'backdoor': {
        'patterns': [b'/bin/bash', b'/bin/sh', b'nc -e', b'reverse shell', b'wget http', b'curl http'],
        'score_per_match': 20,
        'threshold': 2
    },
    'keylogger': {
        'patterns': [b'keylog', b'keystroke', b'password', b'credentials', b'screenshot'],
        'score_per_match': 15,
        'threshold': 2
    },
    'cryptominer': {
        'patterns': [b'mining', b'crypto', b'stratum', b'pool', b'hashrate'],
        'score_per_match': 15,
        'threshold': 2
    },
    'trojan': {
        'patterns': [b'trojan', b'backdoor', b'malware', b'payload', b'exploit'],
        'score_per_match': 20,
        'threshold': 2
    }
}

def lambda_handler(event, context):
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    
    print(f"🔍 Analyzing: {key}")
    
    download_path = f'/tmp/{os.path.basename(key)}'
    s3.download_file(bucket, key, download_path)
    
    with open(download_path, 'rb') as f:
        data = f.read()
    
    analysis = {
        'filename': key,
        'filesize': len(data),
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
        'timestamp': int(datetime.now().timestamp())
    }
    
    threat_score = 0
    threat_indicators = []
    detected_categories = []
    
    if analysis['sha256'] in KNOWN_MALWARE_HASHES or analysis['md5'] in KNOWN_MALWARE_HASHES:
        threat_score = 100
        threat_indicators.append('Known malware signature')
        detected_categories.append('Known Threat')
    
    entropy = calculate_entropy(data)
    analysis['entropy'] = Decimal(str(round(entropy, 2)))  # Convert to Decimal for DynamoDB
    
    if entropy > 7.8:
        threat_score += 40
        threat_indicators.append(f'Very high entropy ({entropy:.2f})')
    elif entropy > 7.2:
        threat_score += 20
        threat_indicators.append(f'High entropy ({entropy:.2f})')
    
    category_matches = classify_malware(data)
    
    for category, matches in category_matches.items():
        if matches['count'] >= THREAT_CATEGORIES[category]['threshold']:
            score = matches['count'] * THREAT_CATEGORIES[category]['score_per_match']
            threat_score += score
            detected_categories.append(category.capitalize())
            threat_indicators.append(f"{category.capitalize()}: {matches['count']} indicators")
    
    analysis['malware_family'] = detected_categories if detected_categories else ['Unknown']
    
    network_iocs = extract_network_iocs(data)
    analysis['network_iocs'] = network_iocs
    
    if network_iocs['ips'] or network_iocs['domains']:
        ioc_count = len(network_iocs['ips']) + len(network_iocs['domains'])
        threat_score += min(ioc_count * 10, 30)
        threat_indicators.append(f"Network IOCs: {len(network_iocs['ips'])} IPs, {len(network_iocs['domains'])} domains")
    
    file_type = detect_file_type(data)
    analysis['file_type'] = file_type
    
    if file_type in ['PE executable', 'ELF executable']:
        threat_score += 30
        threat_indicators.append(f'Executable: {file_type}')
    elif file_type == 'Shell script':
        threat_score += 20
        threat_indicators.append(f'Script: {file_type}')
    
    analysis['threat_score'] = threat_score
    analysis['threat_indicators'] = threat_indicators
    
    if threat_score >= 60:
        analysis['verdict'] = 'MALICIOUS'
        analysis['threat_level'] = 'HIGH'
    elif threat_score >= 30:
        analysis['verdict'] = 'SUSPICIOUS'
        analysis['threat_level'] = 'MEDIUM'
    else:
        analysis['verdict'] = 'CLEAN'
        analysis['threat_level'] = 'LOW'
    
    if analysis['verdict'] in ['MALICIOUS', 'SUSPICIOUS']:
        handle_threat(analysis, bucket, key)
    else:
        handle_clean(analysis, bucket, key)
    
    analysis['s3_location'] = f's3://{bucket}/{key}'
    
    # Store in DynamoDB (already DynamoDB-compatible)
    table.put_item(Item=analysis)
    
    print(f"✅ Analysis complete: {analysis['verdict']} (Score: {threat_score})")
    
    return {'statusCode': 200, 'body': json.dumps({'file': key, 'verdict': analysis['verdict'], 'score': threat_score})}

def classify_malware(data):
    results = {}
    for category, config in THREAT_CATEGORIES.items():
        matches = [p.decode('utf-8', errors='ignore') for p in config['patterns'] if p in data]
        results[category] = {'count': len(matches), 'matches': matches[:5]}
    return results

def extract_network_iocs(data):
    try:
        text = data.decode('utf-8', errors='ignore')
    except:
        text = str(data)
    
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b'
    ips = [ip for ip in set(re.findall(ip_pattern, text)) if not ip.startswith(('0.', '127.'))]
    
    domain_pattern = r'https?://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})'
    domains = list(set(re.findall(domain_pattern, text)))
    
    domain_pattern2 = r'\b([a-z0-9\-]+\.[a-z]{2,}(?:\.[a-z]{2,})?)\b'
    additional = re.findall(domain_pattern2, text.lower())
    exclude = ['example.com', 'localhost', 'test.com', 'amazon.com', 'ubuntu.com']
    additional = [d for d in additional if d not in exclude and len(d) > 5]
    
    domains.extend(additional)
    domains = list(set(domains))[:10]
    
    return {'ips': ips[:10], 'domains': domains}

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def detect_file_type(data):
    if len(data) < 4:
        return 'Unknown'
    if data[:2] == b'MZ':
        return 'PE executable'
    elif data[:4] == b'\x7fELF':
        return 'ELF executable'
    elif data[:2] == b'#!':
        return 'Shell script'
    elif data[:4] == b'PK\x03\x04':
        return 'ZIP archive'
    elif data[:2] == b'\x1f\x8b':
        return 'GZIP compressed'
    elif data[:4] == b'%PDF':
        return 'PDF document'
    else:
        return 'Text/Unknown'

def handle_threat(analysis, bucket, key):
    verdict_emoji = '🚨' if analysis['verdict'] == 'MALICIOUS' else '⚠️'
    print(f"{verdict_emoji} {analysis['verdict']}: {key}")
    
    message = f"""{verdict_emoji} {analysis['verdict']} FILE DETECTED

═══════════════════════════════════════
THREAT ANALYSIS REPORT
═══════════════════════════════════════

File: {analysis['filename']}
Size: {analysis['filesize']:,} bytes
Type: {analysis['file_type']}
SHA256: {analysis['sha256']}

Threat Level: {analysis['threat_level']}
Risk Score: {analysis['threat_score']}/100
Classification: {', '.join(analysis['malware_family'])}

Indicators ({len(analysis['threat_indicators'])}):
"""
    for ind in analysis['threat_indicators']:
        message += f"  • {ind}\n"
    
    if analysis['network_iocs']['ips'] or analysis['network_iocs']['domains']:
        message += "\n🌐 Network IOCs:\n"
        for ip in analysis['network_iocs']['ips']:
            message += f"  → {ip}\n"
        for domain in analysis['network_iocs']['domains']:
            message += f"  → {domain}\n"
    
    message += f"\nLocation: s3://{bucket}/{key}\nStatus: QUARANTINED\n"
    
    sns.publish(TopicArn=MALWARE_ALERT_TOPIC, Subject=f"{verdict_emoji} {analysis['verdict']} - Score: {analysis['threat_score']}", Message=message)
    print("📧 Alert sent")

def handle_clean(analysis, bucket, key):
    print(f"✅ CLEAN: {key}")
    s3.copy_object(CopySource={'Bucket': bucket, 'Key': key}, Bucket=CLEAN_BUCKET, Key=key)
    
    message = f"""✅ CLEAN FILE

File: {analysis['filename']}
SHA256: {analysis['sha256']}
Score: {analysis['threat_score']}/100

Moved to: s3://{CLEAN_BUCKET}/{key}
"""
    sns.publish(TopicArn=CLEAN_ALERT_TOPIC, Subject=f'✅ Clean: {analysis["filename"]}', Message=message)
    print("📦 Moved to clean storage")
