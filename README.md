# Automated Malware Detection & Analysis System

> Cloud-native threat detection using AWS serverless architecture

![AWS](https://img.shields.io/badge/AWS-Cloud-orange)
![Python](https://img.shields.io/badge/Python-3.11-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## 🎯 Overview

Automated malware detection system that captures, analyzes, and classifies threats in real-time using AWS services. Built for security operations, incident response, and threat intelligence gathering.

## ✨ Features

- **Multi-Layer Detection**: 5 complementary analysis techniques
- **Automated Workflow**: Capture → Analyze → Alert in <10 seconds
- **Threat Intelligence**: IOC extraction and malware family classification
- **Real-Time Alerting**: Email notifications with detailed threat reports
- **Serverless Architecture**: Auto-scaling, cost-effective (~$25/month)
- **Threat Scoring**: 0-100 risk assessment with automatic verdict

## 🏗️ Architecture
```
┌─────────────┐
│  Attacker   │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│  SSH Honeypot   │  EC2 with weak credentials
│     (EC2)       │  Captures malicious files
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ S3 Quarantine   │  Isolated storage
│     Bucket      │  Triggers Lambda
└────────┬────────┘
         │
         ▼
┌──────────────────────────┐
│   Lambda Analyzer        │  5-Layer Detection:
│  (Detection Engine)      │  • Hash matching
│                          │  • Entropy analysis
│                          │  • Pattern classification
│                          │  • IOC extraction
│                          │  • File type detection
└─────┬───────────┬────────┘
      │           │
      ▼           ▼
┌──────────┐  ┌──────────┐
│MALICIOUS │  │  CLEAN   │
│(Score≥60)│  │(Score<30)│
└─────┬────┘  └────┬─────┘
      │            │
      ▼            ▼
┌──────────┐  ┌──────────┐
│SNS Alert │  │S3 Clean  │
│  Email   │  │ Storage  │
└─────┬────┘  └──────────┘
      │
      ▼
┌─────────────────┐
│    DynamoDB     │  Threat Intelligence
│ Analysis Results│  • Hashes, IOCs
│   + Dashboard   │  • Verdicts, Scores
└─────────────────┘
```

## 🔍 Detection Methodology

### Five-Layer Analysis

| Layer | Technique | Purpose | Score Impact |
|-------|-----------|---------|--------------|
| 1 | Hash Matching | Identify known malware | +100 (instant) |
| 2 | Entropy Analysis | Detect packing/obfuscation | +20-40 |
| 3 | Pattern Classification | Identify malware families | +15-20 each |
| 4 | IOC Extraction | Find C2 infrastructure | +10 per IOC |
| 5 | File Type Detection | Flag executables/scripts | +20-30 |

### Threat Scoring

- **60-100**: 🚨 MALICIOUS (High threat, immediate alert)
- **30-59**: ⚠️ SUSPICIOUS (Medium threat, review recommended)
- **0-29**: ✅ CLEAN (Low threat, safe storage)

### Malware Families Detected

- **Ransomware**: bitcoin, encrypted, ransom keywords
- **Backdoor**: reverse shells, remote access tools
- **Keylogger**: credential theft, keystroke capture
- **Cryptominer**: mining pools, crypto wallets
- **Trojan**: generic malware patterns

## 📊 Results

- ✅ **Detection Accuracy**: 100% on test samples
- ⚡ **Analysis Speed**: <10 seconds per file
- 📈 **Scalability**: Serverless auto-scaling
- 💰 **Cost**: ~$25-30/month operational
- 🎯 **False Positives**: <5% rate

## 🛠️ Tech Stack

**Cloud Services:**
- AWS EC2 (Honeypot)
- AWS Lambda (Analysis Engine)
- AWS S3 (File Storage)
- AWS DynamoDB (Threat Database)
- AWS SNS (Alerting)
- AWS CloudWatch (Monitoring)

**Languages & Tools:**
- Python 3.11
- Boto3 (AWS SDK)
- inotify-tools (File monitoring)
- Regular Expressions (IOC extraction)

## 🚀 Quick Start

### Prerequisites
- AWS Account
- AWS CLI configured
- Python 3.11+

### Deployment
```bash
# 1. Clone repository
git clone https://github.com/yourusername/aws-malware-detection-system.git
cd aws-malware-detection-system

# 2. Deploy Lambda function
cd lambda
zip lambda.zip lambda_function.py
aws lambda create-function \
  --function-name HoneypotMalwareAnalyzer \
  --runtime python3.11 \
  --zip-file fileb://lambda.zip \
  --handler lambda_function.lambda_handler \
  --role arn:aws:iam::YOUR_ACCOUNT:role/LambdaRole

# 3. Create S3 buckets
aws s3 mb s3://your-quarantine-bucket
aws s3 mb s3://your-clean-bucket

# 4. Launch honeypot EC2
# See infrastructure/honeypot-userdata.sh for configuration
```

**Full setup guide**: [docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md)

## 📸 Screenshots

### Email Alert Example
```
🚨 MALICIOUS FILE DETECTED

File: backdoor.sh
Verdict: MALICIOUS
Threat Level: HIGH
Score: 75/100
Classification: Backdoor/Remote Access Trojan

Network IOCs:
  → 45.142.114.231:4444
  → evil-c2.com

Status: QUARANTINED
```

## 🎥 Demo Video

[Watch 5-minute demonstration](https://youtu.be/uwr6PWY2vFA)

## 🔐 Security Considerations

**⚠️ WARNING: This is an intentionally vulnerable honeypot system!**

- Deploy **only** in isolated environments
- **Never** connect to production networks
- Use dedicated AWS account for security projects
- Enable CloudTrail for audit logging
- Review all captured files in sandboxed environment

## 💡 Use Cases

- **Security Operations Centers (SOC)**: Automated threat triage
- **Incident Response**: Rapid malware classification
- **Threat Intelligence**: IOC collection and correlation
- **Security Research**: Malware behavior analysis
- **Educational**: Learn cloud security and malware analysis

## 📚 Documentation

- [Technical Report](docs/TECHNICAL_REPORT.md) - Complete project documentation
- [Setup Guide](docs/SETUP_GUIDE.md) - Deployment instructions
- [Architecture Design](docs/ARCHITECTURE.md) - System design decisions

## 🏆 Skills Demonstrated

- ✅ Cloud Security Architecture
- ✅ Malware Analysis & Threat Detection
- ✅ Python Development & Scripting
- ✅ AWS Services Integration
- ✅ Serverless Computing
- ✅ Infrastructure as Code
- ✅ Security Automation
- ✅ Incident Response

## 🔮 Future Enhancements

- [ ] VirusTotal API integration
- [ ] Cuckoo Sandbox for dynamic analysis
- [ ] Machine learning threat scoring
- [ ] Multi-region deployment
- [ ] Web dashboard (React frontend)
- [ ] Threat intelligence sharing (MISP)

## 📄 License

MIT License - See [LICENSE](LICENSE) for details

**Disclaimer**: For educational and research purposes only. Not intended for production use without proper security hardening.

## 👤 Author

  Ali al-Saleh
- LinkedIn: Ali AlSaleh
- Email: alsalehali313@gmail.com

---
## do not forget to check out the images

⭐ **If you found this project useful, please star the repository!**

