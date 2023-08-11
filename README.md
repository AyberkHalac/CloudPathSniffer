# CloudPathSniffer

<div align="center">
 <a href="https://www.linkedin.com/in/ayberkhalac/">
    <img src="https://img.shields.io/badge/license-GPLv3-blue">
 </a>
 <a href="https://github.com/ayberkhalac/CloudPathSniffer/issues">
    <img src="https://img.shields.io/github/issues/ayberkhalac/CloudPathSniffer">
 </a>
 <a href="https://github.com/ayberkhalac/CloudPathSniffer">
    <img src="https://img.shields.io/github/stars/ayberkhalac/CloudPathSniffer?color=red&style=flat-square">
 </a>
</div>

# Introduction

## Description

CloudPathSniffer is open-source, easy to use and extensible Cloud Anomaly Detection platform designed to help security teams to find hard to see risks and undetected attackers in their control plane of cloud environments.

In the dynamic environment of cloud security, the inability to view temporary credentials has long been a risk, making it difficult to detect and track potential malicious activity. 

CloudPathSniffer transcends conventional approaches by not only tracking temporary credentials but also unveiling concealed vulnerabilities within logs. Lateral movements were visualized with graphic-based visualization and the interpretation of the outputs was facilitated. This cutting-edge solution seamlessly integrates these insights into the graph database alongside your credentials, resulting in a holistic defense strategy that leaves no stone unturned.

# Features

- Finds all active/expired temporary credentials.
- Finds all active/inactive/deleted long-term access keys.
- [Neo4j](https://neo4j.com/) Graph Database entegration to visualize the anomalous view perfect.    
- Detects AWS Role Juggling Attack, tags the API calls that come from blacklisted IP's, finds EC2 instance credentials used outside of the EC2 instance.
- Finds anomalies in the log records, which includes the generation of temporary credentials and the creation of access keys.

### TODO

- Develop frontend to visualise the credential path map. (If you want to view your data then you can use [Neo4j](https://neo4j.com/) Desktop browser.) 
- Multi region cloudtrail control for now its only for us-east-1. (The fact that IAM does not employ regions ensures that we never miss an IAM case. Exposed credential controls for EC2 are the only issue.)
- Detect privilege escalation scenarios.
- Detect anomalous lateral movements.
- Use saved log files from buckets.

# Dependencies

### 3rd-party dependencies:
  - botocore
  - py2neo
  - boto3
  - neo4j
  - requests
  - PyYAML


# Installation

- CloudPathSniffer uses Neo4j Database so first you should install Neo4j:
Install [Neo4j](https://neo4j.com/) Database Desktop Version : https://neo4j.com/docs/operations-manual/current/installation/

Configure your config file with your Neo4j and AWS credentials. You can either add your credentials to aws credentials file and write the profile name to the config.yaml or you can directly add your credentials to the config.yaml.

- Explanation of config.yaml ?

```
# AWS Credentials
aws_profile_name: {If you've already set up your profile in ~/.aws/credentials, type your profile name here.}
aws_access_key_id: {If not use your temporary credential or long term access key}
aws_secret_access_key:
aws_session_token:


# Bucket Name of CloudTrail Service
bucket_name: {Type the Cloudtrail bucket name here.}


# How many days do you want to go back
all_temporary_credentials:
  days: (Cloudtrail can save your logs for a maximum of 90 days)
  hours: 0
  minutes: 0


# Neo4j database connection
neo4j_connection_configurations:
  username: neo4j (Neo4j database credentials)
  password: neo4j (Neo4j database credentials)
  database_uri: bolt://localhost:7687 (Neo4j database uri)
```

Install python3 requirements:
```sh
pip3 install -r requirements.txt
```

# Usage

Start your Neo4j Database
Start CloudPathSniffer:
```sh
python3 credential_mapper.py
```

# License

CloudPathSniffer is under GNU GPL3 License. For more information please check LICENSE and LICENSE-3RD-PARTY files.
