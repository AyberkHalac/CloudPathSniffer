# AWSCredentialMapper

One of the biggest issue of AWS is that assumed credentials are hidden from view. Attackers can simply stay inside your AWS system easily without caught. The Credential Mapper project integrates Cloudtrail data into Athena to generate assume pathways
more quickly and efficiently. The project doesn't use CloudTrail logs and saved log files in v1.

### What can Credential Mapper do?

- Finds all active/expired temporary credentials
- Finds all active/inactive/deleted access keys.
- Extracts all parents and children of a credential and maps it using neo4j.
- Finds anomalies in the log records, which includes the generation of temporary credentials and the creation of access keys.

### TODO:
=======
- Develop frontend to visualise the credential path map. (For now, you can view your output only from Neo4j browser.) 
- Add detection mechanism for Role Juggling Attack
- Multi region cloudtrail control for now its only for us-east-1. (The fact that IAM does not employ regions ensures that we never miss an IAM case. Exposed credential controls for EC2 are the only issue.)

## Installation

Install Neo4j Database : https://neo4j.com/docs/operations-manual/current/installation/

```sh
pip3 install -r requirements.txt
```

## How to configure config.yaml ?

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

## How to run ?

```sh
.\neo4j.bat console
or neo4j console
```

```sh
python3 credential_mapper.py
```

### Do you want to start ASAP?

```
1- Configure your awscli using the command `aws configure --profile credentialmapper`
2- Configure your config.yaml
  2.1- Start Neo4j console `> neo4j console`
  2.2- Set aws_profile_name: credentialmapper
  2.3- Set your bucket name 
  2.4- Set your neo4j credentials and neo4j uri
3- python3 credential_mapper.py
4- Open Neo4j bucket uri from browser
```

Output Examples:
![graph](https://github.com/AyberkHalac/AWSCredentialMapper/assets/9082447/6b781bbb-a7b1-41ba-9687-468822ef16f6)
![Screenshot](https://github.com/AyberkHalac/AWSCredentialMapper/assets/9082447/99b33a91-0a5d-4476-8c0a-2ba0d9b086cc)
![Screenshot](https://github.com/AyberkHalac/AWSCredentialMapper/assets/9082447/2fc4f6c2-d47a-4c09-8cc1-d395f35dab0f)
![Screenshot](https://github.com/AyberkHalac/AWSCredentialMapper/assets/9082447/7295611a-79b8-4e60-a3b9-1f271ee90595)
![Screenshot](https://github.com/AyberkHalac/AWSCredentialMapper/assets/9082447/604510ed-35cb-4efe-949d-c5647d9f5c31)

