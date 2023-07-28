# AWSCredentialMapper


One of the biggest issue of AWS is that assumed credentials are hidden from view. Attackers can simply stay inside your AWS system easily without caught. The Credential Mapper project integrates Cloudtrail data into Athena to generate assume pathways more quickly and efficiently. The project doesn't use CloudTrail logs and saved log files in v1.


##  Installation

Install Neo4j Database : https://neo4j.com/docs/operations-manual/current/installation/

```sh
pip3 install -r requirements.txt
```
## How to configure config.yaml ?


## How to run ?

```sh
.\neo4j.bat console
or neo4j console
```

```sh
python3 credential_mapper.py
```

