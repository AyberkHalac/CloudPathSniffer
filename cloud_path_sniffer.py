import argparse
import json
import os

from credential_mapper import CredentialMapper
from helpers.boto3_helpers import heartbeat, create_boto3_session
from helpers.config_reader import get_config_file
from helpers.logger import setup_logger
from helpers.repository import Neo4jDatabase
from security import Security, PrivilegeEscalation

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(os.path.join(ROOT_DIR, 'logs'), 'CredentialMapper.log')

logger = setup_logger(logger_name='main', filename=LOG_FILE_PATH)

if __name__ == "__main__":

    # Add argv here
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0', help="Shows program's version number.")
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Shows help message.')
    parser.add_argument('--aws_profile_name', default=None, required=False, help='AWS Local Profile Name')
    parser.add_argument('--aws_access_key_id', default=None, required=False, help='AWS Access Key Id')
    parser.add_argument('--aws_secret_access_key', default=None, required=False, help='AWS Secret Access Key')
    parser.add_argument('--aws_session_token', default=None, required=False, help='AWS Session Token')
    parser.add_argument('--region', default='us-east-1', required=False, help='AWS Client Working Region. For now, you can only select one region.')
    parsed_args = parser.parse_args()

    aws_profile_name = parsed_args.aws_profile_name
    aws_access_key_id = parsed_args.aws_access_key_id
    aws_secret_access_key = parsed_args.aws_secret_access_key
    aws_session_token = parsed_args.aws_session_token
    region = parsed_args.region

    session = None

    try:
        if aws_profile_name is not None or (aws_access_key_id is not None and aws_secret_access_key is not None):
            session = create_boto3_session(aws_profile_name=aws_profile_name, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
        else:
            _profile_name, _aws_access_key_id, _aws_secret_access_key, _aws_session_token = '', '', '', ''
            try:
                config = get_config_file('./config.yaml')
                _profile_name = config['aws_profile_name']
                _aws_access_key_id = config['aws_access_key_id']
                _aws_secret_access_key = config['aws_secret_access_key']
                _aws_session_token = config['aws_session_token']
            except Exception as e:
                logger.critical(e)
                print('Cannot read the config.yaml!')
                exit(1)
            beat = heartbeat(aws_profile_name=_profile_name, aws_access_key_id=_aws_access_key_id, aws_secret_access_key=_aws_secret_access_key, aws_session_token=_aws_session_token)
            if not beat:
                logger.critical('Access Key Expired!')
                print('Access Key Expired!')
                exit(1)
            session = create_boto3_session(aws_profile_name=_profile_name, aws_access_key_id=_aws_access_key_id, aws_secret_access_key=_aws_secret_access_key, aws_session_token=_aws_session_token)
    except Exception as e:
        logger.critical(e)
        print(e)
        exit(-1)

    print("[#] CloudPathSniffer is gonna sniff your CloudTrail :)")

    # # # INITIALIZE NEO4J # # #
    print("[#] Initializing Neo4j.")
    neo_db = Neo4jDatabase()
    neo_db.delete_all_data()

    # # # ADD CREDENTIALS TO THE NEO4J # # #
    print("[#] Preparing the Athena.")
    credential_mapper = CredentialMapper(session=session)
    print('[#] Starting to gather credentials and push them into the Neo4j')
    nodes = credential_mapper.add_all_credentials_to_neo4j()
    credentials = credential_mapper.add_relationships_of_credentials()
    credential_mapper.collect_and_fix_ownerless_credentials()
    print("[#] All credentials are added to the Neo4j")

    # # # SECURITY CONTROLS # # #
    security_controller = Security(session=session, region=region)

    print("[#] Detected Role Juggling Attack Path:")
    role_juggling_attack_results = security_controller.detect_role_juggling_long_repeating_patterns()
    if len(role_juggling_attack_results) > 0:
        credential_mapper.add_role_juggling_attack_to_the_neo4j(role_juggling_attack_results)
    print(json.dumps(role_juggling_attack_results, indent=4))

    print("[#] Illegal Console Logins from Access Keys:")
    console_logins = security_controller.detect_suspicious_console_login_of_iam_credentials()
    if len(console_logins) > 0:
        credential_mapper.add_console_login_of_iam_credentials_to_neo4j(console_logins)
    print(json.dumps(console_logins, indent=4))

    print("[#] Exposed EC2 temporary credentials which are accessed from outside of the AWS IPs:")
    print(json.dumps(security_controller.detect_exposed_ec2_temporary_credentials(), indent=4))

    print("[#] Exposed EC2 temporary credentials which are accessed from different IPs:")
    print(json.dumps(security_controller.detect_exposed_ec2_temporary_credentials_with_aws_ips(), indent=4))

    print("[#] Accesses from Blacklisted IP:")
    print(json.dumps(security_controller.detect_blacklisted_ip_accesses(), indent=4))

    print("[#] Detected Abnormal Relationship Counts:")
    print(json.dumps(security_controller.find_nodes_with_max_relationship(contains_service_accounts=False), indent=4))

    print("[#] Detected Anonymous Access:")
    print(json.dumps(security_controller.detect_anonymous_access(), indent=4))

    print("[#] Detected Anomalies:")
    anomalies = security_controller.detect_anomalies_from_yaml_files()
    if len(anomalies) > 0:
        credential_mapper.add_anomalies_to_the_neo4j(anomalies)
    print(json.dumps(anomalies, indent=4))

    print("[#] Detected Privilege Escalation Scenarios:")
    privilege_escalation = PrivilegeEscalation(session=session, region=region)
    print(json.dumps(privilege_escalation.check_privilege_escalation_scenarios(), indent=4))
