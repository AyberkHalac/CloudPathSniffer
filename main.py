import argparse
import os

from credential_mapper import CredentialMapper
from helpers.boto3_helpers import heartbeat, create_boto3_session
from helpers.config_reader import get_config_file
from helpers.logger import setup_logger
from helpers.repository import Neo4jDatabase

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

    neoDb = Neo4jDatabase()
    neoDb.neo4j_delete_all()

    credentialMapper = CredentialMapper(session=session)

    credentials = credentialMapper.get_all_generated_credentials()
    neoDb.neo4j_bulk_add_credentials(credentials)

    console_logins = credentialMapper.check_console_login_of_iam_credentials()
    if len(console_logins) > 0:
        neoDb.add_rel_as_console_login_of_iam_credentials(console_logins)

    # # # SECURITY CONTROLS # # #

    # security_controller = Security(session=session, region=region)
    # security_controller.check_exposed_ec2_temporary_credentials()
    # security_controller.check_logs_for_blacklisted_ip_accesses()
    # security_controller.check_exposed_ec2_temporary_credentials_with_aws_ips()
    # role_juggling_long_repeating_pattern()
