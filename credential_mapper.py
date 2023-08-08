import errno
import json
import os
import time
from datetime import datetime, timedelta

from botocore.exceptions import ClientError

from helpers.athena_preparation import prepare_athena
from helpers.boto3_helpers import create_boto3_session, heartbeat, get_access_key_of_user, get_user, list_users
from helpers.config_reader import get_config_file
from helpers.database_helper import Neo4jDatabase
from helpers.logger import setup_logger

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(os.path.join(ROOT_DIR, 'logs'), 'CredentialMapper.log')

logger = setup_logger(logger_name='credential_mapper', filename=LOG_FILE_PATH)


class CredentialMapper:

    def __init__(self, aws_profile_name=None, aws_access_key_id=None, aws_secret_access_key=None, aws_session_token=None):
        try:
            if aws_profile_name is not None or (aws_access_key_id is not None and aws_secret_access_key is not None):
                self.session = create_boto3_session(aws_profile_name=aws_profile_name, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
            else:
                _profile_name, _aws_access_key_id, _aws_secret_access_key, _aws_session_token = '', '', '', ''
                try:
                    self.config = get_config_file('./config.yaml')
                    _profile_name = self.config['aws_profile_name']
                    _aws_access_key_id = self.config['aws_access_key_id']
                    _aws_secret_access_key = self.config['aws_secret_access_key']
                    _aws_session_token = self.config['aws_session_token']
                    self.all_temporary_credentials_timespan = self.config['all_temporary_credentials']
                except Exception as e:
                    logger.critical(e)
                    print('Cannot read the config.yaml!')
                    exit(1)
                beat = heartbeat(aws_profile_name=_profile_name, aws_access_key_id=_aws_access_key_id, aws_secret_access_key=_aws_secret_access_key, aws_session_token=_aws_session_token)
                if not beat:
                    print('Access Key Expired!')
                    exit(1)
                self.session = create_boto3_session(aws_profile_name=_profile_name, aws_access_key_id=_aws_access_key_id, aws_secret_access_key=_aws_secret_access_key, aws_session_token=_aws_session_token)
            self.cloudtrail_client = self.session.client('cloudtrail')
            self.athena_client = self.session.client('athena')
            self.ec2_client = self.session.client('ec2')
            prepare_athena(self.athena_client, self.config['bucket_name'], self.session.client('sts').get_caller_identity()['Account'])
        except Exception as e:
            print('[!] Error at starting credential mapper.')
            logger.critical(e)
            exit(1)

    @staticmethod
    def is_long_term_credential_active(val_time: str) -> bool:
        """
        This method checks if credential is active or not
        :param val_time: Creation time of the credentials
        :return: Bool
        """
        datetime_object = datetime.strptime(val_time, "%b %d, %Y, %I:%M:%S %p")
        return True if datetime.utcnow() < datetime_object else False

    @staticmethod
    def write_dict_array_to_csv(dict_list, filename="temporary_credentials.csv"):
        import csv
        try:
            os.makedirs(os.path.join(ROOT_DIR, 'outputs'))
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        if len(dict_list) == 0:
            return None
        keys = dict_list[0].keys()
        with open('./outputs/' + filename, 'w', newline='') as f:
            dict_writer = csv.DictWriter(f, keys)
            dict_writer.writeheader()
            dict_writer.writerows(dict_list)

    def get_all_generated_credentials(self):

        def check_long_term_access_key_status(userName, accessKey):
            status = 'deleted'
            accessKeys = get_access_key_of_user(session=self.session, userName=userName)
            for key in accessKeys:
                if key['AccessKeyId'] == accessKey:
                    status = key['Status']
                    break
            return status

        try:
            added_users = {}
            all_temporary_credentials = []
            logger.debug("[+] Start gathering information from Athena.")
            start_time = datetime.utcnow() - timedelta(days=self.all_temporary_credentials_timespan['days'], hours=self.all_temporary_credentials_timespan['hours'], minutes=self.all_temporary_credentials_timespan['minutes'])
            datetime_object = datetime.strptime(str(start_time), "%Y-%m-%d %H:%M:%S.%f").strftime("%Y-%m-%dT%H:%M:%SZ")
            sql_query = """SELECT  
                            cast(useridentity as json) as useridentity,
                            json_extract(responseelements, '$.credentials.accessKeyId') as accessKeyId,
                            eventtime,
                            json_extract(responseelements, '$.credentials.expiration') as expiration,
                            sourceipaddress as sourceIpAddress,
                            json_extract(responseelements, '$.assumedRoleUser.arn') as assumedRoleUser,
                            eventid,
                            requestparameters,
                            eventname,
                            json_extract(responseelements, '$.accessKey') as createdAccessKey
                                FROM CredentialMapper 
                                    WHERE 
                                        errorcode is NULL
                                        and eventname IN ('GetSessionToken', 'AssumeRole', 'AssumeRoleWithWebIdentity', 'GetFederationToken', 'AssumeRoleWithSAML', 'CreateAccessKey')
                                        and eventtime > '{event_time}'
                                        ORDER BY eventtime ASC""".format(event_time=datetime_object)

            query_response = self.athena_client.start_query_execution(QueryString=sql_query,
                                                                      ResultConfiguration={'OutputLocation': f's3://{self.config["bucket_name"]}/CredentialMapper/'},
                                                                      QueryExecutionContext={'Database': 'CredentialMapper'}
                                                                      )
            query_execution_id = query_response['QueryExecutionId']

            query_response = self.athena_client.get_query_execution(
                QueryExecutionId=query_execution_id
            )
            ready_state = query_response['QueryExecution']['Status']['State']

            timeout = 600
            while ready_state != 'SUCCEEDED' and ready_state != 'FAILED' and timeout > 0:
                query_response = self.athena_client.get_query_execution(
                    QueryExecutionId=query_execution_id
                )
                ready_state = query_response['QueryExecution']['Status']['State']
                time.sleep(2)
                timeout -= 2
                if timeout <= 0:
                    raise ClientError

            response = {}
            is_truncated = False
            first = True
            while len(response.keys()) == 0 or is_truncated:
                if is_truncated is False:
                    response = self.athena_client.get_query_results(
                        QueryExecutionId=query_execution_id,
                        MaxResults=50
                    )
                else:
                    response = self.athena_client.get_query_results(
                        QueryExecutionId=query_execution_id,
                        MaxResults=50,
                        NextToken=response['NextToken']
                    )

                logger.debug("[+] Start parsing the data")
                for trail in response['ResultSet']['Rows']:
                    if first:
                        first = False
                        continue

                    data = {
                        'user_identity': trail['Data'][0]['VarCharValue'] if 'VarCharValue' in trail['Data'][0] else '',
                        'access_key_id': trail['Data'][1]['VarCharValue'] if 'VarCharValue' in trail['Data'][1] else '',
                        'event_time': trail['Data'][2]['VarCharValue'] if 'VarCharValue' in trail['Data'][2] else '',
                        'expiration_time': trail['Data'][3]['VarCharValue'] if 'VarCharValue' in trail['Data'][3] else '',
                        'source_ip_address': trail['Data'][4]['VarCharValue'] if 'VarCharValue' in trail['Data'][4] else '',
                        'assumed_role_arn': trail['Data'][5]['VarCharValue'] if 'VarCharValue' in trail['Data'][5] else '',
                        'event_id': trail['Data'][6]['VarCharValue'] if 'VarCharValue' in trail['Data'][6] else '',
                        'request_parameters': trail['Data'][7]['VarCharValue'] if 'VarCharValue' in trail['Data'][7] else '',
                        'event_name': trail['Data'][8]['VarCharValue'] if 'VarCharValue' in trail['Data'][8] else '',
                        'created_access_key': trail['Data'][9]['VarCharValue'] if 'VarCharValue' in trail['Data'][9] else '',

                    }
                    user_identity = json.loads(data['user_identity'])
                    user_identity_type = user_identity['type']
                    user_identity_principalid = user_identity['principalid']
                    # user_identity_arn = user_identity['arn']
                    user_identity_accountid = user_identity['accountid']
                    user_identity_invokedby = user_identity['invokedby']
                    user_identity_accesskeyid = user_identity['accesskeyid']
                    user_identity_username = user_identity['username']
                    # user_identity_sessioncontext = user_identity['sessioncontext']

                    service_name = ''

                    if user_identity_type == 'IAMUser':
                        requesters_identity = user_identity_accesskeyid
                    elif user_identity_type == 'AWSService':
                        if 'amazonaws.com' in user_identity_invokedby:
                            if 'roleSessionName' in json.loads(data['request_parameters']):
                                requesters_identity = json.loads(data['request_parameters'])['roleSessionName']
                            else:
                                requesters_identity = 'Unknown'
                            service_name = user_identity_invokedby
                        else:
                            requesters_identity = user_identity_invokedby
                    elif user_identity_type == 'AssumedRole':
                        requesters_identity = user_identity_accesskeyid
                    elif user_identity_type == 'SAMLUser':
                        requesters_identity = user_identity_username
                    elif user_identity_type == 'AWSAccount':
                        requesters_identity = user_identity_accountid
                    elif user_identity_type == 'WebIdentityUser':
                        requesters_identity = user_identity_username
                    elif user_identity_type == 'FederatedUser':
                        requesters_identity = user_identity_principalid[user_identity_principalid.find(':') + 1:]
                    elif user_identity_type == 'Root':
                        requesters_identity = 'Root'
                    else:
                        requesters_identity = user_identity

                    # TODO: Add absent identities
                    """ 
                    https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html
                    WebIdentityUser     +
                    AssumedRole         +
                    AWSAccount          +
                    AWSService          +
                    IAMUser             +
                    Root                -
                    FederatedUser       +
                    SAMLUser            +
                    Unknown             -
                    Role                -
                    Directory           -
                    <novalue>           - the attribute is not found
                    """

                    if data['event_name'] != 'CreateAccessKey':
                        access_key_id = data['access_key_id']
                        expiration_time = data['expiration_time'].replace('"', '')
                        is_active = self.is_long_term_credential_active(expiration_time)
                        requested_role = json.loads(data['request_parameters'])['roleArn'] if 'roleArn' in json.loads(data['request_parameters']) else json.loads(data['request_parameters'])['name']
                        if data['event_name'] == 'GetFederationToken':
                            assumed_role_arn = str(json.loads(data['request_parameters'])['policyArns'])
                            requesters_identity = user_identity_accesskeyid
                        else:
                            assumed_role_arn = data['assumed_role_arn'].replace('"', '')
                            if user_identity_type == 'FederatedUser':
                                requesters_identity = service_name + ':' + requesters_identity
                        timestamp = datetime.strptime(data['event_time'], '%Y-%m-%dT%H:%M:%SZ').strftime('%b %d, %Y, %I:%M:%S %p')
                        all_temporary_credentials.append({'user_identity_type': user_identity_type,
                                                          'requesters_identity': requesters_identity,
                                                          'access_key_id': access_key_id.replace('"', ''),
                                                          'event_time': timestamp,
                                                          'expiration_time': expiration_time,
                                                          'assumed_role_arn': assumed_role_arn,
                                                          'requested_role': requested_role,
                                                          'source_ip_address': data['source_ip_address'],
                                                          'is_active': 'Active' if is_active else 'Expired',
                                                          'event_id': data['event_id'],
                                                          'event_name': data['event_name']
                                                          })

                    else:
                        created_access_key = json.loads(data['created_access_key'])
                        timestamp = datetime.strptime(data['event_time'], '%Y-%m-%dT%H:%M:%SZ').strftime('%b %d, %Y, %I:%M:%S %p')
                        user = get_user(session=self.session, userName=created_access_key['userName'])
                        all_temporary_credentials.append({'user_identity_type': user_identity_type,
                                                          'requesters_identity': requesters_identity,
                                                          'access_key_id': created_access_key['accessKeyId'],
                                                          'requested_for': created_access_key['userName'],
                                                          'requested_users_arn': user['Arn'],
                                                          'requested_users_id': user['UserId'],
                                                          'event_time': timestamp,
                                                          'source_ip_address': data['source_ip_address'],
                                                          'is_active': check_long_term_access_key_status(created_access_key['userName'], created_access_key['accessKeyId']),
                                                          'event_id': data['event_id'],
                                                          'event_name': data['event_name']
                                                          })
                        if created_access_key['userName'] not in added_users:
                            added_users[created_access_key['userName']] = []
                        added_users[created_access_key['userName']].append(created_access_key['accessKeyId'])
                logger.debug("[+] Parse is finished.")
                if 'NextToken' in response:
                    is_truncated = True
                else:
                    is_truncated = False
            logger.debug("[+] Athena task is finished.")
            logger.debug("[+] Starting to parse absent access keys.")
            users = list_users(session=self.session)
            for user in users:
                access_keys = get_access_key_of_user(session=self.session, userName=user['UserName'])
                for access_key in access_keys:
                    if user['UserName'] not in added_users or access_key not in added_users[user['UserName']]:
                        all_temporary_credentials.append({'user_identity_type': 'Unknown',
                                                          'requesters_identity': 'Unknown',
                                                          'access_key_id': access_key['AccessKeyId'],
                                                          'requested_for': user['UserName'],
                                                          'requested_users_arn': user['Arn'],
                                                          'requested_users_id': user['UserId'],
                                                          'event_time': access_key['CreateDate'].strftime('%b %d, %Y, %I:%M:%S %p'),
                                                          'source_ip_address': None,
                                                          'is_active': access_key['Status'],
                                                          'event_id': None,
                                                          'event_name': 'CreateAccessKey'
                                                          })
                        if user['UserName'] not in added_users:
                            added_users[user['UserName']] = []
                        added_users[user['UserName']].append(access_key)
            logger.debug("[+] Parsing of the absent access keys task is finished.")

            return all_temporary_credentials
        except ClientError as err:
            logger.critical(err)
            print('[!] Exception while the running Athena.')
            exit(1)
        except Exception as e:
            logger.critical(e)
            print('[!] Exception while the running Athena.')
            exit(1)

    def check_console_login_of_iam_credentials(self):
        """
        https://github.com/Hacking-the-Cloud/hackingthe.cloud/blob/main/content/aws/post_exploitation/create_a_console_session_from_iam_credentials.md
        This function checks if the attacker get console access via iam credentials.
        This function is void and fills the neo4j database
        """
        try:
            console_logins = []
            config = get_config_file('./config.yaml')
            all_temporary_credentials_timespan = config['all_temporary_credentials']
        except Exception as e:
            logger.critical('[!] Getting error reading config file', str(e))
            return
        start_time = datetime.utcnow() - timedelta(days=all_temporary_credentials_timespan['days'], hours=all_temporary_credentials_timespan['hours'], minutes=all_temporary_credentials_timespan['minutes'])
        datetime_object = datetime.strptime(str(start_time), "%Y-%m-%d %H:%M:%S.%f").strftime("%Y-%m-%dT%H:%M:%SZ")
        sql_query = """
        SELECT  
            cast(useridentity as json) as useridentity,
            eventtime,
            sourceipaddress,
            eventid,
            eventname
        FROM CredentialMapper 
            WHERE 
                errorcode is NULL
                and useridentity.type='FederatedUser'
                and eventname = 'ConsoleLogin'
                and eventtime > '2023-07-07T14:55:21Z'
            ORDER BY eventtime ASC
        """.format(event_time=datetime_object)

        query_response = self.athena_client.start_query_execution(QueryString=sql_query,
                                                                  ResultConfiguration={'OutputLocation': f's3://{self.config["bucket_name"]}/CredentialMapper/'},
                                                                  QueryExecutionContext={'Database': 'CredentialMapper'}
                                                                  )
        query_execution_id = query_response['QueryExecutionId']

        query_response = self.athena_client.get_query_execution(
            QueryExecutionId=query_execution_id
        )
        ready_state = query_response['QueryExecution']['Status']['State']

        timeout = 600
        while ready_state != 'SUCCEEDED' and ready_state != 'FAILED' and timeout > 0:
            query_response = self.athena_client.get_query_execution(
                QueryExecutionId=query_execution_id
            )
            ready_state = query_response['QueryExecution']['Status']['State']
            time.sleep(2)
            timeout -= 2
            if timeout <= 0:
                raise ClientError

        response = {}
        is_truncated = False
        first = True
        while len(response.keys()) == 0 or is_truncated:
            if is_truncated is False:
                response = self.athena_client.get_query_results(
                    QueryExecutionId=query_execution_id,
                    MaxResults=50
                )
            else:
                response = self.athena_client.get_query_results(
                    QueryExecutionId=query_execution_id,
                    MaxResults=50,
                    NextToken=response['NextToken']
                )

            logger.debug("[+] Start parsing the data")
            for trail in response['ResultSet']['Rows']:
                if first:
                    first = False
                    continue

                data = {
                    'user_identity': trail['Data'][0]['VarCharValue'] if 'VarCharValue' in trail['Data'][0] else '',
                    'event_time': trail['Data'][1]['VarCharValue'] if 'VarCharValue' in trail['Data'][1] else '',
                    'source_ip_address': trail['Data'][2]['VarCharValue'] if 'VarCharValue' in trail['Data'][2] else '',
                    'event_id': trail['Data'][3]['VarCharValue'] if 'VarCharValue' in trail['Data'][3] else '',
                    'event_name': trail['Data'][4]['VarCharValue'] if 'VarCharValue' in trail['Data'][4] else '',

                }
                user_identity = json.loads(data['user_identity'])
                user_identity_type = user_identity['type']
                user_identity_principalid = user_identity['principalid']
                user_identity_arn = user_identity['arn']
                user_identity_accountid = user_identity['accountid']
                user_identity_session_issuer = user_identity['sessioncontext']['sessionissuer']

                if user_identity_session_issuer['type'] == "IAMUser":
                    requesters_identity_type = user_identity_session_issuer['type']
                    requesters_identity_principalid = user_identity_session_issuer['principalid']
                    requesters_identity_arn = user_identity_session_issuer['arn']
                    requesters_identity_username = user_identity_session_issuer['username']
                else:  # TODO: Check other scenarios about this part
                    requesters_identity_type = None
                    requesters_identity_principalid = None
                    requesters_identity_arn = None
                    requesters_identity_username = None

                timestamp = datetime.strptime(data['event_time'], '%Y-%m-%dT%H:%M:%SZ').strftime('%b %d, %Y, %I:%M:%S %p')
                console_logins.append({
                    'user_identity_type': user_identity_type,
                    'user_identity_principalid': user_identity_principalid,
                    'user_identity_arn': user_identity_arn,
                    'user_identity_accountid': user_identity_accountid,
                    'requesters_identity_type': requesters_identity_type,
                    'requesters_identity_principalid': requesters_identity_principalid,
                    'requesters_identity_arn': requesters_identity_arn,
                    'requesters_identity_username': requesters_identity_username,
                    'event_time': timestamp,
                    'source_ip_address': data['source_ip_address'],
                    'event_id': data['event_id'],
                    'event_name': data['event_name']
                })
        return console_logins


if __name__ == "__main__":
    greeter = Neo4jDatabase()
    greeter.neo4j_delete_all()
    cred_mapper = CredentialMapper()
    credentials = cred_mapper.get_all_generated_credentials()
    greeter.neo4j_bulk_add_credentials(credentials)
    console_logins = cred_mapper.check_console_login_of_iam_credentials()
    if len(console_logins) > 0:
        greeter.add_rel_as_console_login_of_iam_credentials(console_logins)
