import errno
import json
import os
import time
from datetime import datetime, timedelta

from botocore.exceptions import ClientError

from helpers.athena_preparation import prepare_athena
from helpers.boto3_helpers import get_access_key_of_user, get_user, list_users
from helpers.config_reader import get_config_file
from helpers.logger import setup_logger
from helpers.repository import Neo4jDatabase

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(os.path.join(ROOT_DIR, 'logs'), 'CredentialMapper.log')

logger = setup_logger(logger_name='credential_mapper', filename=LOG_FILE_PATH)


class CredentialMapper:

    def __init__(self, session):
        try:
            self.session = session
            self.cloudtrail_client = self.session.client('cloudtrail')
            self.athena_client = self.session.client('athena')
            config = get_config_file('./config.yaml')
            self.timespan_timespan = config['timespan']
            self.bucket_name = config['bucket_name']
            self.users = list_users(session=self.session)
            prepare_athena(self.athena_client, config['bucket_name'], self.session.client('sts').get_caller_identity()['Account'])
            self.neo4j_controller = Neo4jDatabase()
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

    def add_all_credentials_to_neo4j(self):
        logger.debug("[+] Starting add_all_credentials_to_neo4j.")
        try:
            neo_db = Neo4jDatabase()
            with neo_db.driver.session() as driver_session:
                timespan = []
                start_time = datetime.utcnow() - timedelta(days=self.timespan_timespan['days'], hours=self.timespan_timespan['hours'], minutes=self.timespan_timespan['minutes'])
                datetime_object = datetime.strptime(str(start_time), "%Y-%m-%d %H:%M:%S.%f").strftime("%Y-%m-%dT%H:%M:%SZ")
                sql_query = """SELECT DISTINCT cast(useridentity as json) as useridentity
                                    FROM CredentialMapper 
                                WHERE 
                                    eventsource not like '%kms%' and
                                    eventtime > '{event_time}'""".format(event_time=datetime_object)

                query_response = self.athena_client.start_query_execution(QueryString=sql_query,
                                                                          ResultConfiguration={'OutputLocation': f's3://{self.bucket_name}/CredentialMapper/'},
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

                    for trail in response['ResultSet']['Rows']:
                        if first:
                            first = False
                            continue

                        data = {
                            'user_identity': trail['Data'][0]['VarCharValue'] if 'VarCharValue' in trail['Data'][0] else ''

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

                        identity = ''

                        if user_identity_type == 'IAMUser':
                            identity = user_identity_accesskeyid
                            if user_identity_accesskeyid.startswith('ASIA'):
                                user_identity_type = 'AssumedRole'
                            elif user_identity_accesskeyid.startswith('AKIA'):
                                user_identity_type = 'AccessKeyId'
                        elif user_identity_type == 'AWSService':
                            identity = user_identity_invokedby
                        elif user_identity_type == 'AssumedRole':
                            identity = user_identity_accesskeyid
                        elif user_identity_type == 'SAMLUser':
                            identity = user_identity_username
                        elif user_identity_type == 'AWSAccount':
                            identity = user_identity_accountid
                        elif user_identity_type == 'WebIdentityUser':
                            identity = user_identity_username
                        elif user_identity_type == 'FederatedUser':
                            identity = user_identity_principalid[user_identity_principalid.find(':') + 1:]
                        elif user_identity_type == 'Root':
                            identity = 'Root'

                        if identity is None or identity == '' or user_identity_type is None or user_identity_type == '':
                            continue
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

                        timespan.append({'user_identity_type': user_identity_type, 'requesters_identity': identity})
                        driver_session.execute_write(neo_db.create_or_update_node,
                                                     label=user_identity_type,
                                                     identity=identity,
                                                     user_identity_type=user_identity_type)

                    if 'NextToken' in response:
                        is_truncated = True
                    else:
                        is_truncated = False
            return timespan
        except ClientError as err:
            logger.critical("#0005 - " + str(err))
            exit(1)

        except Exception as e:
            logger.critical(e)
            logger.critical("#0005 - " + str(e))
            exit(1)

    def add_relationships_of_credentials(self):
        logger.debug("[+] Starting get_all_relationship_of_credentials.")

        def check_long_term_access_key_status(userName, accessKey):
            status = 'Deleted'
            try:
                accessKeys = get_access_key_of_user(session=self.session, userName=userName)
                for key in accessKeys:
                    if key['AccessKeyId'] == accessKey:
                        status = key['Status']
                        break
            except Exception as exp:
                return 'NotFound'
            return status

        try:
            added_users = {}
            timespan = []
            start_time = datetime.utcnow() - timedelta(days=self.timespan_timespan['days'], hours=self.timespan_timespan['hours'], minutes=self.timespan_timespan['minutes'])
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
                                        eventsource not like '%kms%'
                                        and errorcode is NULL
                                        and eventname IN ('GetSessionToken', 'AssumeRole', 'AssumeRoleWithWebIdentity', 'GetFederationToken', 'AssumeRoleWithSAML', 'CreateAccessKey')
                                        and eventtime > '{event_time}'
                                        ORDER BY eventtime ASC""".format(event_time=datetime_object)

            query_response = self.athena_client.start_query_execution(QueryString=sql_query,
                                                                      ResultConfiguration={'OutputLocation': f's3://{self.bucket_name}/CredentialMapper/'},
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
                    requesters_identity = ''

                    if user_identity_type == 'IAMUser':
                        requesters_identity = user_identity_accesskeyid
                    elif user_identity_type == 'AWSService':
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
                                requesters_identity = requesters_identity + ':' + json.loads(data['request_parameters'])['roleSessionName']
                        timestamp = datetime.strptime(data['event_time'], '%Y-%m-%dT%H:%M:%SZ').strftime('%b %d, %Y, %I:%M:%S %p')
                        credential = {'user_identity_type': user_identity_type,
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
                                      }
                        self.add_credential_to_neo4j(credential)

                    else:
                        created_access_key = json.loads(data['created_access_key'])
                        timestamp = datetime.strptime(data['event_time'], '%Y-%m-%dT%H:%M:%SZ').strftime('%b %d, %Y, %I:%M:%S %p')
                        user = get_user(session=self.session, username=created_access_key['userName'])
                        arn = user['Arn'] if user is True else ''
                        user_id = user['user_id'] if user is True else ''
                        credential = {'user_identity_type': user_identity_type,
                                      'requesters_identity': requesters_identity,
                                      'access_key_id': created_access_key['accessKeyId'],
                                      'requested_for': created_access_key['userName'],
                                      'requested_users_arn': arn,
                                      'requested_users_id': user_id,
                                      'event_time': timestamp,
                                      'source_ip_address': data['source_ip_address'],
                                      'is_active': check_long_term_access_key_status(created_access_key['userName'], created_access_key['accessKeyId']),
                                      'event_id': data['event_id'],
                                      'event_name': data['event_name']
                                      }
                        self.add_credential_to_neo4j(credential)

                        if created_access_key['userName'] not in added_users:
                            added_users[created_access_key['userName']] = []
                        added_users[created_access_key['userName']].append(created_access_key['accessKeyId'])
                if 'NextToken' in response:
                    is_truncated = True
                else:
                    is_truncated = False

            for user in self.users:
                access_keys = get_access_key_of_user(session=self.session, userName=user['UserName'])
                for access_key in access_keys:
                    if user['UserName'] not in added_users or access_key not in added_users[user['UserName']]:
                        credential = {'user_identity_type': 'Unknown',
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
                                      }
                        self.add_credential_to_neo4j(credential)

                        if user['UserName'] not in added_users:
                            added_users[user['UserName']] = []
                        added_users[user['UserName']].append(access_key)

            return timespan
        except ClientError as err:
            logger.critical("#0004 - " + str(err))
            exit(1)
        except Exception as e:
            logger.critical("#0004 - " + str(e))
            exit(1)

    def collect_and_add_unregistered_credentials(self):
        """
        Some credentials don't have logs, but they are inside the other logs, so we can crawl them all.
        :return:
        """
        print("Find the information from other logs")
        #

    def collect_and_fix_ownerless_credentials(self):
        """
        Some credentials have no creation log. Therefore, even if we add them to the db, information about them is still missing.
        For AssumedRole get ???
        For IAMAccessKeyId get username
        :return:
        """
        ownerless_access_keys = self.neo4j_controller.execute_neo4j_cypher('''MATCH (n:IAMAccessKeyId) WHERE NOT EXISTS(()-->(n)) RETURN n''')
        ownerless_assume_roles = self.neo4j_controller.execute_neo4j_cypher('''MATCH (n:AssumedRole) WHERE NOT EXISTS(()-->(n)) RETURN n''')  # and EXISTS((n)-->())
        ownerless_access_key_identities = []
        ownerless_assume_role_identities = []
        for node in ownerless_access_keys:
            ownerless_access_key_identities.append(node['n']['identity'])
        for node in ownerless_assume_roles:
            ownerless_assume_role_identities.append(node['n']['identity'])

        try:
            with self.neo4j_controller.driver.session() as driver_session:
                if len(ownerless_access_key_identities) > 0:
                    sql_query = """
                        SELECT useridentity.accesskeyid,
                               MAX(useridentity.arn) as max_arn,
                               MAX(useridentity.principalid) as max_principalid,
                               MAX(useridentity.username) as max_username
                        FROM CredentialMapper
                        WHERE useridentity.accesskeyid in {identities}
                        GROUP BY useridentity.accesskeyid
                        """.format(identities=tuple(ownerless_access_key_identities))

                    query_response = self.athena_client.start_query_execution(QueryString=sql_query,
                                                                              ResultConfiguration={'OutputLocation': f's3://{self.bucket_name}/CredentialMapper/'},
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

                        for trail in response['ResultSet']['Rows']:
                            if first:
                                first = False
                                continue

                            data = {
                                'access_key_id': trail['Data'][0]['VarCharValue'] if 'VarCharValue' in trail['Data'][0] else '',
                                'arn': trail['Data'][1]['VarCharValue'] if 'VarCharValue' in trail['Data'][1] else '',
                                'principal_id': trail['Data'][2]['VarCharValue'] if 'VarCharValue' in trail['Data'][2] else '',
                                'username': trail['Data'][3]['VarCharValue'] if 'VarCharValue' in trail['Data'][3] else '',
                            }
                            user_identity_principal_id = data['principal_id']
                            user_identity_arn = data['arn']
                            user_identity_username = data['username']
                            user_access_key_id = data['access_key_id']

                            owner_node = driver_session.execute_write(self.neo4j_controller.create_or_update_node,
                                                                      label='IAMUser',
                                                                      identity=user_identity_username,
                                                                      user_identity_type='IAMUser',
                                                                      user_id=user_identity_principal_id,
                                                                      user_arn=user_identity_arn
                                                                      )
                            access_key_node = driver_session.execute_write(self.neo4j_controller.create_or_update_node,
                                                                           label='IAMAccessKeyId',
                                                                           identity=user_access_key_id,
                                                                           user_identity_type='IAMAccessKeyId'
                                                                           )

                            driver_session.write_transaction(self.neo4j_controller.create_or_merge_relationship,
                                                             owner_node,
                                                             'Owns',
                                                             access_key_node
                                                             )

                        if 'NextToken' in response:
                            is_truncated = True
                        else:
                            is_truncated = False

                if len(ownerless_assume_role_identities) > 0:
                    sql_query = """
                        SELECT useridentity.accesskeyid,
                               MAX(useridentity.arn) as max_arn,
                               MAX(useridentity.principalid) as max_principalid
                        FROM CredentialMapper
                        WHERE useridentity.accesskeyid in {identities}
                        GROUP BY useridentity.accesskeyid
                        """.format(identities=tuple(ownerless_assume_role_identities))

                    query_response = self.athena_client.start_query_execution(QueryString=sql_query,
                                                                              ResultConfiguration={'OutputLocation': f's3://{self.bucket_name}/CredentialMapper/'},
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

                        for trail in response['ResultSet']['Rows']:
                            if first:
                                first = False
                                continue

                            data = {
                                'access_key_id': trail['Data'][0]['VarCharValue'] if 'VarCharValue' in trail['Data'][0] else '',
                                'arn': trail['Data'][1]['VarCharValue'] if 'VarCharValue' in trail['Data'][1] else '',
                                'principal_id': trail['Data'][2]['VarCharValue'] if 'VarCharValue' in trail['Data'][2] else ''
                            }
                            user_identity_principal_id = data['principal_id']
                            user_identity_arn = data['arn']
                            user_access_key_id = data['access_key_id']

                            if user_identity_principal_id is not None and ':' in user_identity_principal_id:
                                owners_identity = user_identity_principal_id[user_identity_principal_id.find(':') + 1:]
                            elif user_identity_arn is not None:
                                owners_identity = user_identity_arn[user_identity_arn.rfind('/') + 1:]
                            else:
                                continue
                            if str(owners_identity).startswith('i-'):
                                owner_node = driver_session.execute_write(self.neo4j_controller.create_or_update_node,
                                                                          label='Instance',
                                                                          identity=owners_identity,
                                                                          user_identity_type='Instance'
                                                                          )
                            else:
                                owner_node = self.neo4j_controller.get_node_by_identity(identity=owners_identity)

                            ownerless_assumed_role = self.neo4j_controller.get_node_by_identity(identity=user_access_key_id)
                            if owner_node is not None and ownerless_assumed_role is not None:
                                driver_session.write_transaction(self.neo4j_controller.create_or_merge_relationship,
                                                                 owner_node,
                                                                 'Owns',
                                                                 ownerless_assumed_role
                                                                 )
                        if 'NextToken' in response:
                            is_truncated = True
                        else:
                            is_truncated = False
        except ClientError as err:
            logger.critical(err)
            exit(1)
        except Exception as e:
            logger.critical(e)
            exit(1)

    def add_credential_to_neo4j(self, crawled_credential):
        with self.neo4j_controller.driver.session() as session:
            if crawled_credential['event_name'] == 'CreateAccessKey':
                # Credential Start Node
                start_node = session.write_transaction(self.neo4j_controller.create_or_update_node,
                                                       label='IAMUser',
                                                       identity=crawled_credential['requested_for'],
                                                       user_identity_type='IAMUser',
                                                       user_arn=crawled_credential['requested_users_arn'],
                                                       user_id=crawled_credential['requested_users_id'])

                # Credential End Node
                end_node = session.write_transaction(self.neo4j_controller.create_or_update_node,
                                                     label='IAMAccessKeyId',
                                                     identity=crawled_credential['access_key_id'],
                                                     user_identity_type='IAMAccessKeyId',
                                                     is_active=crawled_credential['is_active'])

                # Create Relationship
                session.write_transaction(self.neo4j_controller.create_or_merge_relationship,
                                          start_node,
                                          crawled_credential['event_name'],
                                          end_node,
                                          source_ip_address=crawled_credential['source_ip_address'],
                                          event_id=crawled_credential['event_id'],
                                          event_name=crawled_credential['event_name'],
                                          event_time=crawled_credential['event_time'],
                                          requesters_identity=crawled_credential['requesters_identity'])
            else:
                # Handle ASSUME ROLE
                if crawled_credential['user_identity_type'] == 'FederatedUser':
                    service_name, requesters_identity = crawled_credential['requesters_identity'].split(':', 1)
                    start_node = session.write_transaction(self.neo4j_controller.create_or_update_node,
                                                           label=crawled_credential['user_identity_type'],
                                                           identity=requesters_identity,
                                                           user_identity_type=crawled_credential['user_identity_type'],
                                                           service_name=service_name)
                else:
                    node_label = 'IAMAccessKeyId' if crawled_credential['requesters_identity'].startswith('AKIA') else crawled_credential['user_identity_type']
                    user_identity_type = 'IAMAccessKeyId' if crawled_credential['requesters_identity'].startswith('AKIA') else crawled_credential['user_identity_type']

                    start_node = session.write_transaction(self.neo4j_controller.create_or_update_node,
                                                           label=node_label,
                                                           identity=crawled_credential['requesters_identity'],
                                                           user_identity_type=user_identity_type)

                end_node = session.write_transaction(self.neo4j_controller.create_or_update_node,
                                                     label='AssumedRole',
                                                     identity=crawled_credential['access_key_id'],
                                                     user_identity_type='AssumedRole',
                                                     access_key_id=crawled_credential['access_key_id'],
                                                     expiration_time=crawled_credential['expiration_time'],
                                                     assumed_role_arn=crawled_credential['assumed_role_arn'],
                                                     requested_role=crawled_credential['requested_role'],
                                                     is_active=crawled_credential['is_active'])

                session.write_transaction(self.neo4j_controller.create_or_merge_relationship,
                                          start_node,
                                          crawled_credential['event_name'],
                                          end_node,
                                          source_ip_address=crawled_credential['source_ip_address'],
                                          event_id=crawled_credential['event_id'],
                                          event_name=crawled_credential['event_name'],
                                          event_time=crawled_credential['event_time'])

                if crawled_credential['event_name'] == 'GetFederationToken':
                    requested_suspicious_node = session.write_transaction(self.neo4j_controller.create_or_update_node,
                                                                          label='RequestedNode',
                                                                          identity=crawled_credential['requested_role'])

                    session.write_transaction(self.neo4j_controller.create_or_merge_relationship,
                                              end_node,
                                              'FederationRoleRequest',
                                              requested_suspicious_node,
                                              source_ip_address=crawled_credential['source_ip_address'],
                                              event_id=crawled_credential['event_id'],
                                              event_name=crawled_credential['event_name'],
                                              event_time=crawled_credential['event_time'])

    def add_console_login_of_iam_credentials_to_neo4j(self, console_login_data_list):
        with self.neo4j_controller.driver.session() as session:
            for console_login_data in console_login_data_list:
                # Credential Start Node
                start_node = self.neo4j_controller.create_or_update_node(
                    session,
                    label='IAMUser',
                    identity=console_login_data['requesters_identity_username'],
                    user_identity_type='IAMUser',
                    user_arn=console_login_data['requesters_identity_arn'],
                    user_id=console_login_data['requesters_identity_principalid']
                )

                # Credential End Node
                end_node = self.neo4j_controller.create_or_update_node(
                    session,
                    label=console_login_data['user_identity_type'],
                    identity=console_login_data['user_identity_principalid'][console_login_data['user_identity_principalid'].find(':') + 1:],
                    user_identity_type=console_login_data['user_identity_type'],
                    user_arn=console_login_data['user_identity_arn'],
                    principal_id=console_login_data['user_identity_principalid'],
                    account_id=console_login_data['user_identity_accountid']
                )

                # Create Relationship
                session.write_transaction(self.neo4j_controller.create_without_merge_relationship,
                                          start_node,
                                          'SuspiciousConsoleLogin',
                                          end_node,
                                          source_ip_address=console_login_data['source_ip_address'],
                                          event_id=console_login_data['event_id'],
                                          event_name=console_login_data['event_name'],
                                          event_time=console_login_data['event_time']
                                          )

    def add_anomalies_to_the_neo4j(self, anomalies):
        """
        For now, I'm connecting all nodes to itself.
        :param anomalies:
        :return:
        """
        with self.neo4j_controller.driver.session() as session:
            for anomaly in anomalies:
                node = self.neo4j_controller.get_node_by_identity(anomaly['identity'])
                if node is not None:
                    session.write_transaction(self.neo4j_controller.create_without_merge_relationship,
                                              node,
                                              'Suspicious' + anomaly['event_name'] + 'Request',
                                              node,
                                              anomaly_description=anomaly['anomaly_description'],
                                              anomaly_severity=anomaly['anomaly_severity'],
                                              event_name=anomaly['event_name'],
                                              source_ip_address=anomaly['source_ip_address'],
                                              useragent=anomaly['useragent'],
                                              event_time=anomaly['event_time'],
                                              event_id=anomaly['event_id']
                                              )

    def add_role_juggling_attack_to_the_neo4j(self, role_juggling_paths):

        with self.neo4j_controller.driver.session() as session:
            for role_juggling_path in role_juggling_paths:
                node = self.neo4j_controller.get_node_by_identity(role_juggling_path['attack_owner'])
                session.write_transaction(self.neo4j_controller.create_without_merge_relationship,
                                          node,
                                          'SuspiciousRoleChainJugglingOnChildPath',
                                          node,
                                          attack_owner=role_juggling_path['attack_owner'],
                                          attack_start_node=role_juggling_path['attack_start_node'],
                                          attack_end_node=role_juggling_path['attack_end_node'],
                                          pattern=role_juggling_path['pattern'],
                                          start_index=role_juggling_path['start_index'],
                                          end_index=role_juggling_path['end_index']
                                          )
