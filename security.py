import ipaddress
import json
import os
import time
from datetime import datetime, timedelta

import boto3
import requests
from botocore.exceptions import ClientError

from helpers.boto3_helpers import describe_instances
from helpers.config_reader import get_config_file
from helpers.logger import setup_logger
from helpers.repository import Neo4jDatabase

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(os.path.join(ROOT_DIR, 'logs'), 'CredentialMapper.log')

logger = setup_logger(logger_name='security_controller', filename=LOG_FILE_PATH)

aws_public_ip_ranges = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json').json()['prefixes']


def is_ip_in_ec2_range(ip_address):
    is_aws_ip = False
    for ip_range_struct in aws_public_ip_ranges:
        if 'ip_prefix' in ip_range_struct and ip_range_struct['service'] == 'EC2':
            try:
                if ipaddress.ip_address(ip_address) in ipaddress.ip_network(ip_range_struct['ip_prefix']):
                    is_aws_ip = True
                    break
            except ValueError as e:
                logger.critical(e)
                return True
    return is_aws_ip


class Security:

    def __init__(self, session: boto3.Session, region: str):
        self.session = session
        self.region = region
        self.athena_client = self.session.client(service_name='athena', region_name=self.region)
        self.neo4j_controller = Neo4jDatabase()
        try:
            config = get_config_file('./config.yaml')
            self.all_temporary_credentials_timespan = config['all_temporary_credentials']
        except Exception as e:
            logger.critical('[!] Getting error reading config file', str(e))
            return

        self.bucket_name = config['bucket_name']
        self.region = region

    def detect_role_juggling_long_repeating_patterns(self):
        """
        This needs a lot of tests for sure :)


        Example input output:
        I1 - [1,2,3,1,2,3,1,2,3]
        O1 - Longest repeating list: [1,2,3,1,2,3,1,2,3] repeating element: [1,2,3] start-end index:(0,8)

        I2 - [1,2,3,4,1,2,3,4,1,2,3,4]
        O2 - Longest repeating list: [1,2,3,4,1,2,3,4,1,2,3,4] repeating element: [1,2,3,4] start-end index:(0,11)

        Repeating list can be 3-n size and has to repeat at least min 2 times

        I3 - [1,2,3,5,1,2,3,6,1,2,3]
        O3 - Longest repeating list: [] repeating element: [] start-end index:(0,0)

        - The repeating sub-lists' length should be bigger than 3
        - Repeat time has to be more than 1

        So,
        Example input output:
        I1 - [1,2,3,1,2,3]
        O1 - Longest repeating list: [] repeating element: [] start-end index:(0,0)  -> Because it repeats only 1 times


        :return:
        """

        def find_repeating_pattern_info(arr):
            pattern_length = 2  # Minimum pattern length to consider
            n = len(arr)
            start_index = 0
            end_index = 0
            for pattern_length in range(2, len(arr) // 2 + 1):
                for i in range(n - 2 * pattern_length + 1):
                    pattern = arr[i:i + pattern_length]
                    cycle_count = 0

                    for j in range(i + pattern_length, n - pattern_length + 1, pattern_length):
                        if arr[j:j + pattern_length] == pattern:
                            cycle_count += 1
                            start_index = i
                            end_index = j + pattern_length - 1
                        else:
                            break

                    if cycle_count >= 2:
                        return pattern, start_index, end_index

            return None, None, None

        longest_unique_paths = self.find_longest_unique_paths()

        array_of_identity_list = []
        for path in longest_unique_paths:
            identity_list = []
            for node in path['p']:
                if 'user_identity_type' not in node:
                    continue
                if node['user_identity_type'] == 'AssumedRole':
                    identity_list.append(node['requested_role'])
                else:
                    identity_list.append(node['identity'])

            array_of_identity_list.append(identity_list)

        pattern_list = []
        for identity_list in array_of_identity_list:
            pattern, start_index, end_index = find_repeating_pattern_info(identity_list)

            if pattern:
                print("Repeating Pattern:", ' -> '.join(pattern))
                print("Start Index:", start_index)
                print("End Index:", end_index)
                pattern_list.append({'pattern': pattern, 'start_index': start_index, 'end_index': end_index})

        return pattern_list

    def find_longest_unique_paths(self):
        # This query gives the longest unique paths
        possible_role_juggling_paths = self.neo4j_controller.execute_neo4j_cypher('''MATCH p=(parent)-[r*]->(child)
                                                                    WHERE NOT EXISTS((child)-->())
                                                                        and NOT EXISTS(()-[:AssumeRole|CreateAccessKey]->(parent))
                                                                        and length(p)>6
                                                                    RETURN p
                                                                    ORDER BY length(p) DESC
                                                                    LIMIT 20''')
        return possible_role_juggling_paths

    def find_nodes_with_max_relationship(self, contains_service_accounts: False):
        """
        The nodes that have the most relationships are found using this method.
        :param contains_service_accounts:
        :return: Neo4j Nodes that has max relationship
        """

        if contains_service_accounts:
            nodes_with_max_relationship = self.neo4j_controller.execute_neo4j_cypher('''MATCH (n)
                                                                        WITH n, SIZE([(n)-[]-() | 1]) AS numRelationships
                                                                        WHERE numRelationships > 20
                                                                        RETURN n, numRelationships
                                                                        ORDER BY numRelationships DESC
                                                                        LIMIT 50;''')
        else:
            nodes_with_max_relationship = self.neo4j_controller.execute_neo4j_cypher('''MATCH (n)
                                                                        WHERE NOT n.identity CONTAINS "amazonaws.com"
                                                                        WITH n, SIZE([(n)-[]-() | 1]) AS numRelationships
                                                                        WHERE numRelationships > 10
                                                                        RETURN n, numRelationships
                                                                        ORDER BY numRelationships DESC
                                                                        LIMIT 50;''')

        return nodes_with_max_relationship

    def detect_exposed_ec2_temporary_credentials(self):
        """
        Technique 1-
        In this technique, we lost logs that are older than the creation of the current ip address.
        But still we can catch the malicious credential usage that are coming from another AWS account/AWS environment.
        (So attacker could take our credential and use it in their ec2 instance)

        In this module we check whether temporary instance credential used outside this instance or not.
        Which conditions change IP address of instance:
            1- Start / Launch
            2- Stop and Restart

        Event Names:
            1- ec2:RunInstances
            2- ec2:StartInstances
            3- ec2:AssociateAddress

        Problems:
            1- AWS does not log instances' public ip addresses.
            2- Because of 1. entry we cant get terminated or stopped instances' ip addresses.
            3- False positives if we cant catch the ip change
            4- If you change your IP too frequently, we might be unable to examine the extensive history because we are unable to access past IP addresses.


        Algorithm:
            1- Describe All Instances and collect current public IP addresses of them
            2- Build SQL query which calculate the timespan for that public ip address

        :return:
        """

        risky_requests_from_unsecure_ip = []

        instance_list = describe_instances(session=self.session, region=self.region)
        # find the last time the ip address changed

        for i in range(len(instance_list)):
            try:
                sql_query = """
                SELECT 
                    eventtime 
                FROM 
                    CredentialMapper 
                WHERE 
                    (eventname='RunInstances' or eventname='StartInstances' or eventname='AssociateAddress')
                     and errorcode IS NULL 
                     and responseelements like '%{InstanceId}%' 
                 ORDER BY 
                    eventtime 
                 DESC 
                 LIMIT 1""".format(InstanceId=instance_list[i]['InstanceId'])

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
                    if len(response['ResultSet']['Rows']) == 1:
                        start_time = datetime.utcnow() - timedelta(days=90)
                        datetime_object = datetime.strptime(str(start_time), "%Y-%m-%d %H:%M:%S.%f").strftime("%Y-%m-%dT%H:%M:%SZ")
                        instance_list[i]['datetime'] = datetime_object
                    else:
                        for trail in response['ResultSet']['Rows']:
                            if first:
                                first = False
                                continue
                            datetime_object = {'datetime': trail['Data'][0]['VarCharValue'] if 'VarCharValue' in trail['Data'][0] else ''}
                            instance_list[i]['datetime'] = datetime_object['datetime']
                    if 'NextToken' in response:
                        is_truncated = True
                    else:
                        is_truncated = False

            except Exception as e:
                logger.critical(e)

        # ----------------------------------------------------------------------------------------------------------------------------
        # If result is empty then we can set the timedelta to 90 days

        try:
            for instance in instance_list:
                sql_query = """
                            SELECT   
                                sourceipaddress, 
                                useridentity.accesskeyid, 
                                eventname,
                                eventtime,
                                eventid,
                                split_part(useridentity.principalId, ':', 2) as principal_id
                            FROM 
                                CredentialMapper 
                            WHERE
                                useridentity.principalid like '%:i-%'
                                and split_part(useridentity.principalid, ':', 2) = '{InstanceId}'
                                and sourceipaddress != '{PublicIpAddress}'
                                and eventtime > '{event_time}'
                            ORDER BY eventtime DESC""".format(InstanceId=instance['InstanceId'],
                                                              event_time=instance['datetime'],
                                                              PublicIpAddress=instance['PublicIpAddress'])

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
                    if len(response['ResultSet']['Rows']) == 1:
                        continue
                    for trail in response['ResultSet']['Rows']:
                        if first:
                            first = False
                            continue
                        data = {'source_ip_address': trail['Data'][0]['VarCharValue'] if 'VarCharValue' in trail['Data'][0] else '',
                                'access_key_id': trail['Data'][1]['VarCharValue'] if 'VarCharValue' in trail['Data'][1] else '',
                                'event_name': trail['Data'][2]['VarCharValue'] if 'VarCharValue' in trail['Data'][2] else '',
                                'event_time': trail['Data'][3]['VarCharValue'] if 'VarCharValue' in trail['Data'][3] else '',
                                'event_id': trail['Data'][4]['VarCharValue'] if 'VarCharValue' in trail['Data'][4] else '',
                                'principal_id': trail['Data'][5]['VarCharValue'] if 'VarCharValue' in trail['Data'][5] else '',
                                }
                        risky_requests_from_unsecure_ip.append(data)
                    if 'NextToken' in response:
                        is_truncated = True
                    else:
                        is_truncated = False

        except Exception as e:
            logger.error(e)
            print(e)
        return risky_requests_from_unsecure_ip

    def detect_exposed_ec2_temporary_credentials_with_aws_ips(self):
        """
        This function analyzes instances to see if their initial credentials are used outside of the instance.

        BUG: Burada AWS dışı iplerden kullanılmış mı diye bir kontrol yapıyoruz fakat saldırgan credentialı alıp Aws içerisinde bir EC2 dan kullanırsa bunu kaçırabiliriz buna bir çözüm bulunması gerekiyor.
        Ayrıca burada şöyle bir sorun da var, instance ip adresleri değiştiği için burada ayrı bir modül yapılıp bakılan instance credentialının kullanıldıgı service in tüm geçmiş verilerine bakılması gerekiyor.
        Ayrıca bu bir instance da olmayabilir. Container da olabilir ondan düzeltilmesi gerekiyor.


        :return: dictionary of instance(str):event(array) couple.
        """
        try:
            risky_requests_from_unsecure_ip = []

            start_time = datetime.utcnow() - timedelta(days=90, hours=0, minutes=0)
            datetime_object = datetime.strptime(str(start_time), "%Y-%m-%d %H:%M:%S.%f").strftime("%Y-%m-%dT%H:%M:%SZ")
            sql_query = """SELECT   sourceipaddress, 
                                    useridentity.accesskeyid, 
                                    eventname,
                                    eventtime,
                                    eventid,
                                    split_part(useridentity.principalId, ':', 2) as principal_id
                            FROM 
                                CredentialMapper 
                            WHERE 
                                useridentity.principalId like '%:i-%'
                                and eventtime > '{event_time}' 
                                ORDER BY eventtime DESC""".format(event_time=datetime_object)

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
                    data = {'source_ip_address': trail['Data'][0]['VarCharValue'] if 'VarCharValue' in trail['Data'][0] else '',
                            'access_key_id': trail['Data'][1]['VarCharValue'] if 'VarCharValue' in trail['Data'][1] else '',
                            'event_name': trail['Data'][2]['VarCharValue'] if 'VarCharValue' in trail['Data'][2] else '',
                            'event_time': trail['Data'][3]['VarCharValue'] if 'VarCharValue' in trail['Data'][3] else '',
                            'event_id': trail['Data'][4]['VarCharValue'] if 'VarCharValue' in trail['Data'][4] else '',
                            'principal_id': trail['Data'][5]['VarCharValue'] if 'VarCharValue' in trail['Data'][5] else '',
                            'description': 'EC2 credentials were used outside of the AWS IP range!'
                            }
                    if not is_ip_in_ec2_range(ip_address=data['source_ip_address']):
                        risky_requests_from_unsecure_ip.append(data)

                if 'NextToken' in response:
                    is_truncated = True
                else:
                    is_truncated = False

            return risky_requests_from_unsecure_ip

        except Exception as e:
            logger.critical(e)
            return []

    def detect_blacklisted_ip_accesses(self):
        try:
            blacklisted_trails = []
            blacklisted_ip_list = []
            blacklist_feed_url = 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt'
            blacklist_threshold = 6
            if not isinstance(blacklist_threshold, int) or blacklist_threshold < 1 or blacklist_threshold > 10:
                return []
            ip_document = requests.get(url=blacklist_feed_url).text
            for ip_line in ip_document.split('\n'):
                if ip_line[0] == '#':
                    continue
                if int(ip_line.split('\t')[1]) >= blacklist_threshold:
                    blacklisted_ip_list.append(ip_line.split('\t')[0])
                else:
                    break
            start_time = datetime.utcnow() - timedelta(days=1, hours=0, minutes=0)  # Check only today
            datetime_object = datetime.strptime(str(start_time), "%Y-%m-%d %H:%M:%S.%f").strftime("%Y-%m-%dT%H:%M:%SZ")
            sql_query = """SELECT  sourceipaddress, 
                                    useridentity.accesskeyid, 
                                    eventname,
                                    eventtime,
                                    eventid,
                                    split_part(useridentity.principalId, ':', 2) as principal_id
                            FROM CredentialMapper 
                            WHERE eventtime > '{event_time}'
                            and sourceipaddress in {blacklisted_ip_list}
                            ORDER BY eventtime DESC""".format(event_time=datetime_object, blacklisted_ip_list=tuple(blacklisted_ip_list))

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
                    raise ClientError  # type: ignore

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

                    data = {'source_ip_address': trail['Data'][0]['VarCharValue'] if 'VarCharValue' in trail['Data'][0] else '',
                            'access_key_id': trail['Data'][1]['VarCharValue'] if 'VarCharValue' in trail['Data'][1] else '',
                            'event_name': trail['Data'][2]['VarCharValue'] if 'VarCharValue' in trail['Data'][2] else '',
                            'event_time': trail['Data'][3]['VarCharValue'] if 'VarCharValue' in trail['Data'][3] else '',
                            'event_id': trail['Data'][4]['VarCharValue'] if 'VarCharValue' in trail['Data'][4] else '',
                            'principal_id': trail['Data'][5]['VarCharValue'] if 'VarCharValue' in trail['Data'][5] else '',
                            'description': 'CLI Requests from BlackListed IP Addresses!'
                            }
                    blacklisted_trails.append(data)
                if 'NextToken' in response:
                    is_truncated = True
                else:
                    is_truncated = False

        except ClientError as err:
            logger.critical(err)
            return []
        except Exception as e:
            logger.critical(e)
            return []

        return blacklisted_trails

    def detect_suspicious_console_login_of_iam_credentials(self):
        """
        https://github.com/Hacking-the-Cloud/hackingthe.cloud/blob/main/content/aws/post_exploitation/create_a_console_session_from_iam_credentials.md
        This function checks if the attacker get console access via iam credentials.
        This function is void and fills the neo4j database
        """
        console_logins = []

        start_time = datetime.utcnow() - timedelta(days=self.all_temporary_credentials_timespan['days'], hours=self.all_temporary_credentials_timespan['hours'], minutes=self.all_temporary_credentials_timespan['minutes'])
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

    def detect_unblocked_honey_token_activities(self):
        self._detect_honey_tokens()

    def _detect_honey_tokens(self):
        # TODO:
        """
        spacesiren:
        {
          "key": {
            "key_id": "59ee279b-941b-4312-89c4-35030caba89a",
            "secret_id": "LiNasGp5g8hgNo0GvebYnNyqLJ50bMqSLYe97jdjsWw=",
            "_etc": "etc."
          }
        }

        :return:
        """
        honey_tokens = []
        return honey_tokens