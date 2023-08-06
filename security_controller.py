import ipaddress
import os
import time
from datetime import datetime, timedelta

import boto3
import requests
from botocore.exceptions import ClientError

from helpers.boto3_helpers import describe_instances
from helpers.logger import setup_logger

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


def check_exposed_ec2_temporary_credentials(session: boto3.Session, bucket_name, region='us-east-1'):
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

    instance_list = describe_instances(session=session, region=region)

    athena_client = session.client('athena', region_name=region)
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

            query_response = athena_client.start_query_execution(QueryString=sql_query,
                                                                 ResultConfiguration={'OutputLocation': f's3://{bucket_name}/CredentialMapper/'},
                                                                 QueryExecutionContext={'Database': 'CredentialMapper'}
                                                                 )
            query_execution_id = query_response['QueryExecutionId']

            query_response = athena_client.get_query_execution(
                QueryExecutionId=query_execution_id
            )
            ready_state = query_response['QueryExecution']['Status']['State']

            timeout = 600
            while ready_state != 'SUCCEEDED' and timeout > 0:
                query_response = athena_client.get_query_execution(
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
                    response = athena_client.get_query_results(
                        QueryExecutionId=query_execution_id,
                        MaxResults=50
                    )
                else:
                    response = athena_client.get_query_results(
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

            query_response = athena_client.start_query_execution(QueryString=sql_query,
                                                                 ResultConfiguration={'OutputLocation': f's3://{bucket_name}/CredentialMapper/'},
                                                                 QueryExecutionContext={'Database': 'CredentialMapper'}
                                                                 )
            query_execution_id = query_response['QueryExecutionId']

            query_response = athena_client.get_query_execution(
                QueryExecutionId=query_execution_id
            )
            ready_state = query_response['QueryExecution']['Status']['State']

            timeout = 600
            while ready_state != 'SUCCEEDED' and timeout > 0:
                query_response = athena_client.get_query_execution(
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
                    response = athena_client.get_query_results(
                        QueryExecutionId=query_execution_id,
                        MaxResults=50
                    )
                else:
                    response = athena_client.get_query_results(
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


def check_exposed_ec2_temporary_credentials_with_aws_ips(session: boto3.Session, bucket_name, region='us-east-1'):
    """
    This function analyzes instances to see if their initial credentials are used outside of the instance.

    BUG: Burada AWS dışı iplerden kullanılmış mı diye bir kontrol yapıyoruz fakat saldırgan credentialı alıp Aws içerisinde bir EC2 dan kullanırsa bunu kaçırabiliriz buna bir çözüm bulunması gerekiyor.
    Ayrıca burada şöyle bir sorun da var, instance ip adresleri değiştiği için burada ayrı bir modül yapılıp bakılan instance credentialının kullanıldıgı service in tüm geçmiş verilerine bakılması gerekiyor.
    Ayrıca bu bir instance da olmayabilir. Container da olabilir ondan düzeltilmesi gerekiyor.


    :return: dictionary of instance(str):event(array) couple.
    """
    athena_client = session.client('athena', region_name=region)

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

        query_response = athena_client.start_query_execution(QueryString=sql_query,
                                                             ResultConfiguration={'OutputLocation': f's3://{bucket_name}/CredentialMapper/'},
                                                             QueryExecutionContext={'Database': 'CredentialMapper'}
                                                             )
        query_execution_id = query_response['QueryExecutionId']

        query_response = athena_client.get_query_execution(
            QueryExecutionId=query_execution_id
        )
        ready_state = query_response['QueryExecution']['Status']['State']

        timeout = 600
        while ready_state != 'SUCCEEDED' and timeout > 0:
            query_response = athena_client.get_query_execution(
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
                response = athena_client.get_query_results(
                    QueryExecutionId=query_execution_id,
                    MaxResults=50
                )
            else:
                response = athena_client.get_query_results(
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


def check_logs_for_blacklisted_ip_accesses(session: boto3.Session, bucket_name, region='us-east-1'):
    try:
        athena_client = session.client('athena', region_name=region)
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

        query_response = athena_client.start_query_execution(QueryString=sql_query,
                                                             ResultConfiguration={'OutputLocation': f's3://{bucket_name}/CredentialMapper/'},
                                                             QueryExecutionContext={'Database': 'CredentialMapper'}
                                                             )
        query_execution_id = query_response['QueryExecutionId']

        query_response = athena_client.get_query_execution(
            QueryExecutionId=query_execution_id
        )
        ready_state = query_response['QueryExecution']['Status']['State']

        timeout = 600
        while ready_state != 'SUCCEEDED' and timeout > 0:
            query_response = athena_client.get_query_execution(
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
                response = athena_client.get_query_results(
                    QueryExecutionId=query_execution_id,
                    MaxResults=50
                )
            else:
                response = athena_client.get_query_results(
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


def role_juggling_long_repeating_pattern(input_list):
    """
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



    :param input_list:
    :return:
    """

    print()
