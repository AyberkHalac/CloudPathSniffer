import os

import boto3
from botocore.exceptions import ClientError

from helpers.logger import setup_logger

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(os.path.join(ROOT_DIR, '..', 'logs'), 'CredentialMapper.log')

logger = setup_logger(logger_name='boto3_helper', filename=LOG_FILE_PATH)


def create_boto3_session(aws_profile_name=None, aws_access_key_id=None, aws_secret_access_key=None, aws_session_token=None) -> boto3.Session:
    try:
        if aws_profile_name is not None:
            return boto3.Session(profile_name=aws_profile_name)
        elif aws_access_key_id is not None and aws_secret_access_key is not None:
            if aws_session_token is not None:
                return boto3.Session(aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
            else:
                return boto3.Session(aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
        else:
            raise ClientError  # type: ignore
    except ClientError as client_error:
        logger.error(client_error)
        return client_error  # type: ignore
    except Exception as e:
        logger.error(e)
        return e  # type: ignore


def heartbeat(aws_profile_name, aws_access_key_id, aws_secret_access_key, aws_session_token):
    try:
        aws_profile_name = None if aws_profile_name == '' else aws_profile_name
        aws_access_key_id = None if aws_access_key_id == '' else aws_access_key_id
        aws_secret_access_key = None if aws_secret_access_key == '' else aws_secret_access_key
        aws_session_token = None if aws_session_token == '' else aws_session_token

        session = create_boto3_session(aws_profile_name=aws_profile_name, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
        if type(boto3.Session()) != type(session):
            return False
        iam_client = session.client('iam')
        result = iam_client.list_users(MaxItems=1)
        return True
    except ClientError as err:
        if err.response['Error']['Code'] == 'AccessDenied':
            logger.error(err)
            return True
        logger.error(err)
        return False
    except Exception as e:
        logger.error(e)
        return False


def describe_instances_all_regions(session):
    instances = []
    regions = []

    try:
        describe_regions_result = session.client('ec2').describe_regions()
        for region in describe_regions_result['Regions']:
            regions.append(region['RegionName'])
    except Exception as e:
        logger.error('Getting error while taking region names:' + str(e))
        return []

    for region in regions:
        response = {}
        is_truncated = False
        try:
            ec2_client = session

            while len(response.keys()) == 0 or is_truncated:
                if is_truncated is False:
                    response = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
                else:
                    response = ec2_client.describe_instances(NextToken=response['NextToken'], Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        if 'PublicIpAddress' in instance:
                            instances.append({'InstanceId': instance['InstanceId'], 'PublicIpAddress': instance['PublicIpAddress']})

                is_truncated = True if 'NextToken' in response else False
        except Exception as e:
            logger.error(e)

    return instances


def describe_instances(session, region='us-east-1'):
    instances = []
    response = {}
    is_truncated = False
    try:
        ec2_client = session.client(service_name='ec2', region_name=region)

        while len(response.keys()) == 0 or is_truncated:
            if is_truncated is False:
                response = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
            else:
                response = ec2_client.describe_instances(NextToken=response['NextToken'], Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    if 'PublicIpAddress' in instance:
                        instances.append({'InstanceId': instance['InstanceId'], 'PublicIpAddress': instance['PublicIpAddress']})

            is_truncated = True if 'NextToken' in response else False
    except Exception as e:
        logger.error(e)

    return instances


def get_access_key_of_user(session: boto3.Session, userName):
    access_keys = []

    try:
        iam_client = session.client('iam')
        paginator = iam_client.get_paginator('list_access_keys')
        response_iterator = paginator.paginate(UserName=userName, PaginationConfig={'PageSize': 50})
        for iteration_page in response_iterator:
            for access_key in iteration_page['AccessKeyMetadata']:
                access_keys.append(access_key)
        return access_keys
    except Exception as e:
        logger.debug('#0001 - ' + str(e) + ' - username:' + userName)
        return []


def list_users(session: boto3.Session):
    users = []

    try:
        iam_client = session.client('iam')
        paginator = iam_client.get_paginator('list_users')
        response_iterator = paginator.paginate(PaginationConfig={'PageSize': 50})
        for iteration_page in response_iterator:
            for user in iteration_page['Users']:
                users.append(user)
        return users
    except Exception as e:
        logger.critical(e)
        raise


def get_user(session: boto3.Session, username):
    try:
        iam_client = session.client('iam')
        user = iam_client.get_user(UserName=username)
        return user['User']
    except ClientError as e:
        logger.debug('#0002 - ' + str(e) + ' - username:' + username)
        return False


def get_long_term_credentials(session: boto3.Session):
    try:
        long_term_credentials = []
        users = list_users(session)
        for user in users:
            username = user['UserName']
            access_keys = get_access_key_of_user(session, username)
            for access_key in access_keys:
                long_term_credentials.append({'username': access_key['UserName'],
                                              'access_key_id': access_key['AccessKeyId'],
                                              'is_active': access_key['Status'],
                                              'create_date': access_key['CreateDate']
                                              })
        return long_term_credentials
    except ClientError as err:
        logger.critical(err)
        return False
    except Exception as e:
        logger.critical(e)
        return False
