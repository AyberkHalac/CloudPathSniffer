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
