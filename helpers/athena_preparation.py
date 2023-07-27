import os
import time

from botocore.exceptions import ClientError

from helpers.logger import setup_logger

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(os.path.join(ROOT_DIR, '..', 'logs'), 'CredentialMapper.log')


logger = setup_logger(logger_name='athena_preparation', filename=LOG_FILE_PATH)


def prepare_athena(athena_client, bucket_name):
    try:
        athena_client.start_query_execution(
            QueryString='DROP TABLE CredentialMapper',
            ResultConfiguration={'OutputLocation': f's3://{bucket_name}/CredentialMapper/'},
            QueryExecutionContext={
                'Database': 'CredentialMapper',
            }
        )
        time.sleep(5)
        athena_client.start_query_execution(
            QueryString='DROP DATABASE CredentialMapper',
            ResultConfiguration={'OutputLocation': f's3://{bucket_name}/CredentialMapper/'},
            QueryExecutionContext={
                'Database': 'CredentialMapper',
            }
        )
        time.sleep(5)

        athena_client.start_query_execution(
            QueryString='CREATE DATABASE CredentialMapper',
            ResultConfiguration={'OutputLocation': f's3://{bucket_name}/CredentialMapper/'})
        time.sleep(5)

        query_response = athena_client.start_query_execution(
            QueryString=f'''
        CREATE EXTERNAL TABLE CredentialMapper (
            eventVersion STRING,
            userIdentity STRUCT<
                type: STRING,
                principalId: STRING,
                arn: STRING,
                accountId: STRING,
                invokedBy: STRING,
                accessKeyId: STRING,
                userName: STRING,
                sessionContext: STRUCT<
                    attributes: STRUCT<
                        mfaAuthenticated: STRING,
                        creationDate: STRING>,
                    sessionIssuer: STRUCT<
                        type: STRING,
                        principalId: STRING,
                        arn: STRING,
                        accountId: STRING,
                        username: STRING>,
                    ec2RoleDelivery: STRING,
                    webIdFederationData: MAP<STRING,STRING>>>,
            eventTime STRING,
            eventSource STRING,
            eventName STRING,
            awsRegion STRING,
            sourceIpAddress STRING,
            userAgent STRING,
            errorCode STRING,
            errorMessage STRING,
            requestParameters STRING,
            responseElements STRING,
            additionalEventData STRING,
            requestId STRING,
            eventId STRING,
            resources ARRAY<STRUCT<
                arn: STRING,
                accountId: STRING,
                type: STRING>>,
            eventType STRING,
            apiVersion STRING,
            readOnly STRING,
            recipientAccountId STRING,
            serviceEventDetails STRING,
            sharedEventID STRING,
            vpcEndpointId STRING,
            tlsDetails STRUCT<
                tlsVersion: STRING,
                cipherSuite: STRING,
                clientProvidedHostHeader: STRING>
        )
        COMMENT 'CredentialMapper'
        ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
        STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
        OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
        LOCATION 's3://{bucket_name}/AWSLogs/568541058488/CloudTrail/'
        TBLPROPERTIES ('classification'='cloudtrail');
            ''',
            ResultConfiguration={'OutputLocation': f's3://{bucket_name}/CredentialMapper/'},
            QueryExecutionContext={
                'Database': 'CredentialMapper',
            })

        query_execution_id = query_response['QueryExecutionId']
        query_response = athena_client.get_query_execution(
            QueryExecutionId=query_execution_id
        )
        ready_state = query_response['QueryExecution']['Status']['State']

        timeout = 600
        while ready_state != 'SUCCEEDED' and timeout > 0:
            if ready_state == 'FAILED':
                return False
            query_response = athena_client.get_query_execution(
                QueryExecutionId=query_execution_id
            )
            ready_state = query_response['QueryExecution']['Status']['State']
            time.sleep(2)
            timeout -= 2
            if timeout <= 0:
                raise ClientError

    except ClientError as err:
        logger.critical(err)
        return False
    except Exception as e:
        logger.critical(e)
        return False


def get_query_results(athena_client, query_execution_id):
    query_response = athena_client.get_query_execution(
        QueryExecutionId=query_execution_id
    )
    ready_state = query_response['QueryExecution']['Status']['State']

    timeout = 100
    while ready_state != 'SUCCEEDED' and timeout > 0:
        query_response = athena_client.get_query_execution(
            QueryExecutionId=query_execution_id
        )
        ready_state = query_response['QueryExecution']['Status']['State']
        time.sleep(2)
        timeout -= 2
        if timeout <= 0:
            raise ClientError

    logs = []
    response = {}
    is_truncated = False

    try:

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
            logs.extend(response['ResultSet']['Rows'])
            if 'NextToken' in response:
                is_truncated = True
            else:
                is_truncated = False
        return logs
    except ClientError as err:
        logger.critical(err)
        raise
    except Exception as e:
        logger.critical(e)
        raise
