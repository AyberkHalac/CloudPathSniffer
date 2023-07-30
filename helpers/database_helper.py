import os

from neo4j import GraphDatabase
from py2neo import Graph, NodeMatcher, Node, Relationship

from helpers.logger import setup_logger

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(os.path.join(ROOT_DIR, '..', 'logs'), 'CredentialMapper.log')

logger = setup_logger(logger_name='database_helper', filename=LOG_FILE_PATH)


class Neo4jDatabase:

    def __init__(self, uri, username, password):
        self.graph = Graph(uri, auth=(username, password))
        self.driver = GraphDatabase.driver(uri, auth=(username, password))

    def neo4j_delete_all(self):
        self.graph.delete_all()

    def neo4j_bulk_add_credentials(self, credentials):

        def is_node_exist(identity):
            matcher = NodeMatcher(self.graph)
            _node = matcher.match(identity=identity).first()
            if _node is None:
                return False
            else:
                return _node

        for credential_relationship in credentials:

            if credential_relationship['event_name'] == 'CreateAccessKey':
                credential_center_node = is_node_exist(identity=credential_relationship['requested_for'])
                if credential_center_node is False:
                    credential_center_node = Node('IAMUser',
                                                  user_identity_type='IAMUser',
                                                  identity=credential_relationship['requested_for'],
                                                  user_arn=credential_relationship['requested_users_arn'],
                                                  user_id=credential_relationship['requested_users_id']
                                                  )
                    self.graph.create(credential_center_node)

                else:
                    credential_center_node['user_id'] = credential_relationship['requested_users_id']
                    credential_center_node['user_arn'] = credential_relationship['requested_users_arn']
                    self.graph.push(credential_center_node)

                credential_end_node = is_node_exist(identity=credential_relationship['access_key_id'])
                if credential_end_node is False:
                    credential_end_node = Node('IAMAccessKeyId',
                                               user_identity_type='IAMAccessKeyId',
                                               identity=credential_relationship['access_key_id'],
                                               is_active=credential_relationship['is_active'])
                    self.graph.create(credential_end_node)
                else:
                    # Remove Label
                    credential_end_node['is_active'] = credential_relationship['is_active']
                    credential_end_node['user_identity_type'] = 'IAMAccessKeyId'
                    self.graph.push(credential_end_node)

                self.graph.create(Relationship(credential_center_node,
                                               credential_relationship['event_name'],
                                               credential_end_node,
                                               source_ip_address=credential_relationship['source_ip_address'],
                                               event_id=credential_relationship['event_id'],
                                               event_name=credential_relationship['event_name'],
                                               event_time=credential_relationship['event_time']
                                               )
                                  )

                if credential_relationship['requesters_identity'] != 'Unknown':

                    credential_start_node = is_node_exist(identity=credential_relationship['requesters_identity'])
                    if credential_start_node is False:
                        credential_start_node = Node(credential_relationship['user_identity_type'],
                                                     user_identity_type=credential_relationship['user_identity_type'],
                                                     identity=credential_relationship['requesters_identity'])
                        self.graph.create(credential_start_node)
                    else:
                        credential_start_node['user_identity_type'] = credential_relationship['user_identity_type']
                        self.graph.push(credential_start_node)

                    self.graph.create(Relationship(credential_start_node,
                                                   'RequestsBehalf',
                                                   credential_center_node,
                                                   source_ip_address=credential_relationship['source_ip_address'],
                                                   event_id=credential_relationship['event_id'],
                                                   event_name=credential_relationship['event_name'],
                                                   event_time=credential_relationship['event_time']
                                                   )
                                      )

            # ASSUME ROLE
            else:
                credential_start_node = is_node_exist(identity=credential_relationship['requesters_identity'])
                if credential_start_node is False:
                    credential_start_node = Node('IAMAccessKeyId' if credential_relationship['requesters_identity'].startswith('AKIA') else credential_relationship['user_identity_type'],
                                                 user_identity_type=credential_relationship['user_identity_type'],
                                                 identity=credential_relationship['requesters_identity'])
                    self.graph.create(credential_start_node)

                else:
                    credential_start_node['user_identity_type'] = credential_relationship['user_identity_type']
                    credential_start_node['identity'] = credential_relationship['requesters_identity']
                    self.graph.push(credential_start_node)

                credential_end_node = is_node_exist(identity=credential_relationship['access_key_id'])
                if credential_end_node is False:
                    credential_end_node = Node('AssumedRole',
                                               identity=credential_relationship['access_key_id'],
                                               expiration_time=credential_relationship['expiration_time'],
                                               assumed_role_arn=credential_relationship['assumed_role_arn'],
                                               requested_role=credential_relationship['requested_role'],
                                               is_active=credential_relationship['is_active'],
                                               user_identity_type="AssumedRole"
                                               )
                    self.graph.create(credential_end_node)

                else:
                    credential_end_node['expiration_time'] = credential_relationship['expiration_time']
                    credential_end_node['assumed_role_arn'] = credential_relationship['assumed_role_arn']
                    credential_end_node['requested_role'] = credential_relationship['requested_role']
                    credential_end_node['is_active'] = credential_relationship['is_active']
                    credential_end_node['user_identity_type'] = 'AssumedRole'
                    self.graph.push(credential_end_node)

                self.graph.create(Relationship(credential_start_node,
                                               credential_relationship['event_name'],
                                               credential_end_node,
                                               source_ip_address=credential_relationship['source_ip_address'],
                                               event_id=credential_relationship['event_id'],
                                               event_name=credential_relationship['event_name'],
                                               event_time=credential_relationship['event_time']
                                               )
                                  )
