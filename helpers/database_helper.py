import os

from neo4j import GraphDatabase
from py2neo import Graph, NodeMatcher, Node, Relationship

from helpers.config_reader import get_config_file
from helpers.logger import setup_logger

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(os.path.join(ROOT_DIR, '..', 'logs'), 'CredentialMapper.log')

logger = setup_logger(logger_name='database_helper', filename=LOG_FILE_PATH)


class Neo4jDatabase:

    def __init__(self):
        try:
            config = get_config_file('../config.yaml')['neo4j_connection_configurations']
            username = config['username']
            password = config['password']
            database_uri = config['database_uri']
            self.graph = Graph(database_uri, auth=(username, password))
            self.driver = GraphDatabase.driver(database_uri, auth=(username, password))
        except Exception as e:
            print('[!] Error at connecting Neo4j\n', str(e))
            exit(1)

    def neo4j_delete_all(self):
        try:
            self.graph.delete_all()
        except Exception as e:
            print('[!] Error at deleting Neo4j\n', str(e))
            exit(1)

    def is_node_exist(self, identity):
        matcher = NodeMatcher(self.graph)
        _node = matcher.match(identity=identity).first()
        if _node is None:
            return False
        else:
            return _node

    def neo4j_bulk_add_credentials(self, credentials):

        for credential_relationship in credentials:

            if credential_relationship['event_name'] == 'CreateAccessKey':

                credential_start_node = self.is_node_exist(identity=credential_relationship['requested_for'])
                if credential_start_node is False:
                    credential_start_node = Node('IAMUser',
                                                 user_identity_type='IAMUser',
                                                 identity=credential_relationship['requested_for'],
                                                 user_arn=credential_relationship['requested_users_arn'],
                                                 user_id=credential_relationship['requested_users_id']
                                                 )
                    self.graph.create(credential_start_node)

                else:
                    credential_start_node['user_id'] = credential_relationship['requested_users_id']
                    credential_start_node['user_arn'] = credential_relationship['requested_users_arn']
                    self.graph.push(credential_start_node)

                credential_end_node = self.is_node_exist(identity=credential_relationship['access_key_id'])
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

                if len(self.graph.match((credential_start_node, credential_end_node), "CreateAccessKey")) == 0:
                    self.graph.merge(Relationship(credential_start_node,
                                                  credential_relationship['event_name'],
                                                  credential_end_node,
                                                  source_ip_address=credential_relationship['source_ip_address'],
                                                  event_id=credential_relationship['event_id'],
                                                  event_name=credential_relationship['event_name'],
                                                  event_time=credential_relationship['event_time'],
                                                  requesters_identity=credential_relationship['requesters_identity']
                                                  )
                                     )

            # ASSUME ROLE
            else:
                if credential_relationship['user_identity_type'] == 'FederatedUser':
                    service_name = credential_relationship['requesters_identity'][:credential_relationship['requesters_identity'].index(':')]
                    requesters_identity = credential_relationship['requesters_identity'][credential_relationship['requesters_identity'].index(':') + 1:]
                    credential_start_node = self.is_node_exist(requesters_identity)
                    if credential_start_node is False:
                        credential_start_node = Node(credential_relationship['user_identity_type'],
                                                     user_identity_type=credential_relationship['user_identity_type'],
                                                     identity=requesters_identity,
                                                     service_name=service_name)
                        self.graph.create(credential_start_node)

                    else:
                        credential_start_node['user_identity_type'] = credential_relationship['user_identity_type']
                        credential_start_node['identity'] = requesters_identity
                        credential_start_node['service_name'] = service_name
                        self.graph.push(credential_start_node)

                else:
                    credential_start_node = self.is_node_exist(identity=credential_relationship['requesters_identity'])
                    if credential_start_node is False:
                        credential_start_node = Node('IAMAccessKeyId' if credential_relationship['requesters_identity'].startswith('AKIA') else credential_relationship['user_identity_type'],
                                                     user_identity_type=credential_relationship['user_identity_type'],
                                                     identity=credential_relationship['requesters_identity'])
                        self.graph.create(credential_start_node)

                    else:
                        credential_start_node['user_identity_type'] = credential_relationship['user_identity_type']
                        credential_start_node['identity'] = credential_relationship['requesters_identity']
                        self.graph.push(credential_start_node)

                credential_end_node = self.is_node_exist(identity=credential_relationship['access_key_id'])
                if credential_end_node is False:
                    if credential_relationship['event_name'] == 'GetFederationToken':
                        credential_end_node = Node('AssumedRole',
                                                   identity=credential_relationship['access_key_id'],
                                                   expiration_time=credential_relationship['expiration_time'],
                                                   assumed_policies=credential_relationship['assumed_role_arn'],
                                                   requested_role=credential_relationship['requested_role'],
                                                   is_active=credential_relationship['is_active'],
                                                   user_identity_type="AssumedRole"
                                                   )
                    else:
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

    def add_rel_as_console_login_of_iam_credentials(self, console_login_data_list):
        for console_login_data in console_login_data_list:

            credential_start_node = self.is_node_exist(identity=console_login_data['requesters_identity_username'])
            if credential_start_node is False:
                credential_start_node = Node('IAMUser',
                                             user_identity_type='IAMUser',
                                             identity=console_login_data['requesters_identity_username'],
                                             user_arn=console_login_data['requesters_identity_arn'],
                                             principal_id=console_login_data['requesters_identity_principalid'],
                                             )
                self.graph.create(credential_start_node)
            else:
                credential_start_node['user_id'] = console_login_data['requesters_identity_principalid']
                credential_start_node['user_arn'] = console_login_data['requesters_identity_arn']
                self.graph.push(credential_start_node)

            credential_end_node = self.is_node_exist(console_login_data['user_identity_principalid'][console_login_data['user_identity_principalid'].find(':') + 1:])
            if credential_end_node is False:
                credential_end_node = Node(console_login_data['user_identity_type'],
                                           user_identity_type=console_login_data['user_identity_type'],
                                           identity=console_login_data['user_identity_principalid'][console_login_data['user_identity_principalid'].find(':') + 1:],
                                           user_arn=console_login_data['user_identity_arn'],
                                           principal_id=console_login_data['user_identity_principalid'],
                                           account_id=console_login_data['user_identity_accountid'],
                                           )
                self.graph.create(credential_end_node)
            else:
                credential_end_node['user_id'] = console_login_data['user_identity_principalid']
                credential_end_node['user_arn'] = console_login_data['user_identity_arn']
                credential_end_node['account_id'] = console_login_data['user_identity_accountid']
                self.graph.push(credential_end_node)

            self.execute_neo4j_cypher(neo4j_cypher="""
            MATCH
              (a:IAMUser),
              (b:FederatedUser)
            WHERE a.identity = '{start_node_identity}' AND b.identity = '{end_node_identity}'
            CREATE (a)-[r:SuspiciousConsoleLogin{{source_ip_address:'{source_ip_address}', event_id:'{event_id}', event_name:'{event_name}', event_time:'{event_time}'}}]->(b)
            RETURN type(r)
            """.format(start_node_identity=str(console_login_data['requesters_identity_username']),
                       end_node_identity=console_login_data['user_identity_principalid'][console_login_data['user_identity_principalid'].find(':') + 1:],
                       source_ip_address=str(console_login_data['source_ip_address']),
                       event_id=console_login_data['event_id'],
                       event_name=console_login_data['event_name'],
                       event_time=str(console_login_data['event_time'])
                       ))

    def find_nodes_with_max_relationship(self, contains_service_accounts: False):
        """
        The nodes that have the most relationships are found using this method.
        :param contains_service_accounts:
        :return: Neo4j Nodes that has max relationship
        """

        if contains_service_accounts:
            nodes_with_max_relationship = self.driver.session().run('''MATCH (n)
                                                                        WITH n, SIZE([(n)-[]-() | 1]) AS numRelationships
                                                                        WHERE numRelationships > 20
                                                                        RETURN n, numRelationships
                                                                        ORDER BY numRelationships DESC
                                                                        LIMIT 50;''')
        else:
            nodes_with_max_relationship = self.driver.session().run('''MATCH (n)
                                                                        WHERE NOT n.identity CONTAINS "amazonaws.com"
                                                                        WITH n, SIZE([(n)-[]-() | 1]) AS numRelationships
                                                                        WHERE numRelationships > 10
                                                                        RETURN n, numRelationships
                                                                        ORDER BY numRelationships DESC
                                                                        LIMIT 50;''')

        return nodes_with_max_relationship.data()

    def find_longest_uniq_paths(self):
        # This query gives the longest unique paths
        possible_role_juggling_paths = self.driver.session().run('''MATCH p=(parent)-[r*]->(child)
                                                                    WHERE NOT EXISTS((child)-->())
                                                                        and NOT EXISTS(()-[:AssumeRole|CreateAccessKey]->(parent))
                                                                        and length(p)>6
                                                                    RETURN p
                                                                    ORDER BY length(p) DESC
                                                                    LIMIT 20''')
        return possible_role_juggling_paths.data()

    def execute_neo4j_cypher(self, neo4j_cypher: str):
        executed_val = self.driver.session().run(neo4j_cypher)
        return executed_val.data()
