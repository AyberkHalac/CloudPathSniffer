import os

from neo4j import GraphDatabase

from helpers.config_reader import get_config_file
from helpers.logger import setup_logger

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(os.path.join(ROOT_DIR, '..', 'logs'), 'CredentialMapper.log')

logger = setup_logger(logger_name='database_helper', filename=LOG_FILE_PATH)


class Neo4jDatabase:

    def __init__(self):
        try:
            config = get_config_file('./config.yaml')['neo4j_connection_configurations']
            username = config['username']
            password = config['password']
            database_uri = config['database_uri']
            self.driver = GraphDatabase.driver(database_uri, auth=(username, password))
        except Exception as e:
            print('[!] Error at connecting Neo4j\n', str(e))
            exit(1)

    def close(self):
        self.driver.close()

    def delete_all_data(self):
        with self.driver.session() as session:
            session.execute_write(self._delete_all_data)

    @staticmethod
    def _delete_all_data(tx):
        # Cypher query to delete all nodes and relationships
        query = "MATCH (n) DETACH DELETE n"
        tx.run(query)

    def execute_neo4j_cypher(self, neo4j_cypher: str):
        try:
            with self.driver.session() as session:
                executed_val = session.run(neo4j_cypher)
                return executed_val.data()
        except Exception as exp:
            logger.critical(str(exp))
            return None

    @staticmethod
    def create_or_update_node(tx, label, identity, **properties):
        # Get the existing labels of the node
        query_get_labels = (
            "MATCH (node {identity: $identity}) "
            "RETURN labels(node) AS labels, node"
        )
        result = tx.run(query_get_labels, identity=identity)

        record = result.single()
        if record is not None:
            existing_labels = record["labels"]
            node = record["node"]

            # Remove existing labels
            for e_label in existing_labels:
                if e_label != label:
                    query_remove_label = (
                        "MATCH (node {identity: $identity}) "
                        f"REMOVE node:{e_label}"
                    )
                    tx.run(query_remove_label, identity=identity)

            # Set the new label
            query_set_label = (
                "MATCH (node {identity: $identity}) "
                f"SET node:{label} "
                "RETURN node"
            )
            result = tx.run(query_set_label, identity=identity)

            # Update the properties
            query_update_properties = (
                f"MATCH (node:{label}"
                "{identity: $identity}) "
                "SET node += $properties "
                "RETURN node"
            )
            result = tx.run(query_update_properties, identity=identity, properties=properties)

            return result.single()

        else:
            # If the node with the specified identity doesn't exist, create a new node with the new label
            query_create_node = (
                f"CREATE (node:{label}"
                "{identity: $identity}) "
                f"SET node += $properties "
                f"RETURN node"
            )
            result = tx.run(query_create_node, identity=identity, properties=properties)

            return result.single()

    @staticmethod
    def create_relationship(tx, start_node, relationship_type, end_node, **properties):
        query = (
            f"MATCH (startNode), (endNode) "
            f"WHERE id(startNode) = $start_id AND id(endNode) = $end_id "
            f"MERGE (startNode)-[rel:{relationship_type}]->(endNode) "
            f"SET rel += $properties"
        )
        tx.run(query, start_id=start_node[0].id, end_id=end_node[0].id, properties=properties)
