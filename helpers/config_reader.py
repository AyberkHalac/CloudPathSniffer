import os

import yaml

from helpers.logger import setup_logger

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(os.path.join(ROOT_DIR, '..', 'logs'), 'CredentialMapper.log')

logger = setup_logger(logger_name='config_reader', filename=LOG_FILE_PATH)


def get_config_file(path):
    with open(path, "r") as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
    return config
