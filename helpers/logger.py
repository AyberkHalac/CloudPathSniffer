import errno
import logging
import os
import sys

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def setup_logger(logger_name, filename):
    formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    try:
        os.makedirs(os.path.join(ROOT_DIR, '..', 'logs'))
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    handler = logging.FileHandler(filename=filename, mode='w')
    handler.setFormatter(formatter)
    screen_handler = logging.StreamHandler(stream=sys.stdout)
    screen_handler.setFormatter(formatter)
    __logger = logging.getLogger(logger_name)
    __logger.setLevel(logging.CRITICAL)
    __logger.addHandler(handler)
    __logger.addHandler(screen_handler)
    return __logger
