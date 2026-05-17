import sys
from loguru import logger

def setup_logger():
    logger.remove()
    logger.add(sys.stderr, level="DEBUG")
    logger.add("sentinel.log", rotation="10 MB", level="INFO")

setup_logger()
