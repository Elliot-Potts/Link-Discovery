import logging

def setup_logger():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # Suppress Flet's debug messages
    logging.getLogger("flet_core").setLevel(logging.WARNING)
    logging.getLogger("flet_runtime").setLevel(logging.WARNING)

    return logger

logger = setup_logger()
