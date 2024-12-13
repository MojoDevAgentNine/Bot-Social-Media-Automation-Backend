import logging
from axiom_py import Client
from axiom_py.logging import AxiomHandler

# Define a function to set up logging
# def setup_logging(api_key: str, dataset: str) -> logging.Logger:
#     """
#     Sets up the logging configuration, including an Axiom handler.
#
#     Args:
#         api_key (str): The Axiom API key for client initialization.
#         dataset (str): The dataset name to use for Axiom logging.
#
#     Returns:
#         logging.Logger: Configured logger instance.
#     """
#     # Initialize Axiom client securely, without exposing the API key in code
#     client = Client(api_key)
#
#     # Create and configure Axiom handler
#     axiom_handler = AxiomHandler(client, dataset)
#
#     # Set up root logger with Axiom handler and DEBUG level
#     root_logger = logging.getLogger()
#     root_logger.setLevel(logging.DEBUG)
#     root_logger.addHandler(axiom_handler)
#
#     return logging.getLogger(__name__)


# axiom_logger/authentication.py

import logging
import os
from axiom_py import Client
from axiom_py.logging import AxiomHandler
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()


class AxiomLogger:
    def __init__(self):
        # Initialize the Axiom client using the auth token from environment variables
        self.client = Client(os.getenv('AXIOM_AUTH_TOKEN'))

        # Get the dataset name from environment variables
        self.dataset = os.getenv('AXIOM_AUTH_DATASET')

        # Set up the logger for Axiom
        self.logger = logging.getLogger("AxiomLogger")
        self.logger.setLevel(logging.DEBUG)

        # Configure the Axiom handler to send logs to Axiom
        axiom_handler = AxiomHandler(self.client, self.dataset)

        # Set log format
        axiom_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        # Add the Axiom handler to the logger
        self.logger.addHandler(axiom_handler)

    def get_logger(self):
        return self.logger

    # logger.debug("This is a debug message")
    # logger.info("This is an info message")
    # logger.warning("This is a warning message")
    # logger.error("This is an error message")
    # logger.critical("This is a critical message")



axiom_logger = AxiomLogger()
logger = axiom_logger.get_logger()
