import os
from dotenv import load_dotenv
from multidb_request_handler import DatabaseOperation

load_dotenv()


class DatabaseManager:
    def __init__(self):
        # Common database configuration
        self.db_config = {
            'host': os.getenv("DB_HOST"),
            'port': os.getenv("DB_PORT"),
            'database_name': os.getenv("DB_NAME"),
            'username': os.getenv("DB_USERNAME"),
            'password': os.getenv("DB_PASSWORD"),
        }

    def get_database(self, table_name):
        """Returns a DatabaseOperation instance for the specified table."""
        return DatabaseOperation(
            table_name=table_name,
            **self.db_config
        )

# Example usage
if __name__ == "__main__":
    db_manager = DatabaseManager()

    # Access the users database
    users_db = db_manager.get_database('users')

    # Access the blacklist database
    blacklist_db = db_manager.get_database('token_blacklist')

    # Now you can use `users_db` and `blacklist_db` as needed
