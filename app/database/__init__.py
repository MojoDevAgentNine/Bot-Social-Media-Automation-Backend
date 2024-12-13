from app.database.database import get_db
from multidb_request_handler import DatabaseOperation


def get_usres_table():
    db = DatabaseOperation(host='http://127.0.0.1', port='44777',
                                database_name='social_automation', table_name='users',
                                username='postgres', password='postgres')
    return db