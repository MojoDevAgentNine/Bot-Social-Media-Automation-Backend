# import os
# from dotenv import load_dotenv
# from sqlalchemy import create_engine
# from sqlalchemy.orm import sessionmaker
# from sqlalchemy.ext.declarative import declarative_base
# load_dotenv()
#
# # DATABASE_URL = os.getenv("DATABASE_URL_LOCAL")
# DATABASE_URL = "postgresql://postgres:123456789@db:5432/social_automation"
# # DATABASE_URL = "postgresql://postgres:123456789@localhost:5432/social_automation"
# # Initialize SQLAlchemy engine and session
# engine = create_engine(DATABASE_URL)
# SessionLocal = sessionmaker(autoflush=False, autocommit=False, bind=engine)
# Base = declarative_base()
#
#
# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()


# app/database/database.py
from sqlalchemy import create_engine, text  # Add text here
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import logging

from multidb_request_handler import DatabaseOperation

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database URL
DATABASE_URL = "postgresql://postgres:postgres@localhost/social_automation"

try:
    # # Create engine with connection pooling
    # engine = create_engine(
    #     DATABASE_URL,
    #     pool_size=5,
    #     max_overflow=10,
    #     pool_timeout=30,
    #     pool_recycle=1800,
    # )
    #
    # # Create SessionLocal class
    # SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Create Base class
    Base = declarative_base()

except Exception as e:
    logger.error(f"Database connection failed: {str(e)}")
    raise


# Dependency to get DB session
def get_db():
    db = DatabaseOperation(host='http://127.0.0.1', port='44777',
                           database_name='social_automation', table_name='users',
                           username='postgres', password='postgres')
    try:
        yield db
    except Exception as e:
        logger.error(f"Database connection failed: {str(e)}")
        raise

def get_usres_table():
    db = DatabaseOperation(host='http://127.0.0.1', port='44777',
                                database_name='social_automation', table_name='users',
                                username='postgres', password='postgres')
    print(db.post_request(endpoint="get?email__like=arif.reza3126@gmail.com&role__like=admin"))
    return db



# Test database connection
# def test_connection():
#     try:
#         with engine.connect() as conn:
#             conn.execute(text("SELECT 1"))
#         logger.info("Database connection successful")
#         return True
#     except Exception as e:
#         logger.error(f"Database connection test failed: {str(e)}")
#         return False
