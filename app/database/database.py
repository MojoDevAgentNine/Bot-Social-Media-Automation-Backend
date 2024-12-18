import logging
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, text
from multidb_request_handler import DatabaseOperation
from sqlalchemy.ext.declarative import declarative_base

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
