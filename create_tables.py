# create_tables.py
from sqlalchemy import inspect, text
from app.database.database import engine, Base
from app.models.user import User, Profile, TokenBlacklist, EmailVerificationCode
import sqlalchemy as sa
from sqlalchemy.schema import CreateTable


def get_column_type_string(column):
    """Convert SQLAlchemy column type to string representation"""
    return str(column.type.compile(engine.dialect))


class DatabaseManager:
    def __init__(self, engine, Base):
        self.engine = engine
        self.Base = Base
        self.inspector = inspect(engine)

    def table_exists(self, table_name):
        return table_name in self.inspector.get_table_names()

    def get_table_columns(self, table_name):
        return {column['name']: column for column in self.inspector.get_columns(table_name)}

    def create_table(self, table):
        try:
            table.create(self.engine)
            print(f"Created new table: {table.name}")
        except Exception as e:
            print(f"Error creating table {table.name}: {str(e)}")

    def add_column(self, table_name, column_name, column):
        try:
            column_type = get_column_type_string(column)
            nullable = "NULL" if column.nullable else "NOT NULL"
            default = f"DEFAULT {column.default.arg}" if column.default is not None else ""

            alter_stmt = f'ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type} {nullable} {default}'
            with self.engine.begin() as conn:
                conn.execute(text(alter_stmt))
            print(f"Added column {column_name} to {table_name}")
        except Exception as e:
            print(f"Error adding column {column_name} to {table_name}: {str(e)}")

    def update_tables(self):
        models = self.Base.metadata.tables

        for table_name, table in models.items():
            if not self.table_exists(table_name):
                self.create_table(table)
            else:
                existing_columns = self.get_table_columns(table_name)
                model_columns = {c.name: c for c in table.columns}

                # Find new columns to add
                new_columns = set(model_columns.keys()) - set(existing_columns.keys())
                for col_name in new_columns:
                    self.add_column(table_name, col_name, model_columns[col_name])


def init_db():
    try:
        db_manager = DatabaseManager(engine, Base)
        db_manager.update_tables()
        print("Database initialization completed successfully!")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    init_db()
