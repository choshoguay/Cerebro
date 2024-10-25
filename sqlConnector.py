### @author: David Wong
### @date: 10/21/2024
### Description: Connector to insert objects into the Postgres database.

# -------- External Modules --------

import psycopg2
import os
from psycopg2 import sql

# -------- Global Variables --------



# -------- External Classes --------



# -------- Private Functions --------


class PSQLConnector:
    def __init__(self, dbname, user, password, host, port):
        self.connection = self.connect_to_db(dbname, user, password, host, port)
        self.cursor = self.connection.cursor() if self.connection else None

    #FUNCTION: CONNECT TO THE POSTGRES DATABASE
    #PARAMETER: host, dbname, user, password

    def connect_to_db(dbname, user, password, host, port):
        print(f"Attempting to connect to database {dbname}...")
        try:
            conn = psycopg2.connect(
                dbname=dbname,
                user=user,
                password=password,
                host=host,
                port=port
            )
            print(f"Connected to {dbname}.")
        except Exception as e:
            print(f"Error connecting to {dbname}: {e}")
            conn = None
        return conn
    
    def create_customer_table(self, conn, vid):
        if not self.cursor:
            print("No database connection.")
            return
        
        customer_name = vid.get_customer_name()
        customer_site = vid.get_customer_site()
        system_version = vid.get_system_version()
        date = vid.get_date()

        table_name = f"staging_{customer_name}_{customer_site}_{system_version}_{date}"

        try:
            cursor = conn.cursor()
            create_query = f"CREATE TABLE IF NOT EXISTS {table_name} ();"
            cursor.execute(create_query)
            conn.commit()
            print(f"Table {table_name} created or already exists.")
        except Exception as e:
            print(f"Error creating {table_name}: {e}")
        finally:
            cursor.close()
                               

    def insert_vid_object(self, vid):
        if not self.cursor:
            print("No database connection.")
            return
        
        customer_name = vid.get_customer_name()
        customer_site = vid.get_customer_site()
        system_version = vid.get_system_version()
        date = vid.get_date()

        table_name = f"staging_{customer_name}_{customer_site}_{system_version}_{date}"

        vid_dict = vars(vid)
        columns = vid_dict.keys()
        values = [vid_dict[column] for column in columns]
        insert_query = sql.SQL('''
            INSERT INTO {table_name} ({columns}) VALUES ({values});
        ''')
    
#FUNCTION: INSERT VID OBJECTS INTO THE POSTGRES DATABASE
#PARAMETER: CONNECTION TO THE DATABASE, LIST OF VID OBJECTS

        

# -------- Main --------

if __name__ == "__main__":
    db_params = {
        'dbname' : 'object_test',
        'user' : 'postgresql',
        'password' : 'Batw1ngs-Adm1n1!',
        'host' : '10.1.233.200',
        'port' : '5432'
    }

    db_connector = PSQLConnector(**db_params)

    for vid in vid_objects:
        db_connector.create_customer_table(db_connector.connection, vid)
        db_connector.insert_vid_object(vid)

    db_connector.close_connection()