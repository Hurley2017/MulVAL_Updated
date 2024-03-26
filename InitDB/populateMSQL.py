import mysql.connector
from CVERead import *
from CVEStore import *
from time import sleep
def get_connection():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Tusher@9051",
            database="nvd"
        )
        print('Connection Parameters Added Successfully!')
        return connection
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None

def setup_db():
    CVEStore()
    try:
        connection = get_connection()
        sleep(3)
        if connection is None:
            return
        
        cursor = connection.cursor()
        cursor.execute("DROP TABLE IF EXISTS nvd")
        cursor.execute("CREATE TABLE nvd(id VARCHAR(20) NOT NULL, "
                       "soft VARCHAR(160) NOT NULL DEFAULT 'undefined', "
                       "rng VARCHAR(100) NOT NULL DEFAULT 'undefined', "
                       "lose_types VARCHAR(100) NOT NULL DEFAULT 'undefined', "
                       "severity VARCHAR(20) NOT NULL DEFAULT 'undefined', "
                       "access VARCHAR(20) NOT NULL DEFAULT 'undefined')")
        print('Table Created Successfully!')
        Whole_Data = ReadCVE()
        #write to database
        print('Inserting Data into Database...')
        for i in range(len(Whole_Data)):
            cursor.execute("INSERT INTO nvd(id, soft, rng, lose_types, severity, access) VALUES(%s, %s, %s, %s, %s, %s)",
                           (Whole_Data[i][0], Whole_Data[i][1], Whole_Data[i][2], Whole_Data[i][3], Whole_Data[i][4], Whole_Data[i][5]))
        connection.commit()
        print('Data Inserted Successfully!')
        cursor.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    setup_db()
