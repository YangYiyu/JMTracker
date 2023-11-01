import sqlite3
import os

class DBService:
    @staticmethod
    def execute_update(sql):
        try:
            conn = sqlite3.connect(os.path.join(os.path.abspath("./database"), "shsac.db"))
            cursor = conn.cursor()
            cursor.execute(sql)
            conn.commit()
            conn.close()
            print("Executing {} successfully!".format(sql))
            return True
        except Exception as e:
            print("Exception occurs when executing {}".format(sql))
            print(e)
            return False
    
    @staticmethod
    def execute_query(sql):
        result = []
        try:
            conn = sqlite3.connect(os.path.join(os.path.abspath("./database"), "shsac.db"))
            cursor = conn.cursor()
            rs = cursor.execute(sql)
            for row in rs.fetchall():
                result.append(row)
            rs.close()
            conn.close()
            print("Executing {} successfully! Fetch {} records.".format(sql, len(result)))
        except Exception as e:
            print("Exception occurs when executing {}".format(sql))
            print(e)
        return result

    @staticmethod
    def create_table():
        sql = '''
        create table method_chain(
            id varchar(100) primary key not null,
            app varchar(100) not null,
            capability varchar(200) not null,
            chainjson text not null,
            trigger text not null,
            remark varchar(200)
        )
        '''
        DBService.execute_update(sql)

if __name__=="__main__":
    # print(os.path.join(os.path.abspath("./database"), "shsac.db"))
    DBService.create_table()