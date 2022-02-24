import MySQLdb
import pandas as pd
import sys
import os

DB_USER = os.getenv("DB_USER")
DB_PWD = os.getenv("DB_PWD")
conn = MySQLdb.connect(user=DB_USER, passwd=DB_PWD, db="yelp_db")
query = "SELECT review_count, stars FROM businesses;"
df = pd.read_sql(query, con=conn)
df.describe().to_csv(sys.stdout, encoding='utf-8',
float_format='%.2f', header = None)
