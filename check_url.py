import pandas as pd

from app import settings

def check_url(database_url, url):
    database = pd.read_csv(database_url)
    filter = (database['type'] != 'benign') & (database['url'] == url)
    return database[filter]
