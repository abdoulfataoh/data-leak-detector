# -*- coding: utf-8 -*-
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_fscore_support as score

import zat
from zat.log_to_dataframe import LogToDataFrame
from zat import dataframe_to_matrix
from zat.dataframe_to_matrix import DataFrameToMatrix
import pickle

from app import settings


def load_dataset(good_dataset_folder, malicious_dataset_folder):
  good_datasets = Path(good_dataset_folder).rglob('*.log')
  malicious_datasets = Path(malicious_dataset_folder).rglob('*.log')
  all_dataframe = pd.DataFrame()
  for good_dataset in good_datasets:
    print(good_dataset)
    log_to_df = LogToDataFrame()
    df = log_to_df.create_dataframe(good_dataset)
    print(df.shape)
    df['is_malicious'] = 0
    all_dataframe = pd.concat([all_dataframe, df])
  for malicious_dataset in malicious_datasets:
    print(malicious_dataset)
    log_to_df = LogToDataFrame()
    df = log_to_df.create_dataframe(malicious_dataset)
    print(df.shape)
    df['is_malicious'] = 1
    all_dataframe = pd.concat([all_dataframe, df])
  return all_dataframe

dataset = load_dataset(settings.GOOD_CONN_DATASET, settings.MALICIOUS_CONN_DATASET)

features_labels = [
          	'id.orig_p',	'id.resp_p',
            'proto',	'service', 'missed_bytes', 'history',	'orig_pkts',
            'resp_pkts',	'resp_ip_bytes',	'tunnel_parents'
           ]
features_not_vectorized = dataset[features_labels]
to_matrix = dataframe_to_matrix.DataFrameToMatrix()

features = to_matrix.fit_transform(features_not_vectorized)
target = dataset['is_malicious']


X_train, X_test, y_train, y_test = train_test_split(features, target, test_size=0.2, random_state=42, shuffle=True)
forest = RandomForestClassifier(n_estimators = 100)  
forest = forest.fit(X_train, y_train)

predictions = forest.predict(X_test)
precision, recall, fscore, _ = score(y_test, predictions, pos_label=1, average='binary')
print(f'precision={precision*100}%, recall={recall*100}%, fscore={fscore*100}%')


# save to_mtrix model
with open(settings.TO_MATRIX_CONN, 'wb') as file:
  pickle.dump(to_matrix, file)

# save to_mtrix model
with open(settings.RANDOM_FOREST_CONN_MODEL, 'wb') as file:
  pickle.dump(forest, file)
