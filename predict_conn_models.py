
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


def predict_conn_pipeline(conn_dataset_path, model, to_matrix):
  # load df
  log_to_df = LogToDataFrame()
  dataset_predit = log_to_df.create_dataframe(conn_dataset_path)

  # # vectorisation
  features_labels = [
          	'id.orig_p',	'id.resp_p',
            'proto',	'service', 'missed_bytes', 'history',	'orig_pkts',
            'resp_pkts',	'resp_ip_bytes',	'tunnel_parents'
           ]
  features_not_vectorized = dataset_predit[features_labels]
  features = to_matrix.transform(features_not_vectorized)


  predictions = model.predict(features) 
  return predictions, dataset_predit
