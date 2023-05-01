import pickle
from pathlib import Path
import time

import streamlit as st
import matplotlib.pyplot as plt
from zat.log_to_dataframe import LogToDataFrame
import pandas as pd

from app import settings
from predict_dns_models import predict_dns_pipeline
from predict_conn_models import predict_conn_pipeline
from check_url import check_url

import subprocess

import pickle


def load_log(log_dataset_path):
    log_to_df = LogToDataFrame()
    log_dataset = log_to_df.create_dataframe(log_dataset_path)
    return log_dataset


# Load all models
with open(settings.TO_MATRIX_DNS, 'rb') as file:
    to_matrix_dns_model = pickle.load(file)


with open(settings.RANDOM_FOREST_DNS_MODEL, 'rb') as file:
    dns_model = pickle.load(file)

# Load all models
with open(settings.TO_MATRIX_CONN, 'rb') as file:
    to_matrix_conn_model = pickle.load(file)


with open(settings.RANDOM_FOREST_CONN_MODEL, 'rb') as file:
    conn_model = pickle.load(file)


# title
st.markdown(
    """
    # DEEP DETECTOR
    """
)


# sidebar
st.sidebar.header('Options')
option = st.sidebar.selectbox(
    'Selectionner',
    ['ANALYSE']
)


st.sidebar.header('Hotspot')
if st.sidebar.button('DEMARRER LE HOTSPOT'):
    subprocess.call(
        ['sudo', 'systemctl', 'start', 'raspapd.service'],
        cwd='/usr/lib/systemd/system'
    )

def wifi_settings():
    interface = st.text_input('interface', settings.INTERFACE)
    driver = st.text_input('driver', settings.DRIVER)
    ssid = st.text_input('ssid', settings.SSID)
    hw_mode = st.text_input('hw_mode', settings.HW_MODE)
    channel = st.text_input('channel', settings.CHANNEL)
    macaddr_acl = st.text_input('macaddr_acl', settings.MACADDR_ACL)
    auth_algs = st.text_input('auth_algs', settings.AUTH_ALGS)
    ignore_broadcast_ssid = st.text_input('ssid', settings.IGNORE_BROADCAST_SSID)
    wpa = st.text_input('wpa', settings.WPA)
    wpa_passphrase = st.text_input('wpa_passphrase', settings.WPA_PASSPHRASE)
    wpa_key_mgmt = st.text_input('wpa_key_mgmt', settings.WPA_KEY_MGMT)
    wpa_pairwise = st.text_input('wpa_pairwise', settings.WPA_PAIRWISE)
    rsn_pairwise = st.text_input('rsn_pairwise', settings.RSN_PAIRWISE)

    if st.button('DEMARRER LE HOTSPOT'):
        with open(settings.HOTSPOT_CONF, 'w') as file:
            file.write(
                settings.HOTSPOT_TEMPLATE.format(
                interface=interface,
                driver=driver,
                ssid=ssid,
                hw_mode=hw_mode,
                channel=channel,
                macaddr_acl=macaddr_acl,
                auth_algs=auth_algs,
                ignore_broadcast_ssid=ignore_broadcast_ssid,
                wpa=wpa,
                wpa_passphrase=wpa_passphrase,
                wpa_key_mgmt=wpa_key_mgmt,
                wpa_pairwise=wpa_pairwise,
                rsn_pairwise=rsn_pairwise
                )
            )
        subprocess.Popen(['sudo', 'hostapd', settings.HOTSPOT_CONF,])
    else:
        pass

def analyse():
    timeoute = st.number_input('Timeout', value=10)
    if st.button('DEMARRER L\'ANALYSE'):

        tshark_process = subprocess.Popen(
            ['sudo', 'tshark', '-i', settings.CAPTURE_INTERFACE, '-a',  f'duration:{timeoute}', '-w', 'workdir/capture.pcap']
        )

        progress_100 = 100
        progress_step = int(2 * progress_100 / timeoute)
        progress_sleep_time = 2
        progress = 0
        progress_bar = st.progress(progress)

        while tshark_process.poll() is None:
            time.sleep(progress_sleep_time)
            if progress < 100:
                progress = progress + progress_step
            
            if progress > 90:
                progress = 90
            
            progress_bar.progress(progress, 'Packet capture in progress...')

        progress = progress + 5  
        progress_bar.progress(progress, 'Analysing packets...')
        subprocess.call(
            ['sudo', settings.ZEEK_PATH, '-Cr', 'workdir/capture.pcap']
        )
        if Path(settings.HTTP_PREDICT_LOG).exists == True:
            st.markdown(
            f"""
            ## ANALYSE DES REQUETES HTTP
            """
            )
            http_df = load_log(settings.HTTP_PREDICT_LOG)
            urls = http_df['url']
            for url in urls:
                r = check_url(settings.URL_DATABASE, url)
                st.dataframe(r)

        progress = progress + 5  
        progress_bar.progress(progress, 'Done.')
        call_prediction('DNS', settings.DNS_PREDICT_LOG, dns_model, to_matrix_dns_model, predict_dns_pipeline)
        call_prediction('CONNECTIONS', settings.CONN_PREDICT_LOG, conn_model, to_matrix_conn_model, predict_conn_pipeline)




def call_prediction(title, log_file, model, to_matrix_model, pipeline):
    st.markdown(
    f"""
    ## ANALYSE DES {title}
    """
    )
    prediction, df_ = pipeline(log_file, model, to_matrix_model)
    prediction = list(prediction)
    col1, col2, col3 = st.columns(3)
    col1.metric("Nombre de requetes DNS Analysees", len(prediction))
    col2.metric("Nombre de requetes dns suspectes", prediction.count(1))
    col3.metric("Nombre de requetes dns propres", prediction.count(0))

    suspicious_indexs = []
    for index, boolean in enumerate(prediction):
        if boolean == True:
            suspicious_indexs.append(index)

    suspicious_df = df_.iloc[suspicious_indexs]

    st.markdown('### Requetes suspectes ')
    st.dataframe(suspicious_df.astype(str))

    labels = 'suspect', 'sain'
    sizes = [prediction.count(1), prediction.count(0)]
    explode = (0, 0.1) 

    fig1, ax1 = plt.subplots()
    ax1.pie(sizes, explode=explode, labels=labels, autopct='%1.1f%%',
        shadow=True, startangle=90)
    ax1.axis('equal')

    st.pyplot(fig1)




functions = {
    'WIFI SETTINGS': wifi_settings,
    'ANALYSE': analyse,
}

# run selected option
functions[option]()