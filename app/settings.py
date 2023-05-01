from environs import Env

env = Env()

# [Hotspot settings]
HOTSPOT_CONF = r'hotspot.conf'

# [Hotpsopt card settings]
CAPTURE_INTERFACE = env('INTERFACE', 'wlp4s0')

GOOD_DNS_DATASET = r'assets/dns_dataset/good'
MALICIOUS_DNS_DATASET = r'assets/dns_dataset/malicious'

GOOD_CONN_DATASET = r'assets/conn_dataset/good'
MALICIOUS_CONN_DATASET = r'assets/conn_dataset/malicious'

TO_MATRIX_CONN = r'assets/models/to_matrix_conn.pickle'
RANDOM_FOREST_CONN_MODEL = r'assets/models/randomforest_conn_model.pickle'

TO_MATRIX_DNS = r'assets/models/to_matrix_dns.pickle'
RANDOM_FOREST_DNS_MODEL = r'assets/models/randomforest_dns_model.pickle'

DNS_PREDICT_LOG = r'dns.log'
CONN_PREDICT_LOG = r'conn.log'
HTTP_PREDICT_LOG = r'http.log'

ZEEK_PATH = r'/opt/zeek/bin/zeek'

# Hotpot settings
INTERFACE='wlp4s0'
DRIVER='nl80211'
SSID='deep detector'
HW_MODE='g'
CHANNEL=6
MACADDR_ACL=0
AUTH_ALGS=1
IGNORE_BROADCAST_SSID=0
WPA=2
WPA_PASSPHRASE=12345678
WPA_KEY_MGMT='WPA-PSK'
WPA_PAIRWISE='TKIP'
RSN_PAIRWISE='CCMP'

URL_DATABASE = r'assets/databases/malicious_phish.csv'

HOTSPOT_TEMPLATE = 'interface={interface}\ndriver={driver}\nssid={ssid}\nhw_mode={hw_mode}\nchannel={channel}\nmacaddr_acl={macaddr_acl}\nauth_algs={auth_algs}\nignore_broadcast_ssid={ignore_broadcast_ssid}\nwpa={wpa}\nwpa_passphrase={wpa_passphrase}\nwpa_key_mgmt={wpa_key_mgmt}\nwpa_pairwise={wpa_pairwise}\nrsn_pairwise={rsn_pairwise}'
