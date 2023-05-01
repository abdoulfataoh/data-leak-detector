# coding: utf-8

import subprocess

class AcessPoint:

    _config_file: str

    def __init__(self, config_file: str):
        self._config_file = config_file

    
    def start(self):
        subprocess.Popen(
            ['sudo', 'hostapd', self._config_file,],
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE
       )   
    

    
