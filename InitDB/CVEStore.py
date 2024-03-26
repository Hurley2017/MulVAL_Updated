import os, sys
from datetime import datetime
from threading import Thread
from time import sleep 

def ThreadDownNVD(file):
    os.system('wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-'+str(file)+'.json.zip')
    os.system('unzip nvdcve-1.1-'+str(file)+'.json.zip -d CVE')
    os.system('rm nvdcve-1.1-'+str(file)+'.json.zip')
    print('nvdcve-1.1-'+str(file)+'.json.zip is downloaded and unzipped')

def CVEStore():
    print('Deploying workers to download and store CVE files...')
    sleep(3)
    if not os.path.exists('CVE'):   
        os.system('mkdir CVE')
    else:
        os.system('rm -rf CVE/*')
        print('OLD CVE folder is cleared') 
        os.system('mkdir CVE')   

    startYear = 2002
    endYear = datetime.now().year
    Threads = []
    while True:
        MissingFiles = []

        for i in range(startYear, endYear+1):
            if not os.path.exists('CVE/nvdcve-1.1-'+str(i)+'.json'):
                MissingFiles.append(i)
        
        if MissingFiles == []:
            break 

        for files in MissingFiles:
            Threads.append(Thread(target=ThreadDownNVD, args=(files,)))

        for thread in Threads:
            thread.start()

        for thread in Threads:
            thread.join()

        Threads = []

    print('All CVE files are downloaded and unzipped') 
    sleep(3)   
        