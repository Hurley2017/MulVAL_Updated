import os
import json
from datetime import datetime
import pprint  
from time import sleep


def ReadCVE():
    sleep(3)
    print("Reading NVD Data...")
    pp = pprint.PrettyPrinter(indent=2)

    startYear = 2002
    endYear = datetime.now().year

    uniqV3 = set()
    uniqV2 = set()  
    Whole_Data = []

    for j in range(startYear, endYear+1):
        file = 'CVE/nvdcve-1.1-'+str(j)+'.json'
        if os.path.exists(file):
            file = json.loads(open(file).read())
            Number_of_CVE_Items = int(file['CVE_data_numberOfCVEs']) 
            CVE_Items = file['CVE_Items']   
            for i in range(Number_of_CVE_Items):
                #Reference of Java Structure Files.
                # pp.pprint(CVE_Items[i])
                # exit(0)
                #CVE_ID
                CVE_ID = CVE_Items[i]['cve']['CVE_data_meta']['ID']
                # print(CVE_ID) 
                #SEV  
                if 'baseMetricV2' in CVE_Items[i]['impact']:
                    SEV = CVE_Items[i]['impact']['baseMetricV2']['severity']          
                elif 'baseMetricV3' in CVE_Items[i]['impact']:
                    SEV = CVE_Items[i]['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                else:
                    SEV = ""    
                # print(SEV)
                #ACCESS
                if 'baseMetricV2' in CVE_Items[i]['impact']:
                    ACCESS = CVE_Items[i]['impact']['baseMetricV2']['cvssV2']['vectorString'][8].lower()
                elif 'baseMetricV3' in CVE_Items[i]['impact']:
                    ACCESS = CVE_Items[i]['impact']['baseMetricV3']['cvssV3']['vectorString'][17].lower()
                else:
                    ACCESS = ""
                # print(ACCESS)
                #SFTW
                if CVE_Items[i]['configurations']['nodes'] != []:
                    if CVE_Items[i]['configurations']['nodes'][0]['cpe_match'] != []:
                        SFTW = CVE_Items[i]['configurations']['nodes'][0]['cpe_match'][0]['cpe23Uri'].split(':')[3]
                    else:
                        SFTW = CVE_Items[i]['configurations']['nodes'][0]['children'][0]['cpe_match'][0]['cpe23Uri'].split(':')[3]
                else:
                    SFTW = ""
                # print(SFTW)
                #RGE
                if 'baseMetricV2' in CVE_Items[i]['impact']:
                    if 'userInteractionRequired' not in CVE_Items[i]['impact']['baseMetricV2']:
                        RGE = CVE_Items[i]['impact']['baseMetricV2']['cvssV2']['accessVector']
                    else:    
                        if CVE_Items[i]['impact']['baseMetricV2']['userInteractionRequired'] == True:
                            RGE = 'user_action_req'
                        else:    
                            RGE = CVE_Items[i]['impact']['baseMetricV2']['cvssV2']['accessVector']          
                elif 'baseMetricV3' in CVE_Items[i]['impact']:
                    if CVE_Items[i]['impact']['baseMetricV3']['cvssV3']['userInteraction'] != 'NONE':
                        RGE = 'user_action_req'
                    else:
                        RGE = CVE_Items[i]['impact']['baseMetricV3']['cvssV3']['attackVector']
                else:
                    RGE = ""
                if RGE == 'NETWORK':
                    RGE = 'remoteExploit'
                elif RGE == 'ADJACENT_NETWORK':
                    RGE = 'lan'
                elif RGE == 'LOCAL':
                    RGE = 'local'
                elif RGE == 'user_action_req':
                    pass    
                else:
                    RGE = 'other'   
                # print(RGE) 
                #LOSSTYPE
                if 'baseMetricV2' in CVE_Items[i]['impact']:
                    conf = CVE_Items[i]['impact']['baseMetricV2']['cvssV2']['confidentialityImpact']
                    avail = CVE_Items[i]['impact']['baseMetricV2']['cvssV2']['availabilityImpact']
                    inti = CVE_Items[i]['impact']['baseMetricV2']['cvssV2']['integrityImpact'] 
                    if conf == 'NONE':
                        conf = 0
                    elif conf == 'PARTIAL':
                        conf = 1    
                    elif conf == 'COMPLETE':
                        conf = 2
                    if avail == 'NONE':
                        avail = 0
                    elif avail == 'PARTIAL':
                        avail = 1
                    elif avail == 'COMPLETE':
                        avail = 2     
                    if inti == 'NONE':
                        inti = 0
                    elif inti == 'PARTIAL':
                        inti = 1
                    elif inti == 'COMPLETE':
                        inti = 2      
                    if conf > avail and conf > inti:
                        LOSSTYPE = 'data_loss'  
                    elif avail > conf and avail > inti:
                        LOSSTYPE = 'availability_loss'
                    elif inti > conf and inti > avail:
                        LOSSTYPE = 'integrity_loss' 
                    else:
                        LOSSTYPE = 'other'                        
                elif 'baseMetricV3' in CVE_Items[i]['impact']:
                    conf = CVE_Items[i]['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
                    avail = CVE_Items[i]['impact']['baseMetricV3']['cvssV3']['availabilityImpact']
                    inti = CVE_Items[i]['impact']['baseMetricV3']['cvssV3']['integrityImpact']
                    if conf == 'NONE':
                        conf = 0
                    elif conf == 'LOW':
                        conf = 1    
                    elif conf == 'HIGH':
                        conf = 2 
                    if avail == 'NONE':
                        avail = 0
                    elif avail == 'LOW':
                        avail = 1    
                    elif avail == 'HIGH':
                        avail = 2 
                    if inti == 'NONE':
                        inti = 0
                    elif inti == 'LOW':
                        inti = 1    
                    elif inti == 'HIGH':
                        inti = 2 
                    if conf > avail and conf > inti:
                        LOSSTYPE = 'data_loss'  
                    elif avail > conf and avail > inti:
                        LOSSTYPE = 'availability_loss'
                    elif inti > conf and inti > avail:
                        LOSSTYPE = 'data_modification' 
                    else:
                        LOSSTYPE = 'other'
                # print(LOSSTYPE) 
                # print('Progress:', i, 'out of', Number_of_CVE_Items, ' files of ', j, ' year.')
                # os.system('clear')     
                if CVE_ID != "" and SFTW != "" and RGE != "" and LOSSTYPE != "" and SEV != "" and ACCESS != "":             
                    Whole_Data.append((CVE_ID, SFTW, RGE, LOSSTYPE, SEV, ACCESS))                      
            del file   
            os.system('clear')     
            print('NVD Data of', j, 'year is read successfully!')
            
        else:
            print(file+' does not exist')           
    print('NVD Data is read successfully!')
    sleep(3)
    return Whole_Data




        

       

