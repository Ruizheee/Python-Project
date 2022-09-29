#Imports
import os, re

def message():
    os.system('cls')
    print(
        '''Welcome! Here, you can search for your favourite CVE details. 
This script mainly uses exploit-db as our source of data at the moment!"
To start off, You can provide a notepad file with details of the exploit that you want to search
E.g. You can provide the CVE number of the exploit 
----------------------------------------------------------------------------------
Contents of the file can be like the following:
cve-2018-5702
cve-2019-10969
cve-2022-34140
...
----------------------------------------------------------------------------------"
'''
    )

def processInputFile(file):
    '''
    This function just takes in the Full Path of the file that you want to feed to the script, 
    then proceeds to make use of regex to grab all the CVE numbers to search
    '''
    #Regex to detect cve numbers
    regex = "cve-\d{4}-\d+"
    #Checks if the full path of the file exists
    assert os.path.exists(file)
    #This list will be used to store all the CVE Numbers detected in the Input File
    cve_List = []
    with open(file,'r') as file_open: #Reading the data from the file
        content = file_open.read().splitlines()
        for line in content:
            if re.search(regex,line.lower()):
                cve_List.append(line.lower())
        return cve_List