import requests, re
from time import sleep
from bs4 import BeautifulSoup
import lib.processVector as processVector
import lib.processCPE as processCPE 
def queryNist(cveNumber):
    """
    This function takes in the CVE numbers from the txt file given through another function called fileInput
    With each CVE number, it then attempts to concatenate 'site:https://nvd.nist.gov/vuln/detail/' to try to get more data through the nvd.nist.gov website.
    Information that this function retrieves:
    - CVSS Score 
    - Vector String (e.g. CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H), which then makes use of another function called decodeFunc to break up the string and extract usable data from it.
    - A list of CPE Strings (e.g. cpe:2.3:a:transmissionbt:transmission:*:*:*:*:*:*:*:*), which then makes use of another function called cpeExtractor to break up the strings and extract more usable data from them.
    """
    headers = {"User_Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"}
    cveSearch = 'https://nvd.nist.gov/vuln/detail/' + cveNumber #Makes use of google dorking to search for results from nvd.nist.gov
    try:
        sleep(5)
        searchResults = requests.get(cveSearch, headers=headers)
        response = searchResults.content
        soup = BeautifulSoup(response,'lxml')
        #Get the CVSS Score
        getCVSS = soup.find_all("div",{"class":"col-lg-3 col-sm-6"})
        cvssScore = re.findall("(\d{1,2}\.\d\s)\w+",str(getCVSS))[0]
        #Get the Description
        getDescriptionClass = soup.find("div",{"class":"col-lg-9 col-md-7 col-sm-12"})
        getDescription = getDescriptionClass.find_all("p",{"data-testid":"vuln-description"})
        removeWordList = ['[<p data-testid="vuln-description">','</p>]'] #Cleaning up the description
        for words in removeWordList:
            getDescription = str(getDescription).replace(words,'')
        #Get the vector string
        getVector = soup.find_all("div",{"class":"col-lg-6 col-sm-12"})
        vector = re.findall("CVSS:\d\.\d\S+",str(getVector))[0] #Using regex to grab the vector string
        #Cleaning and processing the vector string
        vector = vector.replace('</span>','')
        vector = processVector.vectorBreakDown(vector)
        #Finding the CPE String
        findTable = soup.findAll('table',attrs={'data-testid':'vuln-change-history-table'})
        searchSoftwareConfiguration = re.findall("cpe\:\S\.*\S+(?:\s\S+\s\S+\s\S+\s\()?(?:excluding\)|including\))?(?:\s\d+\.\d+)?",str(findTable))
        #Cleaning the CPE String
        for index in range(len(searchSoftwareConfiguration)):
            searchSoftwareConfiguration[index] = searchSoftwareConfiguration[index].replace('</pre>','')
        #Appends all the data into a list 
        cvssVersion = vector[0]
        detailsList = [cveNumber.upper(),cvssVersion,cvssScore,getDescription]
        for number in range(1,len(vector)):
            detailsList.append(vector[number])
        #Appending the CPE String into the list
        detailsList.append(processCPE.cpeBreakDown(searchSoftwareConfiguration))
        return detailsList
    except:
        message = "No such CVE Record for " + cveNumber.upper()
        print(message)

