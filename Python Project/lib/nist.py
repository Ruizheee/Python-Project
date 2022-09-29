import requests, re
from googlesearch import search
from bs4 import BeautifulSoup
import lib.processVector as processVector
import lib.processCPE as processCPE
def queryNist(cveNumbers):
    """
    This function takes in the CVE numbers from the txt file given through another function called fileInput
    With each CVE number, it then attempts to concatenate 'site:https://nvd.nist.gov/vuln/detail/' to try to get more data through the nvd.nist.gov website.
    Information that this function retrieves:
    - CVSS Score 
    - Vector String (e.g. CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H), which then makes use of another function called decodeFunc to break up the string and extract usable data from it.
    - A list of CPE Strings (e.g. cpe:2.3:a:transmissionbt:transmission:*:*:*:*:*:*:*:*), which then makes use of another function called cpeExtractor to break up the strings and extract more usable data from them.
    """
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"}
    cveSearch = 'site:https://nvd.nist.gov/vuln/detail/' + cveNumbers #Makes use of google dorking to search for results from nvd.nist.gov
    for results in search(cveSearch, tld="com", num=20, start=0, stop=25, pause=2):
        try:
            #Perform a request to the URL found from the google search
            searchResults = requests.get(results, headers=headers)
            #Get the response
            response = searchResults.content
            #Make use of BeautifulSoup to parse the response into lxml format
            soup = BeautifulSoup(response, 'lxml')
            #Get the CVSS Score
            getCVSS = soup.find_all("div",{"class":"col-lg-3 col-sm-6"})
            cvssScore = re.findall("(\d\.\d\s)\w+",str(getCVSS))[0]
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
            detailsList = [cveNumbers.upper(),cvssScore,getDescription]
            for number in range(len(vector)):
                detailsList.append(vector[number])
            #Appending the CPE String into the list
            detailsList.append(processCPE.cpeBreakDown(searchSoftwareConfiguration))
            return detailsList
        except:
            message = "No such CVE Record for " + cveNumbers.upper()
            print(message)
        

