import re
def cpeBreakDown(cpeStringList):
    '''
    This function takes in the list of CPE Strings from the nist function and proceeds to manipulate and break the string up into smaller but more usable information.
    Information that it can provide:
    - Part Component (This field identifies the kind of platform) (E.g. Application, Operating System, Hardware)
    - Vendor
    - Product
    - Version Affected
    '''
    upToVersionList = [] #Some CPE Strings have another column with "Up to (Including) or (Excluding) x.xx Version Number"
    information_List = [] #This list will be used to store all the data extracted
    for number in range(len(cpeStringList)):
        cpeString = cpeStringList[number] 
        try:
            #Perform a regex search for to see if there is any "Up to (Including) or (Excluding) x.xx Version Number String"
            upToVersionNumber = re.search(r'versions\s\S+\s\S+\s\((?:excluding\)|including\))\s\d+\.\d+',str(cpeString))
            if upToVersionNumber: #If there is
                upToVersionNumber = str(upToVersionNumber).split("'",1)[1] #Cleaning up the string
                wordsToReplace = [">","'"] 
                for words in wordsToReplace:
                    upToVersionNumber = upToVersionNumber.replace(words,'')
                upToVersionList.append(upToVersionNumber)
                cpeString = cpeString.replace(upToVersionNumber,'')
            else: 
                #Else if there is no string, I append a empty list to maintain the index number  
                #So that I know which CPE String the Version Number String belongs to
                upToVersionList.append([])
        except:
            continue
        cpeString = cpeString.split(':') #Each column of the CPE String that is delimited by the ':' provides information
        part = cpeString[2] #This column determines what type of platform is this exploit about
        if part == 'a':
            part = 'Application'
        elif part == 'o':
            part = 'Operating System'
        elif part == 'h':
            part = 'Hardware Devices'
        vendor = cpeString[3] #Vendor of the product that is affected
        product = cpeString[4] #Product that is affected
        #Version number of the product that is affected, 
        #Sometimes, it will be written in the "Up to (Including) or (Excluding) x.xx Version Number String"
        version = cpeString[5]
        upToVersionNumber = upToVersionList[number]
        detailsList = [part,vendor,product]
        #Check if the "Up to (Including) or (Excluding) x.xx Version Number String" exists
        if upToVersionNumber: 
            detailsList.append(upToVersionNumber)
        else: 
            detailsList.append(version)
        information_List.append(detailsList)
    return information_List

