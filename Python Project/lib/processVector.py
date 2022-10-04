'''
The following few functions are used to break down the Vector string. The Vector string includes the following information
- Attack Vector
- Attack Complexity
- Privileges Required
- User Interaction
- Confidentiality (Will information be lost)
- Integrity (Will information be altered)
- Availability (Will information be lost)
'''
#Example of CVSS String: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
#vector_string = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
def cvssSplitFunc(vector_string):
    vector_string = vector_string.split('/') #Split by '/' to get the values of each column
    vectorSeparatedList = [] #This list will be used to store the key and value of each column
    for i in range(len(vector_string)):
        vector_string[i] = vector_string[i].split(':') #Get the key and value of each column
    for element in vector_string: #Appends all the key and value into the new list
        for item in element: 
            vectorSeparatedList.append(item)
    #Now that we have all the keys and values in the list, I will be separating the entire list into two
    #First list will include all the keys
    #Second list will include all the values
    #Then I will proceed to make a dictionary with these two lists 
    nameList = vectorSeparatedList[::2] #Making the first list
    valueList = vectorSeparatedList[1::2] #Making the second list
    cvssDict = dict(zip(nameList,valueList)) #Converting both to dictionary
    cvssVersion = cvssDict.get('CVSS') 
    return cvssDict, cvssVersion



def attackVectorFunc(vector_string): 
    cvssDict = cvssSplitFunc(vector_string)[0]
    attackVector = cvssDict.get('AV')
    if attackVector == 'N':
        attackVector = 'Network'
    elif attackVector == 'A':
        attackVector = 'Adjacent'
    elif attackVector == 'L':
        attackVector = 'Local'
    elif attackVector == 'P':
        attackVector = 'Physical'
    return attackVector

def attackComplexityFunc(vector_string):
    cvssDict = cvssSplitFunc(vector_string)[0]
    attackComplexity = cvssDict.get('AC')
    if attackComplexity == 'L':
        attackComplexity = 'Low'
    elif attackComplexity == 'H':
        attackComplexity = 'High'
    return attackComplexity

def privilegesRequiredFunc(vector_string):
    cvssDict = cvssSplitFunc(vector_string)[0]
    privilegesRequired = cvssDict.get('PR')
    if privilegesRequired == 'N':
        privilegesRequired = 'None'
    elif privilegesRequired == 'L':
        privilegesRequired = 'Low'
    elif privilegesRequired == 'H':
        privilegesRequired = 'High'
    return privilegesRequired

def userInteractionFunc(vector_string):
    cvssDict = cvssSplitFunc(vector_string)[0]
    userInteraction = cvssDict.get('UI')
    if userInteraction == 'R':
        userInteraction = 'Required'
    elif userInteraction == 'N':
        userInteraction = 'None'
    return userInteraction

def confidentialityFunc(vector_string):
    cvssDict = cvssSplitFunc(vector_string)[0]
    confidentiality = cvssDict.get('C')
    if confidentiality == 'H':
        confidentiality = 'High'
    elif confidentiality == 'L':
        confidentiality = 'Low'
    elif confidentiality == 'N':
        confidentiality = 'None'
    return confidentiality

def integrityFunc(vector_string):
    cvssDict = cvssSplitFunc(vector_string)[0]
    integrity = cvssDict.get('I')
    if integrity == 'H':
        integrity = 'High'
    elif integrity == 'L':
        integrity = 'Low'
    elif integrity == 'N':
        integrity = 'None'
    return integrity

def availabilityFunc(vector_string):
    cvssDict = cvssSplitFunc(vector_string)[0]
    availability = cvssDict.get('A')
    if availability == 'H':
        availability = 'High'
    elif availability == 'L':
        availability = 'Low'
    elif availability == 'N':
        availability = 'None'
    return availability

def vectorBreakDown(vector_string):
    attackVector = attackVectorFunc(vector_string)
    attackComplexity = attackComplexityFunc(vector_string)
    privilegesRequired = privilegesRequiredFunc(vector_string)
    userInteractions = userInteractionFunc(vector_string)
    confidentiality = confidentialityFunc(vector_string)
    integrity = integrityFunc(vector_string)
    availability = availabilityFunc(vector_string)
    return attackVector, attackComplexity, privilegesRequired, userInteractions, confidentiality, integrity, availability

