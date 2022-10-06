'''
The following few functions are used to break down the Vector string. The Vector string includes the following information
- Attack Vector
- Attack Complexity
- Privileges Required
- User Interaction
- Confidentiality 
- Integrity 
- Availability 
'''
#Example of CVSS String: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
#vector_string = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
def vectorBreakDown(vector_string):
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
    attackVector = cvssDict.get('AV') 
    attackComplexity = cvssDict.get('AC')
    privilegesRequired = cvssDict.get('PR')
    userInteraction = cvssDict.get('UI')
    confidentiality = cvssDict.get('C')
    integrity = cvssDict.get('I')
    availability = cvssDict.get('A')
    attackVector_to_replace = {
        'N':'Network',
        'A':'Adjacent',
        'L':'Local',
    }
    rest_ofCharacters_to_replace = {
        'P':'Physical',
        'L':'Low',
        'H':'High',
        'R':'Required',
        'N':'None'
    }
    for key2,value2 in attackVector_to_replace.items():
        attackVector = attackVector.replace(key2,value2)
    print(attackVector)
    for key,value in rest_ofCharacters_to_replace.items():
        attackComplexity = attackComplexity.replace(key,value)
        privilegesRequired = privilegesRequired.replace(key,value)
        userInteraction = userInteraction.replace(key,value)
        confidentiality = confidentiality.replace(key,value)
        integrity = integrity.replace(key,value)
        availability = availability.replace(key,value)
    return cvssVersion,attackVector, attackComplexity, privilegesRequired, userInteraction, confidentiality, integrity, availability, 




