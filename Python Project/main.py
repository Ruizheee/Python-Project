import lib.fileInput as fi
import lib.nist as nist_func
import lib.output_csv as out_csv
import lib.ransom_gangname as ransom
import lib.popularCVE as popular

def main():
    """
    Main function
    """
    fi.message()
    csvName = input("What name do you want your csv file to be? ")
    ransom_grouplist = ransom.get_ransomware_gang()[0]
    cve_numberDict = ransom.search_Ransomware_gang(ransom_grouplist)
    print("Writing to " + csvName + " now!")
    for groupname,cve_numberList in cve_numberDict.items():
        for index in range(len(cve_numberList)):
            detailsList = nist_func.queryNist(cve_numberList[index])
            if detailsList is not None:
                detailsList.insert(0,groupname)
                out_csv.write_tofile(detailsList,csvName)
            else:
                pass
    popular.count_PopularCve(f'{csvName}.csv')
    popular.count_YearlyCve(f'{csvName}.csv')
    popular.yearly_mostActiveGroup(f'{csvName}.csv')
    print('Script completed')

if __name__ == "__main__":
    main()