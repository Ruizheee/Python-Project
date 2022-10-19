import lib.fileInput as fi
import lib.nist as nist_func
import lib.output_csv as out_csv
import lib.getRansomwareList as ransomware_list
import lib.searchRansomResults as ransomware_results

def main():
    """
    Main function
    """
    fi.message()
    csvName = input("What name do you want your csv file to be? ")
    ransom_grouplist = ransomware_list.get_ransomware_gang()[0]
    cve_numberDict = ransomware_results.search_Ransomware_gang(ransom_grouplist)
    print("Writing to " + csvName + " now!")
    for groupname,cve_numberList in cve_numberDict.items():
        for index in range(len(cve_numberList)):
            detailsList = nist_func.queryNist(cve_numberList[index])
            if detailsList is not None:
                detailsList.insert(0,groupname)
                out_csv.write_tofile(detailsList,csvName)
            else:
                pass
    print('Script completed')

if __name__ == "__main__":
    main()