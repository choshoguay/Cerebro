

# -------- External Modules --------

import os
from datetime import datetime
from dateutil.relativedelta import relativedelta
import zipfile
import fileAttributesClass
import re

# -------- Global Variables --------

#s3 = '\\\\10.38.97.45\\ci475316-fed-s3-storage-share\\customers #use this at the end 
s3 = 'E:\\Customers' ##for testing

organization = {
    'CIV_LEA': ['NA'],
    'DoD': ['Army', 'DLA', 'Navy', 'USAF', 'USMC']
}
postgres_db = '10.1.233.199'
destination_path = 'C:/Users/Public/Downloads/New_CKLs'

date_patterns = [ #ORDER HERE MATTERS - IT SHOULD MATCH AGAINST THE LONGEST DATE FORMAT FIRST
    
    (r'.(\d{8}).', '%Y%m%d'),  # 20211228
    (r'.(\d{8}).', '%d%m%Y'),  # 28122021
    (r'.(\d{8}).', '%m%d%Y'),  # 12282021
    (r'.(\d{6}).', '%y%m%d'),  # 211228
    (r'.(\d{2}\d{2}\d{4}).', '%m%d%Y'),  # 01012022
    (r'.(\d{2}\d{2}\d{2}).', '%m%d%y'),  # 010122
    (r'.(\d{2}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{4}).', '%d%b%Y'),  # 28Jan2022
    (r'.(\d{2}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{2}).', '%d%b%y'),  # 28Jan22
    (r'.(\d{4}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{2}).', '%Y%b%d'),  # 2022Jan28
    (r'.(\d{2}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{2}).', '%y%b%d'),  # 22Jan28


    
    #(r'\b\d{8}\b', '%Y%m%d'), # 20211228
    #(r'\b\d{8}\b', '%d%m%Y'),  # 28122021
    #(r'\b\d{8}\b', '%m%d%Y'),  # 12282021
    #(r'\b\d{6}\b', '%y%m%d'), # 211228
    #(r'\b\d{2}\d{2}\d{4}\b', '%m%d%Y'), # 01012022

    #UNDERSCORES
    #(r'_(\d{8})\.', '%m%d%Y'),  # _08142018.
    #(r'_(\d{8})\.', '%Y%m%d'),  # _20180822.
    #(r'_(\d{8})\.', '%Y%m%d'),  # _20180822.
    #(r'_(\d{8})_', '%Y%m%d'), # _20211228_

    #(r'\b\d{2}\d{2}\d{2}\b', '%m%d%y'), # 010122
    #(r'\b\d{2}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{4}\b', '%d%b%Y'), # 28Jan2022
    #(r'\b\d{2}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{2}\b', '%d%b%y'), # 28Jan22
    #(r'\b\d{4}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{2}\b', '%Y%b%d'), # 2022Jan28
    #(r'\b\d{2}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{2}\b', '%y%b%d'), # 22Jan28
    
    #UNDERSCORES
    #(r'_(\d{6})_', '%y%m%d'), # _211228_
    #(r'_(\d{2}\d{2}\d{4})_', '%m%d%Y'), # _01012022_
    #(r'_(\d{2}\d{2}\d{2})_', '%m%d%y'), # _010122_
    #(r'_(\d{2}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{4})_', '%d%b%Y'), # _28Jan2022_
    #(r'_(\d{2}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{2})_', '%d%b%y'), # _28Jan22_
    #(r'_(\d{4}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{2})_', '%Y%b%d'), # _2022Jan28_
    #(r'_(\d{2}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{2})_', '%y%b%d'), # _22Jan28_
]

# -------- Private Functions --------

## FUNCTION : GET THE AGE OF THE FILE BASED ON THE NAMING IN THE FILE I.E. AUDIT_10JAN21_INITIALS.CKL
## PARAMETER : FILE NAME

def get_file_age(filepath):
    filename = os.path.basename(filepath)
    print(filepath)
    for pattern, date_format in date_patterns:
        match = re.search(pattern, filename)
        if match:
            date_str = match.group()
            if '_' in date_str:  
                date_str = match.group(1)
            date = datetime.strptime(date_str, date_format)
            age = (datetime.now() - date).days
            return filename, age
    #return filename, "does not match any date patterns"


## FUNCTION : GRAB THE S3 DIRECTORY PATH TO FILES AND THEN EXTRACT 
## PARAMETER : TAKES IN LIST OF ZIP FILES AND THE DESTINATION TO EXTRACT TO

def extract_files_from_s3(zips, raw_files, destination):
    
    error_files = []

    for zip_file in zips:
        directory = os.path.dirname(zip_file)
        constant_path = 'Customers\\'
        directory_parts = directory.split(constant_path)
        directory = constant_path + directory_parts[1]
        folder_structure = destination + directory
        if not os.path.exists(folder_structure):
            try:
                print(f'Creating {folder_structure}...')
                os.makedirs(folder_structure, exist_ok=True)
            except PermissionError:
                print(f"Unable to create {folder_structure}. Please close any open files and try again.")
                return
            with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                print(f'Extracting {zip_file} to {folder_structure}')
                try:
                    zip_ref.extractall(folder_structure)
                except FileNotFoundError as e:
                    error_files.append(folder_structure)
                    print(f"Unable to extract files to {folder_structure}. Error {e}. Please check the path and try again.")
                    continue
        else:
            print(f'{folder_structure} already exists. Skipping extraction.')
            continue

    #for files in raw_files:
    #    directory = os.path.dirname(files)
    #    constant_path = 'Customers\\'
    #    directory_parts = directory.split(constant_path)
    #    directory = constant_path + directory_parts[1]
    #    folder_structure = destination + directory




## FUNCTION : SCAN S3 DIRECTORY FOR RESPECTIVE ZIP FILES THAT CONTAIN THE SCAN DATA
## PARAMETER : S3 DIRECTORY PATH

def getNewScans(directory):

    now = datetime.now()
    two_years_ago = now - relativedelta(days=730) #temporarily use 2 years for the initial run, then switch to 7 days 

    #seven_days_ago = now - relativedelta(days=7)

    zip_files = []
    raw_ckls = []  
    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            ##insert file object creation here
            ##maybe use this place to differentiate between files that exist within a database or whether it's new?
            file = os.path.join(dirpath, filename)
            
            #if it's a .zip file
            if filename.endswith('.zip') and filename.startswith('Deliverables'):
                if(two_years_ago < datetime.fromtimestamp(os.path.getctime(file))):
                    #print(f'Found zip {file}: Appending to zip list...')
                    zip_files.append(file)

            #if it's a raw ckl
            if filename.endswith('.ckl'):
                try:
                    if(two_years_ago < datetime.fromtimestamp(os.path.getctime(file))):
                        #print(f'Found {file}: Appending to file list...')
                        raw_ckls.append(file.replace("/", "\\"))
                except FileNotFoundError as e:
                    print(f"Error: {e}")
                    continue

    return zip_files, raw_ckls

# -------- Public Functions --------

def main():
    print('Start Time: ', datetime.now().strftime("%m/%d/%Y %H:%M:%S"))
    zip_list, raw_ckls = getNewScans(s3)
    count = 0 
    for i in range(len(raw_ckls)):
        if not get_file_age(raw_ckls[i]) == None:
            count += 1
        print(get_file_age(raw_ckls[i]))
    print(count)
    print(len(raw_ckls))
    #extract_files_from_s3(zip_list, raw_ckls, destination_path)
    print('End Time: ', datetime.now().strftime("%m/%d/%Y %H:%M:%S"))

if __name__ == '__main__':
    main()


