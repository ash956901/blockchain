########################################################### Backend for Python - Clinical Trial Blockchain Implementaion ########################################################################
# Developed on the Django Framework with Python, this prototype leverages encryption libraries, such as hashlib and cryptography, to ensure data integrity. The core                            #
# infrastructure is an emulated file-based blockchain network, designed to synchronize the changes in one system to all other systems in the chain. This demonstrates                           #
# important blockchain benefits, including immutability, full traceability, and transparency. We used the methodology of a clinical trial on Long COVID conducted at                            #
# St. Johns Medical College, Bengaluru, to emulate the working of a clinical trial. (Supplementary file)                                                                                        #
#                                                                                                                                                                                               #
# The detailed description of the methodology and Python codes are open sourced and posted in the GitHub repository (https://github.com/ictashik/BlockChain_ClinicalTrial).                     #
# Briefly, the views.py file contains the basic backend of the code. The building block of the code is the class named Block, and each block indicates the full data of one participant.        #
# Function load_or_generate_key() either retrieves an existing encryption key or crafts a new one. The foundation of the blockchain is established via create_genesis_block(), while            #
# create_new_block(previous_block, data) appends subsequent blocks. Data confidentiality is upheld through encrypt_data(data) and decrypt_data(encrypted_data) utilizing Fernet encryption.     #
# The persistence of blocks in the system is managed by save_block_to_file(block) and load_block_from_file(filepath). The verify_blockchain() function ascertains the blockchain's consistency. #
# For user interaction, SaveBlock(request) captures new block data through a form interface. Although the proof-of-concept demonstrates the feasibility of integrating blockchain principles    #
# into clinical trial processes through a web portal, this model is preliminary and not suited for production deployment.                                                                       #
#################################################################################################################################################################################################

from django.shortcuts import render, redirect

import hashlib
import os
import time
import glob
from cryptography.fernet import Fernet
import json
import pandas as pd
from datetime import datetime,timedelta
import random
from cryptography.fernet import InvalidToken
from django.http import HttpResponse
from django.contrib import messages # Import Django messages framework

# Create your views here.

#Key File Path
KEY_FILE = 'key.csv'
AUDIT_LOG_FILE = 'audit_log.csv' # New audit log file

#Random Date Generation Start and End Date. 
start_date = datetime(2019, 1, 1)
end_date = datetime(2020, 12, 31)


def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        return pd.read_csv(KEY_FILE, header=None).values[0][0]
    else:
        key = Fernet.generate_key().decode('utf-8')
        pd.DataFrame([key]).to_csv(KEY_FILE, index=False, header=False)
        return key

key = load_or_generate_key()

# key = Fernet.generate_key().decode('utf-8')
cipher_suite = Fernet(key.encode('utf-8'))

# Helper function to log audit events
def log_audit_event(event_type: str, description: str, related_info: str = "N/A"):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = pd.DataFrame([{
        'Timestamp': now,
        'EventType': event_type,
        'Description': description,
        'RelatedInfo': related_info
    }])
    
    audit_log_path = AUDIT_LOG_FILE 
    # Ensure directory exists if AUDIT_LOG_FILE includes a path, for now assuming it's in root
    # os.makedirs(os.path.dirname(audit_log_path), exist_ok=True) # If needed

    if not os.path.exists(audit_log_path):
        log_entry.to_csv(audit_log_path, index=False)
    else:
        log_entry.to_csv(audit_log_path, mode='a', header=False, index=False)
    print(f"AUDIT_LOG: {event_type} - {description} - {related_info}")

def index(request):
    print("DEBUG: Entered index function") # DEBUG PRINT
    #Name of the Chain
    chain = 'test'

    print("DEBUG: About to call create_blockchain") # DEBUG PRINT
    # create_blockchain(chain,10) # Comment this out for persistence
    print("DEBUG: Returned from create_blockchain") # DEBUG PRINT

    ChainDataFrame = get_blockchain_data()
    print("DEBUG: ChainDataFrame from get_blockchain_data in index view:")
    print(ChainDataFrame)

    # Prepare ChainDataFrame_json for table display (CDF)
    ChainDataFrame_json = [] # Default to empty list
    if not ChainDataFrame.empty:
        try:
            # Attempt to sort by ParticipantEnrollmentNumber if the column exists for consistent display
            # This is for display and should be robust even if data contains error strings.
            df_for_json = ChainDataFrame.copy()
            if 'ParticipantEnrollmentNumber' in df_for_json.columns:
                try:
                    # Convert to string before sorting to handle mixed types that might occur with error messages
                    df_for_json['ParticipantEnrollmentNumber'] = df_for_json['ParticipantEnrollmentNumber'].astype(str)
                    df_for_json = df_for_json.sort_values(by=['ParticipantEnrollmentNumber'])
                except Exception as e_sort:
                    print(f"DEBUG: Could not sort ChainDataFrame by ParticipantEnrollmentNumber for JSON display: {e_sort}")
            
            ChainDataFrame_json = json.loads(df_for_json.to_json(orient='records'))
            print("DEBUG: ChainDataFrame_json populated for table display.")
        except Exception as e_json:
            print(f"DEBUG: Error preparing ChainDataFrame for JSON conversion (table display might be empty): {e_json}")
            # ChainDataFrame_json will remain [] if error occurs
    else:
        print("DEBUG: ChainDataFrame from get_blockchain_data was empty.")
    

    # Initialize analytics variables
    ParticipantsCount = 0
    MaleCount = 0
    FeMaleCount = 0
    OthersCount = 0

    # Attempt analytics calculations on the original ChainDataFrame
    # These calculations might be less meaningful if data is corrupted, but we try.
    if not ChainDataFrame.empty and 'ParticipantEnrollmentNumber' in ChainDataFrame.columns and 'Sex' in ChainDataFrame.columns:
        try:
            # Filter out rows where ParticipantEnrollmentNumber might be an error string before counting for analytics
            valid_participants_df = ChainDataFrame[
                ~ChainDataFrame['ParticipantEnrollmentNumber'].astype(str).str.contains("DECRYPTION FAILED", case=False, na=False) &
                ~ChainDataFrame['ParticipantEnrollmentNumber'].astype(str).str.contains("MISSING DATA", case=False, na=False)
            ]
            if not valid_participants_df.empty:
                ParticipantsCount = valid_participants_df['ParticipantEnrollmentNumber'].count()
                MaleCount = valid_participants_df[valid_participants_df['Sex'] == 'M']['ParticipantEnrollmentNumber'].count()
                FeMaleCount = valid_participants_df[valid_participants_df['Sex'] == 'F']['ParticipantEnrollmentNumber'].count()
                OthersCount = valid_participants_df[valid_participants_df['Sex'] == 'O']['ParticipantEnrollmentNumber'].count()
            else:
                print("DEBUG: No valid participant data for analytics after filtering out errors.")
            print("DEBUG: Analytics calculated.")
        except KeyError as e_analytics_key:
            print(f"DEBUG: KeyError during DataFrame analytics: {e_analytics_key}. Analytics will be default/zero.")
        except Exception as e_analytics_other:
            print(f"DEBUG: General error during DataFrame analytics: {e_analytics_other}. Analytics will be default/zero.")
    else:
        print("DEBUG: ChainDataFrame empty or missing required columns for analytics. Analytics will be default/zero.")

    NotesDF_json = []
    ChainDF_from_csv = getchainDF(chain) # Renamed to avoid confusion with ChainDataFrame from blocks
    if not ChainDF_from_csv.empty:
        try:
            NotesDF_json  = json.loads(ChainDF_from_csv.to_json(orient='records'))
        except Exception as e:
            print(f"Error converting ChainDF (from test.csv) to JSON: {e}")
    
    chain_is_valid = verify_blockchain()
    ChainStatusMessage = "Valid" if chain_is_valid else "InValid"
    
    # If the chain is invalid due to decryption failure, some data might be error strings
    # The template should be robust to display these (which it is with [DECRYPTION FAILED])

    if chain_is_valid:
        log_audit_event("CHAIN_VERIFICATION", "Chain verification successful.", f"Accessed via: index view")
    else:
        log_audit_event("CHAIN_VERIFICATION_FAILED", "Chain verification FAILED.", f"Accessed via: index view")

    return render(request,'index.html',{'CHAIN':ChainStatusMessage,
                                        'CDF':ChainDataFrame_json, # Pass the JSON list
                                        'NDF':NotesDF_json,
                                        'ParticipantsCount':ParticipantsCount,
                                        'MaleCount':MaleCount,
                                        'FeMaleCount':FeMaleCount,
                                        'OthersCount':OthersCount,
                                        })

#Converts the CSV into Pandas Dataframe. CSV is for comparison with the chain data. Even if your Chain becomes invalid you can check the the csb file. 
def getchainDF(name):
    csv_path = name + '.csv'
    if os.path.exists(csv_path):
        try:
            ChainDF = pd.read_csv(csv_path)
            return ChainDF
        except pd.errors.EmptyDataError:
            print(f"Warning: {csv_path} is empty. Returning empty DataFrame.")
            return pd.DataFrame() # Return empty DataFrame for empty CSV
    else:
        print(f"Warning: {csv_path} not found. Returning empty DataFrame.")
        return pd.DataFrame() # Return empty DataFrame if CSV doesn't exist

#Class Definition
class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash

# SHA 256 Hash Calculation for the Block Data
def calculate_hash(index, previous_hash, timestamp, data_dictionary):
    # Convert the data dictionary to a sorted JSON string for consistent hashing
    try:
        json_string = json.dumps(data_dictionary, sort_keys=True)
    except TypeError as e:
        print(f"Error serializing data_dictionary to JSON: {e}. Data: {data_dictionary}")
        # Handle error appropriately, perhaps raise it or return a specific error hash
        raise
    value = str(index) + str(previous_hash) + str(timestamp) + json_string
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

#Creating the Genesis Block. Using Empty Data. 'data' is the dictionary that contains empty data. 
def create_genesis_block():
    data_dict = {
        "ParticipantEnrollmentNumber": "0",
        "Group": "None",
        "DateofEnrollment":"None",
        "Age": "0",
        "Sex": "None",
        "Education": "None",
        "Allergy": "None",
        "Vaccine": "None",
        "CoMorbidity": "None",
        "FollowUpDate": "None",
        "NoOfAntiHistamines": "0",
        "LongCovidFatigueFollowUp": "None",
        "LongCovidFatigueFollowUpEnrollment": "None",
        "Consent":"None",
        "EthicsApprovalID": "GENESIS_ETHICS_APPROVED"
    }
    encrypted_data_for_storage = encrypt_data(data_dict)
    timestamp = int(time.time())
    block_hash = calculate_hash(0, "0", timestamp, data_dict) # Pass data_dict
    #Calling the constructor for creating a Block object. 
    return Block(0, "0", timestamp, encrypted_data_for_storage, block_hash)

#Creates a New Block. The Previous Hash and Data are the inputs. 
def create_new_block(previous_block, data_dict):
    index = previous_block.index + 1
    timestamp = int(time.time())
    encrypted_data_for_storage = encrypt_data(data_dict)
    block_hash = calculate_hash(index, previous_block.hash, timestamp, data_dict) # Pass data_dict
    now = datetime.now()

    #Adding the same Data to CSV for Reference.
    csv_filename = 'test.csv' # Assuming 'test' is the chain name for this CSV
    expected_csv_headers = ['Name', 'Key', 'Time', 'Hash', 'Mess']
    
    ChainDict = {
        'Name' : 'test', # Corresponds to chain_name in create_blockchain
        'Key' : key,
        'Time' : now.strftime("%d/%m/%Y %H:%M:%S"),
        'Hash': block_hash,
        'Mess' : f"Block #{index} Added",
    }
    
    current_row_df = pd.DataFrame([ChainDict], columns=expected_csv_headers)

    if not os.path.exists(csv_filename):
        # Create new CSV with headers and the current row
        final_df_to_save = current_row_df
    else:
        # Append to existing CSV
        existing_df = pd.read_csv(csv_filename)
        final_df_to_save = pd.concat([existing_df, current_row_df], ignore_index=True)

    final_df_to_save.to_csv(csv_filename, index=False)
    return Block(index, previous_block.hash, timestamp, encrypted_data_for_storage, block_hash)

#The Data in the Dictionary is encrypted using Fernet Encryption. 
def encrypt_data(data):
    data_str = json.dumps(data)
    encrypted_data = cipher_suite.encrypt(data_str.encode('utf-8'))
    return encrypted_data.decode('utf-8')

#The Data in the Dictionary is decrypted using Fernet decryption. 
def decrypt_data(encrypted_data):
    try:
        decrypted_data_bytes = cipher_suite.decrypt(encrypted_data.encode('utf-8'))
        return json.loads(decrypted_data_bytes.decode('utf-8'))
    except InvalidToken:
        print(f"DECRYPTION ERROR: InvalidToken encountered for data starting with: {encrypted_data[:30]}...")
        return {"error": "DECRYPTION_FAILED", "original_data": encrypted_data} # Return a dict indicating error
    except Exception as e: # Catch other potential errors during decryption/JSON loading
        print(f"DECRYPTION ERROR: General error {type(e).__name__} for data: {encrypted_data[:30]}...")
        return {"error": f"GENERAL_DECRYPTION_ERROR: {type(e).__name__}", "original_data": encrypted_data}

#Saving the Block as a txt file. 
def save_block_to_file(block, folder='blocks'):
    os.makedirs(folder, exist_ok=True)
    filepath = f'{folder}/block_{block.index}.txt'
    print(f"Attempting to save block to: {filepath}")
    data = [str(block.index), block.previous_hash, str(block.timestamp), block.data, block.hash]
    with open(filepath, 'w') as f:
        f.write('\n'.join(data))
    print(f"Successfully saved block to: {filepath}")

#Reading the file to get the block contents
def load_block_from_file(filepath):
    with open(filepath, 'r') as f:
        lines = f.read().splitlines()
        #Calling class constructor to return the Block.
        return Block(int(lines[0]), lines[1], int(lines[2]), lines[3], lines[4])

#Creating New Blockchain. 
def create_blockchain(name,num_blocks_to_add):
    print("DEBUG: Entered create_blockchain") # DEBUG PRINT
    chain_name = str(name)
    # key = Fernet.generate_key()
    print("DEBUG: Calling create_genesis_block") # DEBUG PRINT
    blockchain = [create_genesis_block()]
    previous_block = blockchain[0]
    print(f"DEBUG: Genesis block object created, index: {blockchain[0].index}") # DEBUG PRINT

    save_block_to_file(blockchain[0]) # Explicitly save genesis block
    print("DEBUG: After saving genesis block") # DEBUG PRINT

    # ChainDF = pd.DataFrame()


    #Test Data Generation. Completely Random
    print("DEBUG: Entering loop to create more blocks") # DEBUG PRINT
    for i in range(1, num_blocks_to_add+1):
        print(f"DEBUG: Loop iteration i={i}") # DEBUG PRINT
        block_to_add = create_new_block(previous_block, {
            "ParticipantEnrollmentNumber": "L" + str(i),
            "Group": "A" if i%2 == 0 else "B",
            "DateofEnrollment":str(generate_random_date(start_date, end_date)),
            "Age": str(i*10),
            "Sex": "M" if i%2 == 0 else "F",
            "Education": "None",
            "Allergy": "Y" if i%2 == 0 else "N",
            "Vaccine": "Y" if i%2 == 0 else "N",
            "CoMorbidity": "Y" if i%2 == 0 else "N",
            "FollowUpDate": str(generate_random_date(start_date, end_date)),
            "NoOfAntiHistamines": i,
            "LongCovidFatigueFollowUp": "Y" if i%2 == 0 else "N",
            "LongCovidFatigueFollowUpEnrollment": "Y" if i%2 == 0 else "N",
            "Consent":"Y",
            "EthicsApprovalID": f"ETHICS_APP_{str(i).zfill(3)}"
        })
        blockchain.append(block_to_add)
        previous_block = block_to_add
        print(f"Block #{block_to_add.index} has been added to the blockchain!")
        print(f"Hash: {block_to_add.hash}\n")
        now = datetime.now()
        
        #The Same Data is saved as a CSV file for Reference.
        ChainDict = {
        'Name' : chain_name,
        'Key' : key,
        'Time' : now.strftime("%d/%m/%Y %H:%M:%S"),
        'Hash': block_to_add.hash,
        'Mess' : f"Block #{block_to_add.index} Added",
        }
        IndDF = pd.DataFrame([ChainDict])
        # ChainDF = pd.concat([ChainDF,IndDF])
        save_block_to_file(block_to_add)
        print(f"DEBUG: End of loop iteration i={i}") # DEBUG PRINT
    
    # ChainDF.to_csv(name+'.csv',index=False)
    print("DEBUG: Exiting create_blockchain") # DEBUG PRINT


# Verification of the Integrity of the Blockchain. If any of the hashes don't match, this function will return False.
def verify_blockchain(folder='blocks'):
    block_files = sorted(glob.glob(f'{folder}/*.txt'), key=os.path.getmtime)
    previous_hash = None
    for block_file in block_files:
        block = load_block_from_file(block_file)
        decrypted_data_dict = decrypt_data(block.data)

        if isinstance(decrypted_data_dict, dict) and 'error' in decrypted_data_dict:
            print(f"Integrity check failed for block #{block.index}: Decryption failed with error: {decrypted_data_dict['error']}")
            return False # If data can't be decrypted, content hash can't be verified against original content

        # Calculate hash based on decrypted content (now a dict)
        current_block_calculated_hash = calculate_hash(block.index, block.previous_hash, block.timestamp, decrypted_data_dict)
        
        #Checks if the previous block's hash and that marked in the current block is same. 
        if previous_hash is not None and previous_hash != block.previous_hash:
            print(f"Invalid block #{block.index}: Previous hash mismatch.")
            return False
        # Check if the stored hash matches the hash calculated from its decrypted content
        if current_block_calculated_hash != block.hash:
            print(f"Invalid hash in block #{block.index}: Stored hash does not match calculated hash of decrypted content.")
            return False
        previous_hash = block.hash
    print("Blockchain is valid.")
    return True

#Getting the Blockchain Data into pandas Dataframe.
def get_blockchain_data(folder='blocks'):
    block_files = sorted(glob.glob(f'{folder}/*.txt'), key=os.path.getmtime)
    blockchain_data = []
    # Define expected columns based on genesis block or a standard structure for consistent DataFrame columns
    # This helps if some blocks are corrupted and don't return all fields.
    expected_fields = [
        "ParticipantEnrollmentNumber", "Group", "DateofEnrollment", "Age", "Sex", 
        "Education", "Allergy", "Vaccine", "CoMorbidity", "FollowUpDate", 
        "NoOfAntiHistamines", "LongCovidFatigueFollowUp", 
        "LongCovidFatigueFollowUpEnrollment", "Consent", "EthicsApprovalID"
    ]

    for block_file in block_files:
        block = load_block_from_file(block_file) # block object has .index
        decrypted_content = decrypt_data(block.data) # this is a dict or error dict
        
        record = {'block_index': block.index} # Ensure block_index is always set first
        
        if isinstance(decrypted_content, dict) and 'error' in decrypted_content:
            print(f"Block {block.index} data could not be decrypted: {decrypted_content['error']}")
            # Set a specific placeholder for ParticipantEnrollmentNumber for corrupted blocks
            record['ParticipantEnrollmentNumber'] = f"[Data Corrupted - Block {block.index}]"
            for field in expected_fields:
                if field != 'ParticipantEnrollmentNumber': # Avoid overwriting the specific placeholder
                    record[field] = "[DECRYPTION FAILED]"
        elif isinstance(decrypted_content, dict): # Successfully decrypted dict
            for field in expected_fields:
                record[field] = decrypted_content.get(field, "[MISSING DATA]") # Use .get for safety
        else:
            # Should not happen if decrypt_data works as expected
            print(f"Block {block.index} returned unexpected data type from decrypt_data: {type(decrypted_content)}")
            record['ParticipantEnrollmentNumber'] = f"[Unknown Data Format - Block {block.index}]"
            for field in expected_fields:
                if field != 'ParticipantEnrollmentNumber':
                    record[field] = "[UNKNOWN DATA FORMAT]"

        blockchain_data.append(record)
    return pd.DataFrame(blockchain_data)

#Getting the Hash of last Block. 
def get_last_block_hash(folder='blocks'):
    block_files = sorted(glob.glob(f'{folder}/*.txt'), key=os.path.getmtime)
    if block_files:
        last_block = load_block_from_file(block_files[-1])
        return last_block.hash
    else:
        return None

#Random Date Generation
def generate_random_date(start_date, end_date):
    return start_date + timedelta(
        seconds=random.randint(0, int((end_date - start_date).total_seconds())))

#Returns the Last Block as Object.
def get_last_block(folder='blocks'):
    block_files = sorted(glob.glob(f'{folder}/*.txt'), key=os.path.getmtime)
    if block_files:
        last_block = load_block_from_file(block_files[-1])
        return last_block
    else:
        return None


#Saving a New Block. This utilized the Data transferred through POST. request is the input for this function. this should be called through Django Frontend. 
def SaveBlock(request):
    NewData = {
        "ParticipantEnrollmentNumber" : str(request.POST.get('ParticipantEnrollmentNumber')),
        "Group" : str(request.POST.get('Group')),
        "DateofEnrollment" : str(request.POST.get('DateofEnrollment')),
        "Age" : str(request.POST.get('Age')),
        "Sex" : str(request.POST.get('Sex')),
        "Education" : str(request.POST.get('Education')),
        "Allergy" : str(request.POST.get('Allergy')),
        "Vaccine" : str(request.POST.get('Vaccine')),
        "CoMorbidity" : str(request.POST.get('CoMorbidity')),
        "FollowUpDate" : str(request.POST.get('FollowUpDate')),
        "NoOfAntiHistamines" : str(request.POST.get('NoOfAntiHistamines')),
        "LongCovidFatigueFollowUp" : str(request.POST.get('LongCovidFatigueFollowUp')),
        "LongCovidFatigueFollowUpEnrollment" : str(request.POST.get('LongCovidFatigueFollowUpEnrollment')),
        "Consent" : str(request.POST.get('Consent')),
        "EthicsApprovalID" : str(request.POST.get('EthicsApprovalID'))
    }

    # print(NewData)
    last_block = get_last_block()
    new_block_index = last_block.index if last_block else 'N/A'
    save_block_to_file(create_new_block(last_block, NewData))
    log_audit_event("BLOCK_ADDED", f"New block #{new_block_index} added to the chain.", f"Participant: {NewData.get('ParticipantEnrollmentNumber')}")
    messages.success(request, f"Block #{new_block_index} added successfully!")
    return index(request)

def tamper_block(request, block_idx):
    folder = 'blocks'
    block_filename = f"{folder}/block_{block_idx}.txt"
    
    if os.path.exists(block_filename):
        try:
            with open(block_filename, 'r') as f:
                lines = f.read().splitlines()
            
            # Ensure there are enough lines and the data line exists (typically 4th line, index 3)
            if len(lines) >= 4:
                print(f"Original data for block {block_idx}: {lines[3]}")
                # Tamper: Change a character in the encrypted data string
                # This is a simple way to corrupt it. 
                # More robust tampering might involve specific bit changes if you knew the encryption.
                if len(lines[3]) > 0:
                    tampered_data = list(lines[3])
                    original_char_index = min(5, len(tampered_data) -1) # pick a char to change, not too far in
                    original_char = tampered_data[original_char_index]
                    # Change it to something else, e.g., 'A' to 'B', or lowercase to uppercase
                    tampered_data[original_char_index] = chr(ord(original_char) + 1) if original_char.isalpha() else 'X' 
                    lines[3] = "".join(tampered_data)
                    print(f"Tampered data for block {block_idx}: {lines[3]}")

                    with open(block_filename, 'w') as f:
                        f.write('\n'.join(lines))
                    print(f"Successfully tampered with block file: {block_filename}")
                    messages.success(request, f"Successfully tampered with block #{block_idx}.")
                    log_audit_event("BLOCK_TAMPERED", f"Block #{block_idx} data file was modified.", f"File: {block_filename}")
                else:
                    print(f"Data line in block {block_idx} is empty, cannot tamper.")
                    messages.info(request, f"Data line in block #{block_idx} is empty. No changes made.")
                    log_audit_event("BLOCK_TAMPER_NO_OP", f"Tamper attempt on block #{block_idx}, but data line was empty.", f"File: {block_filename}")
            else:
                print(f"Block file {block_filename} has too few lines to tamper data line.")
                messages.warning(request, f"Block file for block #{block_idx} has an unexpected format. No changes made.")
                log_audit_event("BLOCK_TAMPER_FORMAT_ERROR", f"Tamper attempt on block #{block_idx}, but file format was unexpected.", f"File: {block_filename}")
        except Exception as e:
            print(f"Error tampering block {block_idx}: {e}")
            messages.error(request, f"Error tampering block #{block_idx}: {e}")
            log_audit_event("BLOCK_TAMPER_FAILED", f"Error tampering block #{block_idx}: {e}", f"File: {block_filename}")
    else:
        print(f"Block file {block_filename} not found for tampering.")
        messages.warning(request, f"Block file for block #{block_idx} not found. Cannot tamper.")
        log_audit_event("BLOCK_TAMPER_NOT_FOUND", f"Tamper attempt on block #{block_idx}, but file was not found.", f"File: {block_filename}")
        
    return redirect('index') # Redirect back to the main page

def initialize_new_blockchain(request):
    print("INITIALIZE: Attempting to initialize a new blockchain.")
    
    # 1. Delete existing block files from the 'blocks' directory
    blocks_folder = 'blocks'
    if os.path.exists(blocks_folder):
        for filename in glob.glob(os.path.join(blocks_folder, 'block_*.txt')):
            try:
                os.remove(filename)
                print(f"INITIALIZE: Deleted old block file: {filename}")
            except OSError as e:
                print(f"INITIALIZE ERROR: Could not delete file {filename}: {e}")
    else:
        os.makedirs(blocks_folder) # Ensure blocks folder exists

    # 2. Delete existing test.csv (if it exists)
    test_csv_file = 'test.csv' # Assuming it's in the BCCT directory
    if os.path.exists(test_csv_file):
        try:
            os.remove(test_csv_file)
            print(f"INITIALIZE: Deleted old {test_csv_file}")
        except OSError as e:
            print(f"INITIALIZE ERROR: Could not delete file {test_csv_file}: {e}")

    # 3. Delete and regenerate key.csv to ensure fresh encryption for the new chain
    # This ensures old keys don't try to decrypt new blocks or vice-versa if something was mixed up.
    # For a real system, key management is more complex, but for this demo, a fresh key is simplest.
    key_file_path = KEY_FILE # KEY_FILE is a global 'key.csv'
    if os.path.exists(key_file_path):
        try:
            os.remove(key_file_path)
            print(f"INITIALIZE: Deleted old key file: {key_file_path}")
        except OSError as e:
            print(f"INITIALIZE ERROR: Could not delete key file {key_file_path}: {e}")
    
    # Reload the key (it will be regenerated by load_or_generate_key)
    global key, cipher_suite # We need to update the global key and cipher_suite
    key = load_or_generate_key()
    cipher_suite = Fernet(key.encode('utf-8'))
    print(f"INITIALIZE: New encryption key generated and loaded.")
    log_audit_event("KEY_REGENERATED", "A new encryption key was generated.")

    # 4. Call create_blockchain to generate new blocks
    chain_name = 'test' # Or get from config/request if needed
    num_blocks = 10     # Or get from config/request
    try:
        print(f"INITIALIZE: Calling create_blockchain('{chain_name}', {num_blocks})")
        create_blockchain(chain_name, num_blocks)
        print("INITIALIZE: create_blockchain completed.")
    except Exception as e:
        print(f"INITIALIZE ERROR: Error during create_blockchain: {e}")
        # Optionally, you could add a Django message here to show the error on the page
        messages.error(request, f"Error initializing blockchain: {e}")
        log_audit_event("BLOCKCHAIN_INIT_FAILED", f"Error during create_blockchain: {e}")
        return redirect('index') # Redirect even if there was an error during creation

    messages.success(request, "Blockchain successfully initialized with new data!")
    log_audit_event("BLOCKCHAIN_INITIALIZED", f"Blockchain re-initialized with {num_blocks} new blocks.")
    return redirect('index') # Redirect back to the main page

def view_block_detail(request, block_idx):
    folder = 'blocks'
    block_filename = f"{folder}/block_{block_idx}.txt"
    block_data = None
    error_message = None
    log_audit_event("BLOCK_VIEW_ATTEMPT", f"Attempting to view details for block #{block_idx}.", f"File: {block_filename}")

    if os.path.exists(block_filename):
        try:
            # Load the raw block object
            block_object = load_block_from_file(block_filename)
            print(f"DEBUG view_block_detail: Loaded block {block_idx}. Stored hash: {block_object.hash}")
            print(f"DEBUG view_block_detail: Encrypted data from file (first 100 chars): {block_object.data[:100]}")
            
            # Decrypt its data content
            decrypted_patient_data = decrypt_data(block_object.data)
            print(f"DEBUG view_block_detail: Decrypted patient data for block {block_idx}: {decrypted_patient_data}")
            
            # Prepare context for the template
            block_data = {
                'index': block_object.index,
                'timestamp': datetime.fromtimestamp(block_object.timestamp).strftime('%Y-%m-%d %H:%M:%S'), # Format timestamp
                'previous_hash': block_object.previous_hash,
                'hash': block_object.hash, # Stored hash
                'encrypted_data_str': block_object.data, 
                'patient_data': decrypted_patient_data,
                'recalculated_hash': None, # Initialize
                'hashes_match': False # Initialize
            }

            if isinstance(decrypted_patient_data, dict) and 'error' not in decrypted_patient_data:
                # Re-encrypt and re-calculate hash for verification display
                try:
                    print(f"DEBUG view_block_detail: Attempting to recalculate hash for block {block_idx} based on decrypted data.")
                    # For recalculation, pass the decrypted dictionary directly
                    recalculated_hash = calculate_hash(block_object.index, 
                                                       block_object.previous_hash, 
                                                       block_object.timestamp, 
                                                       decrypted_patient_data) # Pass the dict
                    block_data['recalculated_hash'] = recalculated_hash
                    block_data['hashes_match'] = (block_object.hash == recalculated_hash)
                    print(f"DEBUG view_block_detail: Recalculated hash: {recalculated_hash}, Hashes_match: {block_data['hashes_match']}")
                except Exception as e:
                    print(f"Error during re-encryption/hash calculation for block {block_idx} view: {e}")
                    # Keep default None/False for recalculated_hash and hashes_match
            elif isinstance(decrypted_patient_data, dict) and 'error' in decrypted_patient_data:
                print(f"DEBUG view_block_detail: Decryption error detected for block {block_idx}. 'recalculated_hash' and 'hashes_match' will use default False/None.")
            else:
                print(f"DEBUG view_block_detail: Decrypted data for block {block_idx} is not a dict or no error key, but not processed for hash recalc. State: {decrypted_patient_data}")
            
            if isinstance(decrypted_patient_data, dict) and 'error' in decrypted_patient_data:
                block_data['decryption_error'] = decrypted_patient_data['error']
                log_audit_event("BLOCK_VIEW_DECRYPTION_ERROR", f"Decryption error viewing block #{block_idx}. Error: {decrypted_patient_data['error']}", f"File: {block_filename}")

        except Exception as e:
            print(f"Error loading or processing block {block_idx} for detail view: {e}")
            error_message = f"Could not load or process details for block {block_idx}. Error: {e}"
            log_audit_event("BLOCK_VIEW_LOAD_ERROR", f"Error loading/processing block #{block_idx} for detail view: {e}", f"File: {block_filename}")
    else:
        error_message = f"Block file {block_filename} not found."
        log_audit_event("BLOCK_VIEW_NOT_FOUND", f"Attempt to view block #{block_idx}, but file not found.", f"File: {block_filename}")

    return render(request, 'CTPortal/block_detail.html', {
        'block': block_data,
        'error_message': error_message,
        'block_idx': block_idx # Pass original index for titling or messages
    })

def verify_chain_view(request):
    # This view simply triggers the verification logic which is already part of get_blockchain_data
    # and by redirecting to index, the template will get the updated chain_status.
    # verify_blockchain() # Called by get_blockchain_data, which is called by index
    # For explicit audit logging from this specific action:
    chain_is_valid = verify_blockchain() # Re-verify to log its specific status from this endpoint
    if chain_is_valid:
        log_audit_event("CHAIN_VERIFICATION", "Chain verification successful.", f"Triggered by: 'Verify Chain Integrity' button")
    else:
        log_audit_event("CHAIN_VERIFICATION_FAILED", "Chain verification FAILED.", f"Triggered by: 'Verify Chain Integrity' button")
    return redirect('index')

def public_portal_view(request):
    # Fetch only aggregated data for the public view
    ChainDataFrame = get_blockchain_data() 
    ParticipantsCount = 0
    if not ChainDataFrame.empty and 'ParticipantEnrollmentNumber' in ChainDataFrame.columns:
        ParticipantsCount = ChainDataFrame['ParticipantEnrollmentNumber'].count()
    
    chain_is_valid = verify_blockchain()
    ChainStatusMessage = "Valid" if chain_is_valid else "InValid"
    
    context = {
        'ParticipantsCount': ParticipantsCount,
        'CHAIN_STATUS': ChainStatusMessage,
        'page_title': "Public Clinical Trial Information"
    }
    return render(request, 'CTPortal/public_portal.html', context)

def audit_log_view(request):
    audit_log_data_json = []
    if os.path.exists(AUDIT_LOG_FILE):
        try:
            df = pd.read_csv(AUDIT_LOG_FILE)
            # Sort by timestamp, most recent first
            df['Timestamp'] = pd.to_datetime(df['Timestamp'])
            df = df.sort_values(by='Timestamp', ascending=False)
            df['Timestamp'] = df['Timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S') # Convert back to string for JSON
            audit_log_data_json = json.loads(df.to_json(orient='records'))
        except pd.errors.EmptyDataError:
            print(f"AUDIT_LOG: {AUDIT_LOG_FILE} is empty.")
        except Exception as e:
            print(f"Error reading or processing audit log: {e}")
            messages.error(request, f"Could not load audit log: {e}")

    context = {
        'audit_log_entries': audit_log_data_json,
        'page_title': "System Audit Log"
    }
    return render(request, 'CTPortal/audit_log.html', context)
