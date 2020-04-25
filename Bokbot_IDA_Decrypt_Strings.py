'''
BokBot shellcode strings decryption
'''
import struct
import string

def is_readable_string(decrypt_string):
    return all(ord(c) < 127 and c in string.printable for c in decrypt_string)

def find_named_func_addr(named_func):
    seg=idaapi.getnseg(0) #we are in shellcode so...
    if seg:
        funcs=Functions(seg.startEA, seg.endEA)
        for funcaddress in funcs:
            f_name= GetFunctionName(funcaddress)
            if f_name == named_func:
                return funcaddress

def find_function_arg(addr):
    addr = idc.PrevHead(addr)
    if GetMnem(addr) == "push":
        return GetOperandValue(addr, 0)
    return 0;    

def find_error_address(addr):
    addr = idc.PrevHead(addr-4)
    if GetMnem(addr) == "push":
        return GetOperandValue(addr, 0)
    return 0;    

def get_string(addr,passed_counter):
    return GetManyBytes(addr,passed_counter)
 

def decrypt_string(addr,encrypted_string_first_bytes):
    plaintext = []
    xor_key = encrypted_string_first_bytes[:4]
    xor_key = struct.unpack('<L',xor_key)[0]
    string_length = encrypted_string_first_bytes[4:6]
    string_length =  ( struct.unpack('<H',string_length)[0] ^  struct.unpack('<L',encrypted_string_first_bytes[:4])[0])&0xFFFF
    full_encrypted_string = get_string(addr,string_length+6) #Now we need how many bytes to read so read again.
    ciphertext = full_encrypted_string[6:]
    
    for i in range(string_length):
        xor_key = i + ( ((xor_key << 29)& 0xffffffff) | (xor_key >> 3));
        decrypted_character =  chr((xor_key&0xff)^ord(ciphertext[i]))
        if decrypted_character != '\x00':
            plaintext.append(decrypted_character)
            
    return ''.join(plaintext)


decryption_function_address = FindBinary(0, SEARCH_DOWN, "0F B6 04 01 0F B6 4D F4 33 C1");

encryption_function =  GetFunctionName(decryption_function_address)

decryption_function_start_address =  find_named_func_addr(encryption_function)

for addr in XrefsTo(decryption_function_start_address, flags=0):
    try:
        encrypted_address_candidate = find_function_arg(addr.frm)
        if encrypted_address_candidate:
            encrypted_string_first_bytes  =  get_string(encrypted_address_candidate,6) #We do not know how many bytes are the encrypted string. Get the first 6 and calculate the required size
            decrypted_string = decrypt_string(encrypted_address_candidate,encrypted_string_first_bytes)
            if(is_readable_string(decrypted_string)):
                MakeComm(addr.frm,decrypted_string)
        else:
            continue
    except Exception as e:
        print hex(addr.frm)
        print e
        continue
