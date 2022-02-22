import binascii
import string

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

max_bits = 32



def Get_Data(Address,N):

    return get_bytes(Address,N)
def BokBot_Rotation(Seed):
    Seed = Seed+0x2e59
    Seed = ror ( Seed, 1, max_bits)
    Seed = ror ( Seed, 1, max_bits)
    Seed = ror ( Seed, 2, max_bits)
    Seed  = Seed ^ 0x151D
    Seed = rol ( Seed, 2, max_bits)
    Seed = rol ( Seed, 1, max_bits)
    return Seed

def is_string_readable(data):
    for i in range(5): #We check the first 5 bytes only
        if data[i] in string.printable:
            return 1
    return 0

def Byte_Array_Check(Address):
    if 'byte' in print_operand(Address,1) or 'unk_' in print_operand(Address,1) or 'qword_' in print_operand(Address,1):
        return 1
    return 0

def Get_Data_Address(Address):
    while True:
        Address = prev_head(Address)
        if 'rcx' in print_operand(Address,0):
            return Address
    return 0
def decrypt_str(Address):
    Decrypted_String = ''
    initial_bytes = Get_Data(Address,10)
    Seed = initial_bytes[:4]
    Seed = int.from_bytes(Seed,'little')
    string_size = (int.from_bytes(initial_bytes[4:6],'little') ^  int.from_bytes(initial_bytes[:4],'little')) & 0xffff
    Encrypted_Data = Get_Data(Address+6,string_size)
    for i in range( string_size):
        Seed = BokBot_Rotation(Seed)
        Decrypted_Byte = (Seed&0xff) ^ (Encrypted_Data[i] & 0xff)
        Decrypted_String += (chr(Decrypted_Byte))
    return Decrypted_String
for addr in XrefsTo(0x20B35A3B7A4):
    Encrypted_Data_Address = Get_Data_Address(addr.frm)
    if Byte_Array_Check(Encrypted_Data_Address):
        Encrypted_Data_Address = get_operand_value(Encrypted_Data_Address,1)
        decrypted_string = decrypt_str( Encrypted_Data_Address)
        if is_string_readable(decrypted_string):
            set_cmt(addr.frm,decrypted_string,0)
    else:
        print ("[-] Failed to find encrypted data address")
