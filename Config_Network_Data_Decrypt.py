import binascii
import string

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

max_bits = 32

'''
Used only in the configuration decryption routine

def Validate_Config(Data,Expected_Value):
    Validation_resultult = 0
    for byte in Data:
        Validation_resultult = rol(byte+Validation_resultult,3,max_bits)
    print ( hex(Validation_resultult))
    if Validation_resultult == Expected_Value:
        print ( "[+] Configuration decrypted successfully")
        return 1
    else:
        print ( "[-] Validation value does not match with the expected value. Make sure configuration was decrypted correct")
        return 0
'''


section_data = bytes.fromhex('EA4ED36091BCCC0AEDD2C0DF2EEFFE95C7918DA0598895F6469DCF7799E7241091D3964FBAC6407611BE4142BAB050045E2D53B3A468BA9CA863B69139FED50F68C65FA0D8ADC7EFBAA7AF56ED896F08668B5CAFFEE9F5551ABF948F39D91781285A94A8DEDA5794275518E87E791B930165DC4E4637BDD81E40C55A4E286953140A5826E8BF466D4F75BD164C16D00B00747578838B2359F55208648433650F51D12CD9E89FB18B0BBF856FD3A06D663A04A5D0601BE09CDA363657A6F8C953A3D55CA75F0A61961981199247A094B0453293C0A95EC5B945C9906032A2F7865B4FC2643A21EF565496C01C37B80EEA9515A75A08D0C523A93CDBC4F2277E44F8CDECAB6DAA9941EFE5414787E34B842A8DD11C06EACCE46BA845A1C4AAAC6D6366265238823F0B0ABE990CE1BE8D9B6E7543CE60FBCB7A9003A12B54D82A1E03C32599DFF9F16909FA04E8881004684CEDE61FC1BDD039417E111923A7E98A47DD001F689398A8A93C6AAEA5D8707786BE62E19D90FB77B48E16FE56868B74D8E1BBC0921D875C0A0F0F938C09F8EE016765519DA5B91B4058279CAF7D72C9B81EC61F496CC5FBA86962EF30702334FBC4991BCC3D78E994B7EA1A939DF3D4740B2CBE3D9C49D87069CC6AB6966C8FCC1FD057A976127A5F51A217012EB60133EA5F88F7CEB066E826DD6AACCEF7517C4072AC5C7E2AA25B5BAAB5B22066F718A8DFC1DD90D1484A0497257AD372D0AE8DF1D9EEFB8F33A07CD3E0CAFFD02AA7E20C87A178FF840FA9BCE48B23F1F4CD63207B2839B214717C25FD67A95F82D73EB935A13C34EF7E3B67C391E37C0D6B47B402BBB91E2BE96FF903')
key = bytearray(section_data[-16:])
counter = 0
result = b''
while counter<len(section_data)-20:
    second_key_index = counter & 3
    key_index = (counter + 1) & 3
    xor_operation = (int.from_bytes((key[second_key_index*4:second_key_index*4+4]),'little') + int.from_bytes((key[key_index*4:key_index*4+4]),'little')) ^ section_data[counter]
    result += (  (xor_operation&0xff).to_bytes(1, byteorder='little') )
    v10 = key[key_index*4:key_index*4+4]
    counter += 1
    v11 = ror(int.from_bytes(key[4*second_key_index:second_key_index*4+4],"little"), int.from_bytes(v10,"little") & 7,max_bits) + 1;
    key[second_key_index*4:second_key_index*4+4] = v11.to_bytes(4, byteorder='little')
    
    key[key_index*4:key_index*4+4] = (ror( int.from_bytes( key[key_index*4:key_index*4+4],"little"), v11 & 7, max_bits) + 1).to_bytes(4, byteorder='little')


print ( binascii.hexlify( result))