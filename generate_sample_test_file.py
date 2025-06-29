import csv
import random

header = [
    'md5','sha1','file_extension','EntryPoint','PEType','MachineType','magic_number','bytes_on_last_page','pages_in_file','relocations','size_of_header','min_extra_paragraphs','max_extra_paragraphs','init_ss_value','init_sp_value','init_ip_value','init_cs_value','over_lay_number','oem_identifier','address_of_ne_header','Magic','SizeOfCode','SizeOfInitializedData','SizeOfUninitializedData','AddressOfEntryPoint','BaseOfCode','BaseOfData','ImageBase','SectionAlignment','FileAlignment','OperatingSystemVersion','ImageVersion','SizeOfImage','SizeOfHeaders','Checksum','Subsystem','DllCharacteristics','SizeofStackReserve','SizeofStackCommit','SizeofHeapCommit','SizeofHeapReserve','LoaderFlags','text_VirtualSize','text_VirtualAddress','text_SizeOfRawData','text_PointerToRawData','text_PointerToRelocations','text_PointerToLineNumbers','text_Characteristics','rdata_VirtualSize','rdata_VirtualAddress','rdata_SizeOfRawData','rdata_PointerToRawData','rdata_PointerToRelocations','rdata_PointerToLineNumbers','rdata_Characteristics','registry_read','registry_write','registry_delete','registry_total','network_threats','network_dns','network_http','network_connections','processes_malicious','processes_suspicious','processes_monitored','total_procsses','files_malicious','files_suspicious','files_text','files_unknown','dlls_calls','apis'
]

def random_md5():
    return ''.join(random.choices('0123456789abcdef', k=32))
def random_sha1():
    return ''.join(random.choices('0123456789abcdef', k=40))

def benign_row(idx):
    return [
        random_md5(), random_sha1(), 'exe', f'0x{1000+idx*1000:x}', 'PE32+', 'AMD AMD64', 'MZ', '0x0090', '0x0003', '0x0000', '0x0004', '0x0000', '0xFFFF', '0x0000', '0x00B8', '0x0000', '0x0000', '0x0000', '0x0000', '0x000000F8', 'PE32+', '0x00011200', '0x0000D200', '0x00000000', f'0x{10000+idx*10000:x}', '0x00001000', '0x00004000', '0x0000000140000000', '0x00001000', '0x00000200', '5.2', '0.0', '0x00022000', '0x00000400', '0x0001E8D0', 'IMAGE_SUBSYSTEM_WINDOWS_GUI', "['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE', 'IMAGE_DLLCHARACTERISTICS_NX_COMPAT', 'IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE']", '0x0000000000100000', '0x0000000000001000', '0x0000000000001000', '0x0000000000100000', '0x00000000', '0x000111FE', '0x00001000', '0x00011200', '0x00000400', '0x00000000', '0x00000000', "['IMAGE_SCN_CNT_CODE', 'IMAGE_SCN_MEM_EXECUTE', 'IMAGE_SCN_MEM_READ']", '0x00007B14', '0x00013000', '0x00007C00', '0x00011600', '0x00000000', '0x00000000', "['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ']", random.randint(0,10), random.randint(0,5), random.randint(0,2), random.randint(0,20), random.randint(0,2), random.randint(0,10), random.randint(0,10), random.randint(0,5), random.randint(0,3), random.randint(0,2), random.randint(0,10), random.randint(0,30), random.randint(0,5), random.randint(0,5), random.randint(0,5), random.randint(0,3), random.randint(0,10), random.randint(0,200)
    ]

def ransomware_row(idx):
    return [
        random_md5(), random_sha1(), 'exe', f'0x{2000+idx*1000:x}', 'PE32+', 'AMD AMD64', 'MZ', '0x0090', '0x0004', '0x0000', '0x0004', '0x0000', '0xFFFF', '0x0000', '0x00B8', '0x0000', '0x0000', '0x0000', '0x0000', '0x000001F8', 'PE32+', '0x00021200', '0x0001D200', '0x00000000', f'0x{20000+idx*10000:x}', '0x00002000', '0x00008000', '0x0000000140000000', '0x00002000', '0x00000200', '6.2', '0.0', '0x00032000', '0x00000800', '0x0002E8D0', 'IMAGE_SUBSYSTEM_WINDOWS_GUI', "['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE', 'IMAGE_DLLCHARACTERISTICS_NX_COMPAT']", '0x0000000000200000', '0x0000000000002000', '0x0000000000002000', '0x0000000000200000', '0x00000000', '0x000211FE', '0x00002000', '0x00021200', '0x00000800', '0x00000000', '0x00000000', "['IMAGE_SCN_CNT_CODE', 'IMAGE_SCN_MEM_EXECUTE', 'IMAGE_SCN_MEM_READ']", '0x00017B14', '0x00023000', '0x00017C00', '0x00021600', '0x00000000', '0x00000000', "['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ']", random.randint(1000,3000), random.randint(800,2000), random.randint(200,800), random.randint(2000,6000), random.randint(10,30), random.randint(30,100), random.randint(20,80), random.randint(10,40), random.randint(10,30), random.randint(5,20), random.randint(10,40), random.randint(50,150), random.randint(20,60), random.randint(10,60), random.randint(10,60), random.randint(10,30), random.randint(20,60), random.randint(200,800)
    ]

with open('sample_test_file.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(header)
    for i in range(50):
        writer.writerow(benign_row(i))
    for i in range(50):
        writer.writerow(ransomware_row(i))

print('Generated 100 samples (50 benign, 50 ransomware) in sample_test_file.csv')
