import os
import lief

ELF_MAGIC_MAIN = "7F 45 4C 46 " # ELF Magic

def check_binary_information(path):
    print ("\n[*] validating patched binary at: " + path)
    bin = lief.parse(path)

    bin_segments = bin.segments
    bin_sections = bin.sections

    header = bin.header
    print ("[*] detected segments:", len(bin_segments))
    print ("[*] detected sections:", len(bin_sections))

    if len(bin_segments) != header.numberof_segments:
        print ("[*] segment mismatch detected!!: " + path)
        return -1

    if len(bin_sections) != header.numberof_sections:
        print ("[*] section mismatch detected!!: " + path)
        return -1
    
    print ("[*] section & segment verification completed")
    print ("[*] verifying magic")
    magic_header_id_bytes = header.identity
    magic = ""

    for x in range(4):
        byte_magic = str(hex(magic_header_id_bytes[x]))
        magic += byte_magic.upper()[2:] + " "

    if ELF_MAGIC_MAIN != magic:
        print ("[*] ELF magic mismatch detected, binary is corrupted!!")
        return -1

    print ("[*] ELF magic: ", magic)
    print ("[*] binary verification successful")
    return 0
    

def is_binary_elf(path: str):
    name_array_data = path.split("/")
    name = name_array_data[len(name_array_data) - 1]

    extension = name.split(".")[1]

    if "so" not in extension:
        return False
    else:
        return True
    
    binary = lief.parse(path)
    header = binary.header

    magic_header_id_bytes = header.identity
    magic = ""

    for x in range(4):
        byte_magic = str(hex(magic_header_id_bytes[x]))
        magic += byte_magic.upper()[2:] + " "
    
    if ELF_MAGIC_MAIN != magic:
        return True

    return False