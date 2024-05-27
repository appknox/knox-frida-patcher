import os
import sys
import argparse
import rand
import elfcheck
import time

parser = argparse.ArgumentParser()
parser.add_argument('-b','--binarypath', type=str, nargs='?', help='location of frida binary to patch (server or gadget)')
parser.add_argument('-o','--output', type=str, nargs='?', help='output location for new binary')

args = parser.parse_args()
exclusions = []

if args.binarypath:
    frida_bin = args.binarypath
else:
    sys.exit(parser.print_help())

with open(frida_bin, 'rb') as f:
    data = bytearray(f.read())

try:
    exclusions.append(data.index(b'/System/Library/Caches/') + len('/System'))
except:
    pass

def find_and_replace(replacer, replacee = "", startpos = 0, endpos = 0):
    match = replacer.encode('utf8')
    length = len(match)
    if replacee == '':
        val = rand.gen_random_name(length).encode('utf8')[startpos:]
    else:
        val = replacee.encode('utf8')[startpos:]
        if len(val) > length:
            raise Exception('[-] input length is higher than required')
        else:
            val += int.to_bytes(0, length - len(val), 'big')     
    if endpos > 0:
        val = val[:-endpos]
    cur_index = 0

    while True:
        try:
            index = data.index(match, cur_index)
            cur_index = index + 1
            if index in exclusions:
                continue
        except:
            break
        data[index + startpos : index + length - endpos] = val
        print("[*] patching: " + replacer + " at: " + str(hex(index)) + " with: " + val.decode("utf8"))

def verify_exported_binary(path):
    if elfcheck.is_binary_elf(path):
        try:
            elfcheck.check_binary_information(path + "-modified")
        except:
            raise Exception('[-] binary verification failed, corrupted output!!')
    else:
        print ("\n[*] skipping binary checks, reason: NOT_ELF_BINARY")

frida_string_to_patch = [
    "linjector",
    "gmain",
    "gum-js-loop",
    "re.frida.server",
    "frida-helper",
    "gdbus",
    "frida-agent",
    "pipe-",
    "GADGET",
    "gadget.so",
    "FRIDA",
    "AGENT",
    "frida-",
    "frida-agent-32.so",
    "frida-server",
    "frida-agent-64.so",
]

for value in frida_string_to_patch:
    find_and_replace(value)
    time.sleep(0.5)

find_and_replace('\"frida\"', startpos=1, endpos=1)

if args.output:
    bin_name = str(args.output)
else:
    bin_name = '%s-modified' % frida_bin

with open(bin_name, 'wb') as f:
    f.write(data)
    verify_exported_binary(args.binarypath)
