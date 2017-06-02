import argparse
from base64 import b64decode
from Crypto.PublicKey import RSA
from dns import resolver
def parse_args():
    parser = argparse.ArgumentParser(description='A small application to do DKIM scanning')
    parser.add_argument('-w', '--wordlist', action="store", dest="wordlist", required=True)
    parser.add_argument('-n', '--nameserver', action="store", dest="nameserver", default="8.8.8.8")
    parser.add_argument('-d', '--domain', action="store", dest="domain", required=True)
    return parser.parse_args()

def load_dkim_list(location):
    selectors = []
    with open(location) as dkim_fp:
        for line in dkim_fp:
            if line.strip() != '':
                selectors.append(line.strip())
    if not selectors:
        print "Error no selectors were found in the file"
    return selectors

def parse_dkim(ret_str):
    dkim_type = {'v':'', 'g':'', 'h':'', 'k':'', 'n':'', 'p':'', 's':'', 't':''}
    newcommand = True
    current_index = None
    skip = False
    curr_command = ''
    ret_str = ret_str.strip()
    if not ret_str:
        print "Error"
        return -1
    else:
        end = len(ret_str)
        for i in range(0, end):
            if skip:
                skip = False
                continue
            if newcommand and ret_str[i] in dkim_type.keys() and ret_str[i+1] == '=':
                current_index = ret_str[i]
                skip = True
                newcommand = False
            elif not newcommand and ret_str[i] == ';':
                dkim_type[current_index] = curr_command
                newcommand = True
                curr_command = ''
            elif not newcommand:
                curr_command += ret_str[i]
            else:
                pass
            if i == end-1:
                dkim_type[current_index] = curr_command
    return dkim_type
def main():
    args = parse_args()
    res = resolver.Resolver()
    res.nameservers = [str(args.nameserver)]
    selectors = load_dkim_list(str(args.wordlist))
    for selector in selectors:
        try:
            answers = res.query(selector+'._domainkey.' + str(args.domain), 'TXT')
        except (resolver.NoAnswer, resolver.NXDOMAIN):
            answers = []
        if len(answers) > 1:
            print "We received more than one DKIM back this site is misconfigured"
        elif not answers:
            pass
        else:
            print "[+] We found a valid DKIM record:", selector
            for rdata in answers:
                txt_string = ''.join(rdata.strings)
                dkim_type = parse_dkim(txt_string)
                asn_bytes = b64decode(dkim_type['p'])
                key_pub = RSA.importKey(asn_bytes)
                key_size = key_pub.size() + 1
                if key_size <= 1024:
                    print "[-] The public key length was too small (" + str(key_size) + ")"
                else:
                    print "[+] The public key is", key_size, "bit"
main()
