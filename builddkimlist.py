import argparse
import mailbox
import re

def parse_args():
    parser = argparse.ArgumentParser(description='A small application to do DKIM scanning')
    parser.add_argument('-o', '--output', action="store", dest="output", required=True)
    parser.add_argument('-m', '--mailbox', action="store", dest="mailbox", required=True)
    return parser.parse_args()

def main():
    dkim_list = set()
    args = parse_args()
    mbox = mailbox.mbox(args.mailbox)
    for message in mbox:
        dkim_headers = message.get_all('DKIM-Signature')
        if not dkim_headers:
            continue
        for header in dkim_headers:
            if header:
                regex = r's=(.*?);\s'
                if re.search(regex, header):
                    match = re.search(regex, header)
                    if match.group(1) == "bh=bAdPyaClkPse2YsGS9J/Gh+upWg82rbW+axoHah5/Co=":
                        print "got here"
                        print header
                    dkim_list.add(match.group(1))
    fp_out = open(str(args.output), 'w')
    for entry in dkim_list:
        fp_out.write(entry + "\n")
main()
