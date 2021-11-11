#!/usr/bin/env python3

import sys
import re
import json
import requests

def parse_line(line):
    m = re.search('^[0-9]+\ ', line)
    return int(m.group(0)) if m != None else None

filename = sys.argv[1]

results = open(filename).read().split('\n')


scan_result = {}
cur_key = None
for line in results:
    line = line.strip()
    m = re.search('[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', line)
    if m != None:
        cur_key = m.group(0)
    else:
        r = parse_line(line)
        if r != None:
            if cur_key not in scan_result:
                scan_result[cur_key] = {'dids' : [] }
            scan_result[cur_key]['dids'].append(r)
            r = requests.get("http://ipwhois.app/json/%s" % cur_key)
            scan_result[cur_key]['geo'] = json.loads(r.text)
print(json.dumps(scan_result))
