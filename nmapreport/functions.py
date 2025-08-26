import xmltodict, json, html, os, hashlib, re, urllib.parse, base64
import socket
import platform
import subprocess
from typing import Optional

def get_machine_ip() -> Optional[str]:
    """
    Get the IP address of the current machine, works on both Windows and Linux.
    Returns the primary IP address or None if it cannot be determined.
    """
    try:
        # First try to determine the operating system
        system = platform.system().lower()
        
        if system == 'windows':
            # For Windows, use socket to get hostname and then get IP
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            return ip
        
        elif system == 'linux':
            # For Linux, try multiple methods
            
            # Method 1: Using hostname command
            try:
                ip = subprocess.check_output(['hostname', '-I']).decode().strip().split()[0]
                return ip
            except (subprocess.SubprocessError, IndexError):
                pass
            
            # Method 2: Using ip command
            try:
                cmd = "ip -4 addr show | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}' | grep -v '127.0.0.1' | head -n 1"
                ip = subprocess.check_output(cmd, shell=True).decode().strip()
                return ip
            except subprocess.SubprocessError:
                pass
            
            # Method 3: Using socket as fallback
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(('8.8.8.8', 80))  # Connect to Google DNS to get local IP
                ip = s.getsockname()[0]
                s.close()
                return ip
            except socket.error:
                pass
        
        # If all methods fail, try basic socket method as last resort
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        return ip
        
    except Exception as e:
        print(f"Error getting IP address: {e}")
        return None

def token_check(token):
	tokenhash = open('/root/token.sha256').read().strip()
	if tokenhash == hashlib.sha256(token.encode('utf-8')).hexdigest():
		return True
	return False

def labelToMargin(label):
	labels = {
		'Vulnerable':'10px',
		'Critical':'22px',
		'Warning':'28px',
		'Checked':'28px'
	}

	if label in labels:
		return labels[label]

def labelToColor(label):
	labels = {
		'Vulnerable':'red',
		'Critical':'black',
		'Warning':'orange',
		'Checked':'blue'
	}

	if label in labels:
		return labels[label]

def fromOSTypeToFontAwesome(ostype):
	icons = {
		'windows':'fab fa-windows',
		'solaris':'fab fa-linux',	# there isn't a better icon on fontawesome :(
		'unix':'fab fa-linux',		# same here...
		'linux':'fab fa-linux',
	}

	if ostype.lower() in icons:
		return str(icons[ostype.lower()])
	else:
		return 'fas fa-question'

def nmap_ports_stats(scanfile):
	try:
		oo = xmltodict.parse(open('/opt/xml/'+scanfile, 'r').read())
	except:
		return {'po':0,'pc':0,'pf':0}

	r = json.dumps(oo['nmaprun'], indent=4)
	o = json.loads(r)
	debug = {}

	po,pc,pf = 0,0,0

	if 'host' not in o:
		return {'po':0,'pc':0,'pf':0}

	iii=0
	lastaddress = ''
	for ik in o['host']:
		if type(ik) is dict:
			i = ik
		else:
			i = o['host']

		lastportid = 0

		if '@addr' in i['address']:
			address = i['address']['@addr']
		elif type(i['address']) is list:
			for ai in i['address']:
				if ai['@addrtype'] == 'ipv4':
					address = ai['@addr'] 

		addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()

		if lastaddress == address:
			continue
		lastaddress = address

		striggered = False
		if 'ports' in i and 'port' in i['ports']:
			for pobj in i['ports']['port']:
				if type(pobj) is dict:
					p = pobj
				else:
					p = i['ports']['port']

				if lastportid == p['@portid']:
					continue
				else:
					lastportid = p['@portid']

				if address not in debug:
					debug[address] = {'portcount':{'pc':{},'po':{},'pf':{}}}
				debug[address][p['@portid']] = p['state']

				if p['state']['@state'] == 'closed':
					pc = (pc + 1)
					debug[address]['portcount']['pc'][iii] = pc
				elif p['state']['@state'] == 'open':
					po = (po + 1)
					debug[address]['portcount']['po'][iii] = po
				elif p['state']['@state'] == 'filtered':
					pf = (pf + 1)
					debug[address]['portcount']['pf'][iii] = pf
				iii = (iii + 1)

	return {'po':po,'pc':pc,'pf':pf, 'debug':json.dumps(debug)}
def ports_stats(scanfile):
	try:
		oo = xmltodict.parse(open(scanfile, 'r').read())
	except:
		return {'po':0,'pc':0,'pf':0}

	r = json.dumps(oo['nmaprun'], indent=4)
	o = json.loads(r)
	debug = {}

	po,pc,pf = 0,0,0

	if 'host' not in o:
		return {'po':0,'pc':0,'pf':0}

	iii=0
	lastaddress = ''
	for ik in o['host']:
		if type(ik) is dict:
			i = ik
		else:
			i = o['host']

		lastportid = 0

		if '@addr' in i['address']:
			address = i['address']['@addr']
		elif type(i['address']) is list:
			for ai in i['address']:
				if ai['@addrtype'] == 'ipv4':
					address = ai['@addr'] 

		addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()

		if lastaddress == address:
			continue
		lastaddress = address

		striggered = False
		if 'ports' in i and 'port' in i['ports']:
			for pobj in i['ports']['port']:
				if type(pobj) is dict:
					p = pobj
				else:
					p = i['ports']['port']

				if lastportid == p['@portid']:
					continue
				else:
					lastportid = p['@portid']

				if address not in debug:
					debug[address] = {'portcount':{'pc':{},'po':{},'pf':{}}}
				debug[address][p['@portid']] = p['state']

				if p['state']['@state'] == 'closed':
					pc = (pc + 1)
					debug[address]['portcount']['pc'][iii] = pc
				elif p['state']['@state'] == 'open':
					po = (po + 1)
					debug[address]['portcount']['po'][iii] = po
				elif p['state']['@state'] == 'filtered':
					pf = (pf + 1)
					debug[address]['portcount']['pf'][iii] = pf
				iii = (iii + 1)

	return {'po':po,'pc':pc,'pf':pf, 'debug':json.dumps(debug)}
def get_cve(scanmd5):
	cvehost = {}
	cvefiles = os.listdir('/opt/notes')
	for cf in cvefiles:
		m = re.match('^('+scanmd5+')_([a-z0-9]{32,32})\.cve$', cf)
		if m is not None:
			if m.group(1) not in cvehost:
				cvehost[m.group(1)] = {}

			if m.group(2) not in cvehost[m.group(1)]:
				cvehost[m.group(1)][m.group(2)] = open('/opt/notes/'+cf, 'r').read()

			#cvehost[m.group(1)][m.group(2)][m.group(3)] = open('/opt/notes/'+cf, 'r').read()

	return cvehost
	

def get_ports_details(scanfile):
	faddress = ""
	oo = xmltodict.parse(open('/opt/xml/'+scanfile, 'r').read())
	out2 = json.dumps(oo['nmaprun'], indent=4)
	o = json.loads(out2)

	r = {'file':scanfile, 'hosts': {}}
	scanmd5 = hashlib.md5(str(scanfile).encode('utf-8')).hexdigest()

	# collect all labels in labelhost dict
	labelhost = {}
	labelfiles = os.listdir('/opt/notes')
	for lf in labelfiles:
		m = re.match('^('+scanmd5+')_([a-z0-9]{32,32})\.host\.label$', lf)
		if m is not None:
			if m.group(1) not in labelhost:
				labelhost[m.group(1)] = {}
			labelhost[m.group(1)][m.group(2)] = open('/opt/notes/'+lf, 'r').read()

	# collect all notes in noteshost dict
	noteshost = {}
	notesfiles = os.listdir('/opt/notes')
	for nf in notesfiles:
		m = re.match('^('+scanmd5+')_([a-z0-9]{32,32})\.notes$', nf)
		if m is not None:
			if m.group(1) not in noteshost:
				noteshost[m.group(1)] = {}
			noteshost[m.group(1)][m.group(2)] = open('/opt/notes/'+nf, 'r').read()

	# collect all cve in cvehost dict
	cvehost = get_cve(scanmd5)

	for ik in o['host']:

		# this fix single host report
		if type(ik) is dict:
			i = ik
		else:
			i = o['host']

		hostname = {}
		if 'hostnames' in i and type(i['hostnames']) is dict:
			# hostname = json.dumps(i['hostnames'])
			if 'hostname' in i['hostnames']:
				# hostname += '<br>'
				if type(i['hostnames']['hostname']) is list:
					for hi in i['hostnames']['hostname']:
						hostname[hi['@type']] = hi['@name']
				else:
					hostname[i['hostnames']['hostname']['@type']] = i['hostnames']['hostname']['@name'];

		if i['status']['@state'] == 'up':
			po,pc,pf = 0,0,0
			ss,pp,ost = {},{},{}
			lastportid = 0

			if '@addr' in i['address']:
				address = i['address']['@addr']
			elif type(i['address']) is list:
				for ai in i['address']:
					if ai['@addrtype'] == 'ipv4':
						address = ai['@addr']

			if faddress != "" and faddress != address:
				continue

			addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()
			#cpe[address] = {}

			labelout = ''
			if scanmd5 in labelhost:
				if addressmd5 in labelhost[scanmd5]:
					labelout = labelhost[scanmd5][addressmd5]

			notesout,notesb64,removenotes = '','',''
			if scanmd5 in noteshost:
				if addressmd5 in noteshost[scanmd5]:
					notesb64 = noteshost[scanmd5][addressmd5]
			#		notesout = '<br><a id="noteshost'+str(hostindex)+'" href="#!" onclick="javascript:openNotes(\''+hashlib.md5(str(address).encode('utf-8')).hexdigest()+'\', \''+notesb64+'\');" class="small"><i class="fas fa-comment"></i> contains notes</a>'
			#		removenotes = '<li><a href="#!" onclick="javascript:removeNotes(\''+addressmd5+'\', \''+str(hostindex)+'\');">Remove notes</a></li>'

			cveout = ''
			#cvecount = 0
			if scanmd5 in cvehost:
				if addressmd5 in cvehost[scanmd5]:
					cveout = json.loads(cvehost[scanmd5][addressmd5])
			#		for cveobj in cvejson:	
			#			cvecount = (cvecount + 1)


			#if faddress == "":
			#	r['hosts'][address] = {'hostname':hostname, 'label':labelout, 'notes':notesb64}
			#else:
			r['hosts'][address] = {'ports':[], 'hostname':hostname, 'label':labelout, 'notes':notesb64, 'CVE':cveout}

			if 'ports' in i and 'port' in i['ports']:
				for pobj in i['ports']['port']:
					if type(pobj) is dict:
						p = pobj
					else:
						p = i['ports']['port']

					if lastportid == p['@portid']:
						continue
					else:
						lastportid = p['@portid']

					v,z,e='','',''
					pp[p['@portid']] = p['@portid']

					servicename = ''
					if 'service' in p:
						ss[p['service']['@name']] = p['service']['@name']

						if '@version' in p['service']:
							v = p['service']['@version']

						if '@product' in p['service']:
							z = p['service']['@product']

						if '@extrainfo' in p['service']:
							e = p['service']['@extrainfo']

						servicename = p['service']['@name']

					#if faddress != "":
					r['hosts'][address]['ports'].append({
						'port': p['@portid'],
						'name': servicename,
						'state': p['state']['@state'],
						'protocol': p['@protocol'],
						'reason': p['state']['@reason'],
						'product': z,
						'version': v,
						'extrainfo': e
					})
	return r
def find_json_upward(start_path, stop_path="/opt/xml"):
		current_path = os.path.abspath(start_path)
		stop_path = os.path.abspath(stop_path)

		while True:
			for fname in os.listdir(current_path):
				if (fname.startswith("CVE_") & fname.endswith('.json')):
					return os.path.join(current_path, fname)

			if current_path == stop_path:
				break 

			parent = os.path.dirname(current_path)
			if parent == current_path:
				break  # Prevent infinite loop 

			current_path = parent

		return None
def load_collector_info(start_path):
    collector_info = {}

    json_path = find_json_upward(start_path)
    if not json_path:
        print("Warning: collector JSON not found.")
        return collector_info
    
    try:
        with open(json_path, 'r') as f:
            collector_data = json.load(f)
            for entry in collector_data:
                if isinstance(entry, dict) and 'ip' in entry:
                    ip = entry['ip']
                    collector_info[ip] = {'services': {}}
                    for svc in entry.get('services', []):
                        port = svc.get('port')
                        service_name = svc.get('service')
                        product = svc.get('product')
                        version = svc.get('version')
                        misc = svc.get('Misc')
                        cves = svc.get('cves', [])
                        vulns = svc.get('vulns', {})
                        vuln_checks = {}
                        # Add all vulnerability check results
                        for k in svc.keys():
                            if k.endswith('vulnerability check'):
                                vuln_checks[k] = svc[k]
                        # Store all info for this port
                        collector_info[ip]['services'][port] = {
                            'service': service_name,
                            'product': product,
                            'version': version,
                            'misc': misc,
                            'cves': cves,
                            'vulns': vulns,
                            'vuln_checks': vuln_checks
                        }
                else:
                    print(f"Skipping invalid entry in {json_path}: {entry}")
    except Exception as e:
        print(f"Warning: could not load collector info from {json_path}: {e}")

    return collector_info

