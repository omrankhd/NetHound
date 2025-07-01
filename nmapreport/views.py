from django.shortcuts import render, redirect
from django.http import HttpResponse , Http404
import xmltodict, json, html, os, hashlib, re, urllib.parse, base64
from collections import OrderedDict
from nmapreport.functions import *
from nmapreport.api import *
from django.conf import settings
from pathlib import Path
from time import strftime, localtime




def login(request):
	r = {}

	if request.method == "POST":
		if(re.search('^[a-zA-Z0-9]+$', request.POST['token'])):
			if token_check(request.POST['token']) is True:
				request.session['auth'] = True
				r['auth'] = 'ok'
				return HttpResponse(json.dumps(r), content_type="application/json")

	return render(request, 'nmapreport/nmap_auth.html', r)

def setscanpath(request, scanname):
    print("Scan name:", scanname)
    base_path =  request.session['path']#'/opt/xml'
    print("base_path:", base_path)
    print("is_file_exist:",scanname in os.listdir('/opt/xml'))
    if scanname == 'unset':
        request.session.pop('scanfile', None)
        request.session.pop('scanfolder', None)
        return redirect('/') 
        
    else:
        full_path = os.path.join('/opt/xml', scanname)
        print ("full_path",full_path)
        if os.path.isdir(full_path):
            request.session['scanfolder'] = full_path
            request.session.pop('scanfile', None)  # Ensure only one is set
            print(f"Set folder session to {full_path}")
            

        elif full_path.startswith(base_path):  # Check only filename match
            request.session['scanfile'] = scanname
            request.session.pop('scanfolder', None)  # Ensure only one is set
            print(f"Set file session to {scanname}")

    return render(request, 'nmapreport/nmap_hostdetails.html', {
        'js': '<script> location.href="/"; </script>'
    })

def port(request, port):
	return render(request, 'nmapreport/index.html', { 'out': '', 'table': '', 'scaninfo': '', 'scandetails': '', 'trhost': '' })

# def details(request, address):
   

#     r = {}
#     if 'auth' not in request.session:
#         return render(request, 'nmapreport/nmap_auth.html', r)
#     else:
#         r['auth'] = True

#     if 'scanfolder' not in request.session:
#         return redirect('/select-scanfolder/')

#     folder_path = request.session['scanfolder']
#     folder_name = os.path.basename(folder_path.rstrip('/'))
#     scanmd5 = hashlib.md5(folder_name.encode('utf-8')).hexdigest()
#     addressmd5 = hashlib.md5(address.encode('utf-8')).hexdigest()

#     # Find the host matching the address
#     target_host = None
#     for fname in os.listdir(folder_path):
#         if not fname.endswith('.xml'):
#             continue
#         try:
#             with open(os.path.join(folder_path, fname), 'r') as f:
#                 xml = xmltodict.parse(f.read())
#             o = json.loads(json.dumps(xml['nmaprun'], indent=4))
#             hosts = o.get('host', [])
#             if not isinstance(hosts, list):
#                 hosts = [hosts]
#             for i in hosts:
#                 addr_info = i.get('address')
#                 if isinstance(addr_info, list):
#                     for ai in addr_info:
#                         if ai.get('@addrtype') == 'ipv4' and ai.get('@addr') == address:
#                             target_host = i
#                 elif isinstance(addr_info, dict) and addr_info.get('@addr') == address:
#                     target_host = i
#                 if target_host:
#                     break
#             if target_host:
#                 break
#         except Exception:
#             continue

#     if not target_host:
#         r['js'] = '<script>alert("Host not found in any scan file.");</script>'
#         return render(request, 'nmapreport/nmap_portdetails.html', r)

#     # Load CVEs, labels, notes
#     labelhost, noteshost, cvehost = {}, {}, get_cve(scanmd5)
#     for f in os.listdir('/opt/notes'):
#         if re.match(fr'^{scanmd5}_[a-z0-9]{{32}}\.(host\.label|notes)$', f):
#             key = f.split('.')[0].split('_')[1]
#             with open(os.path.join('/opt/notes', f), 'r') as fp:
#                 content = fp.read()
#             if f.endswith('.host.label'):
#                 labelhost.setdefault(scanmd5, {})[key] = content
#             elif f.endswith('.notes'):
#                 noteshost.setdefault(scanmd5, {})[key] = content

#     r['trhost'] = ''
#     r['trhead'] = '<tr><th>Port</th><th style="width:300px;">Product / Version</th><th>Extra Info</th><th>&nbsp;</th></tr>'
#     r['tr'] = {}

#     hostname = ''
#     hlist = target_host.get('hostnames', {}).get('hostname', [])
#     if isinstance(hlist, dict):
#         hlist = [hlist]
#     for hi in hlist:
#         hostname += f"<span class='small grey-text'><b>{hi['@type']}:</b> {hi['@name']}</span><br>"

#     r['address'] = html.escape(address)
#     r['hostname'] = hostname
#     r['scanfile'] = folder_name

#     # Label
#     r['label'] = ''
#     if scanmd5 in labelhost and addressmd5 in labelhost[scanmd5]:
#         label = labelhost[scanmd5][addressmd5]
#         r['label'] = html.escape(label)
#         r['labelcolor'] = labelToColor(label)

#     # Notes
#     if scanmd5 in noteshost and addressmd5 in noteshost[scanmd5]:
#         decoded = base64.b64decode(urllib.parse.unquote(noteshost[scanmd5][addressmd5])).decode('utf-8')
#         r['notes'] = decoded
#         r['table'] = f'''
#             <div class="card" style="background-color:#3e3e3e;">
#                 <div class="card-content"><h5>Notes</h5>{decoded}</div>
#             </div>
#         '''
#     else:
#         r['table'] = ''

#     # Port Details
#     ports = target_host.get('ports', {}).get('port', [])
#     if isinstance(ports, dict):
#         ports = [ports]

#     po, pc, pf = 0, 0, 0
#     rmdupl = {}
#     pel = 0

#     for p in ports:
#         portid = p.get('@portid')
#         if portid in rmdupl:
#             continue
#         rmdupl[portid] = True
#         pel += 1

#         state = p['state']['@state']
#         reason = p['state'].get('@reason', '')
#         protocol = p.get('@protocol', '')
#         service = p.get('service', {})
#         servicename = service.get('@name', '')
#         version = service.get('@version', '<i class="grey-text">No Version</i>')
#         product = service.get('@product', '<i class="grey-text">No Product</i>')
#         extrainfo = service.get('@extrainfo', '<i class="grey-text">N/A</i>')

#         # CPE
#         cpe_html = ''
#         cpes = service.get('cpe', [])
#         if isinstance(cpes, str):
#             cpes = [cpes]
#         for cpei in cpes:
#             cpe_html += f'<div class="grey-text" style="font-family:monospace;font-size:12px;">{html.escape(cpei)}</div>'

#         # Scripts
#         so = ''
#         scripts = p.get('script', [])
#         if isinstance(scripts, dict):
#             scripts = [scripts]
#         for sosc in scripts:
#             sid = sosc.get('@id', '')
#             if sid and sid != 'fingerprint-strings':
#                 out = sosc.get('@output', '')
#                 so += f'''
#                     <div style="word-wrap: break-word; word-break: break-all; padding:6px; margin-left:6px; border-left:solid #666 1px; max-width:300px; font-size:12px; color:#ccc; font-family:monospace;">
#                         <sup style="color:#999;border-bottom:solid #999 1px;">script output</sup><br><b>{html.escape(sid)}</b> {html.escape(out)}
#                     </div>
#                 '''

#         # State counters
#         if state == 'open':
#             po += 1
#         elif state == 'closed':
#             pc += 1
#         elif state == 'filtered':
#             pf += 1

#         # Table Row
#         r['tr'][portid] = {
#             'service': servicename,
#             'protocol': protocol,
#             'portid': portid,
#             'product': product,
#             'version': version,
#             'cpe': cpe_html,
#             'state': state,
#             'reason': reason,
#             'extrainfo': extrainfo,
#             'pel': str(pel)
#         }

#         badge = f'<span class="new badge blue" data-badge-caption="">{protocol} / {portid}</span>'
#         curl = f"curl -v -A 'Mozilla/5.0' -k 'http://{address}:{portid}'"
#         telnet = f"telnet {address} {portid}"
#         nikto = f"nikto -host 'http://{address}:{portid}'"

#         r['trhost'] += f'''
#         <tr>
#             <td style="vertical-align:top;"><span style="color:#999;font-size:12px;">{servicename}</span><br>{badge}</td>
#             <td>{product} / {version}<br><span style="font-size:12px;color:#999;">State: {state}<br>Reason: {reason}</span></td>
#             <td style="vertical-align:top">{extrainfo}<br>{cpe_html}</td>
#             <td>
#                 <ul id="dropdown{pel}" class="dropdown-content" style="min-width:300px;">
#                     <li><a href="#!" class="btncpy" data-clipboard-text="{curl}">Copy as curl</a></li>
#                     <li><a href="#!" class="btncpy" data-clipboard-text="{nikto}">Copy as nikto</a></li>
#                     <li><a href="#!" class="btncpy" data-clipboard-text="{telnet}">Copy as telnet</a></li>
#                 </ul>
#                 <a class="dropdown-trigger btn blue right" href="#!" data-target="dropdown{pel}"><i class="material-icons">arrow_drop_down</i></a>
#                 <button onclick="apiPortDetails('{html.escape(address)}','{portid}');" class="btn blue right"><i class="material-icons">receipt</i></button>
#             </td>
#         </tr>
#         '''

#     # CVE
#     cveout = ''
#     if scanmd5 in cvehost and addressmd5 in cvehost[scanmd5]:
#         cvejson = json.loads(cvehost[scanmd5][addressmd5])
#         for entry in cvejson:
#             listcve = entry if isinstance(entry, list) else [entry]
#             for cveobj in listcve:
#                 refs = ''.join([f'<a href="{ref}">{ref}</a><br>' for ref in cveobj.get('references', [])])
#                 exdb = ''
#                 if 'exploit-db' in cveobj:
#                     exdb = '<br><b>Exploit DB:</b><br>' + ''.join(
#                         [f'<a href="{e["source"]}">{html.escape(e["title"])}</a><br>' for e in cveobj['exploit-db'] if 'title' in e]
#                     )
#                 cveout += f'''
#                     <div id="{html.escape(cveobj["id"])}" style="line-height:28px;padding:10px;border-bottom:solid #666 1px;margin-top:10px;">
#                         <span class="label red">{html.escape(cveobj["id"])}</span> {html.escape(cveobj["summary"])}<br>
#                         <div class="small" style="line-height:20px;"><b>References:</b><br>{refs}</div>
#                         <div class="small">{exdb}</div>
#                     </div>
#                 '''
#     r['cvelist'] = cveout

#     # JS
#     r['js'] = f'''
#     <script>
#     $(document).ready(function() {{
#         var clipboard = new ClipboardJS(".btncpy");
#         clipboard.on("success", function(e) {{
#             M.toast({{html: "Copied to clipboard"}});
#         }});
#         $(".dropdown-trigger").dropdown();
#         $("#detailspo").html('<center><h4><i class="fas fa-door-open green-text"></i> {po}</h4><span class="small grey-text">OPEN PORTS</span></center>');
#         $("#detailspc").html('<center><h4><i class="fas fa-door-closed red-text"></i> {pc}</h4><span class="small grey-text">CLOSED PORTS</span></center>');
#         $("#detailspf").html('<center><h4><i class="fas fa-filter grey-text"></i> {pf}</h4><span class="small grey-text">FILTERED PORTS</span></center>');
#     }});
#     </script>
#     '''

#     return render(request, 'nmapreport/nmap_portdetails.html', r)

def details(request, address):
	r = {}

	if 'auth' not in request.session:
		return render(request, 'nmapreport/nmap_auth.html', r)
	else:
		r['auth'] = True

	# oo = xmltodict.parse(open('/opt/xml/'+request.session['scanfile'], 'r').read())
	# r['out2'] = json.dumps(oo['nmaprun'], indent=4)
	# o = json.loads(r['out2'])
	host_found = None
	nmaprun_source = None

	if 'scanfolder' in request.session:
		folder_path = request.session['scanfolder']

		for fname in os.listdir(folder_path):
			if not fname.endswith('.xml'):
				continue

			xml_path = os.path.join(folder_path, fname)
			try:
				with open(xml_path, 'r') as f:
					oo = xmltodict.parse(f.read())
					o = json.loads(json.dumps(oo.get('nmaprun', {})))

				hosts = o.get('host', [])
				if isinstance(hosts, dict):  # single host
					hosts = [hosts]

				for host in hosts:
					addr_block = host.get('address', {})
					saddr = ''

					if isinstance(addr_block, dict):
						saddr = addr_block.get('@addr', '')
					elif isinstance(addr_block, list):
						for a in addr_block:
							if a.get('@addrtype') == 'ipv4':
								saddr = a.get('@addr')
								break

					if saddr == address:
						host_found = host
						nmaprun_source = {
							'nmaprun': o,
							'scanfile': fname  # local use only
						}
						break

				if host_found:
					break

			except Exception as e:
				print(f"[!] Failed to parse {xml_path}: {e}")
				continue

		if not host_found:
			return render(request, 'nmapreport/nmap_portdetails.html', {'error': 'Address not found'})

		o = nmaprun_source['nmaprun']
		scanfile = nmaprun_source['scanfile']  # DO NOT set this in session

	else:
		scanfile = request.session['scanfile']  # single file mode
		with open(f'/opt/xml/{scanfile}', 'r') as f:
			oo = xmltodict.parse(f.read())
		r['out2'] = json.dumps(oo['nmaprun'], indent=4)
		o = json.loads(r['out2'])

	# Compute hashes
	scanmd5 = hashlib.md5(scanfile.encode('utf-8')).hexdigest()
	addressmd5 = hashlib.md5(address.encode('utf-8')).hexdigest()
	r['trhost'] = ''
	v,e,z,h = '','','',''
	pc,po,pf=0,0,0

	# scanmd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
	# addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()

	# collect all labels in labelhost dict
	# labelhost = {}
	# labelfiles = os.listdir('/opt/notes')
	# for lf in labelfiles:
	# 	m = re.match('^('+scanmd5+')_([a-z0-9]{32,32})\.host\.label$', lf)
	# 	if m is not None:
	# 		if m.group(1) not in labelhost:
	# 			labelhost[m.group(1)] = {}
	# 		labelhost[m.group(1)][m.group(2)] = open('/opt/notes/'+lf, 'r').read()

	# # collect all notes in noteshost dict
	# noteshost = {}
	# notesfiles = os.listdir('/opt/notes')
	# for nf in notesfiles:
	# 	m = re.match('^('+scanmd5+')_([a-z0-9]{32,32})\.notes$', nf)
	# 	if m is not None:
	# 		if m.group(1) not in noteshost:
	# 			noteshost[m.group(1)] = {}
	# 		noteshost[m.group(1)][m.group(2)] = open('/opt/notes/'+nf, 'r').read()

	scanmd5 = get_scan_context_md5(request)

	labelhost = {}
	noteshost = {}

	try:
		notefiles = os.listdir('/opt/notes')
	except FileNotFoundError:
		notefiles = []

	for fname in notefiles:
		# Match label files
		m_label = re.match(r'^(' + re.escape(scanmd5) + r')_([a-f0-9]{32})\.host\.label$', fname)
		if m_label:
			_, hashstr = m_label.groups()
			labelhost.setdefault(scanmd5, {})
			with open(f'/opt/notes/{fname}', 'r') as f:
				labelhost[scanmd5][hashstr] = f.read()

		# Match note files
		m_note = re.match(r'^(' + re.escape(scanmd5) + r')_([a-f0-9]{32})\.notes$', fname)
		if m_note:
			_, hashstr = m_note.groups()
			noteshost.setdefault(scanmd5, {})
			with open(f'/opt/notes/{fname}', 'r') as f:
				noteshost[scanmd5][hashstr] = f.read()

	# collect all cve in cvehost dict
	cvehost = get_cve(scanmd5)

	r['trhead'] = '<tr><th>Port</th><th style="width:300px;">Product / Version</th><th>Extra Info</th><th>&nbsp;</th></tr>'
	for ik in o['host']:
		pel=0
		# this fix single host report
		if type(ik) is dict:
			i = ik
		else:
			i = o['host']

		if 'ports' not in i:
			continue

		if '@addr' in i['address']:
			saddress = i['address']['@addr']
		elif type(i['address']) is list:
			for ai in i['address']:
				if ai['@addrtype'] == 'ipv4':
					saddress = ai['@addr'] 

		if str(saddress) == address:
			hostname = ''
			if 'hostnames' in i and type(i['hostnames']) is dict:
				# hostname = json.dumps(i['hostnames'])
				if 'hostname' in i['hostnames']:
					hostname += '<br>'
					if type(i['hostnames']['hostname']) is list:
						for hi in i['hostnames']['hostname']:
							hostname += '<span class="small grey-text"><b>'+hi['@type']+':</b> '+hi['@name']+'</span><br>'
					else:
						hostname += '<span class="small grey-text"><b>'+i['hostnames']['hostname']['@type']+':</b> '+i['hostnames']['hostname']['@name']+'</span><br>'

			r['address'] = html.escape(str(saddress))
			r['hostname'] = hostname
			
			scantitle = scanfile.replace('.xml', '').replace('_', ' ')
			
			r['scanfile'] = scantitle



			labelout = '<span id="hostlabel"></span>'
			if scanmd5 in labelhost:
				if addressmd5 in labelhost[scanmd5]:
					labelcolor = labelToColor(labelhost[scanmd5][addressmd5])
					labelmargin = labelToMargin(labelhost[scanmd5][addressmd5])
					labelout = '<span id="hostlabel" style="margin-left:60px;margin-top:-24px;" class="rightlabel '+labelcolor+'">'+html.escape(labelhost[scanmd5][addressmd5])+'</span>'

					r['label'] = html.escape(labelhost[scanmd5][addressmd5])
					r['labelcolor'] = labelcolor

			rmdupl = {}
			r['tr'] = {}
			for pobj in i['ports']['port']:
				if type(pobj) is dict:
					p = pobj
				else:
					p = i['ports']['port']

				if p['@portid'] in rmdupl:
					continue

				rmdupl[p['@portid']] = 1

				if p['state']['@state'] == 'closed':
					pc = (pc + 1)
				elif p['state']['@state'] == 'open':
					po = (po + 1)
				elif p['state']['@state'] == 'filtered':
					pf = (pf + 1)

				pel = (pel + 1)
				oshtml = ''
				if 'service' in p:
					if '@ostype' in p['service']:
						oshtml = '<div style="font-family:monospace;padding:6px;margin:6px;border-left:solid #666 1px;"><sup style="border-bottom:solid #ccc 1px;">Operating System</sup><br>'+html.escape(p['service']['@ostype'])+'</div>'

				so = ''
				if 'script' in p:
					if '@id' in p['script']:
						if p['script']['@id'] != 'fingerprint-strings':
							so += '<div style="word-wrap: break-word;word-break: break-all;padding:6px;margin-left:6px;border-left:solid #666 1px;max-width:300px;font-size:12px;color:#ccc;font-family:monospace;"><sup style="color:#999;border-bottom:solid #999 1px;">script output</sup><br><b>'+html.escape(p['script']['@id'])+'</b> '+html.escape(p['script']['@output'])+'</div>'
					else:
						for sosc in p['script']:
							if '@id' in sosc:
								if sosc['@id'] != 'fingerprint-strings':
									so += '<div style="word-wrap: break-word;word-break: break-all;padding:6px;margin:6px;border-left:solid #666 1px;max-width:300px;font-size:12px;color:#ccc;font-family:monospace;"><sup style="color:#999;border-bottom:solid #999 1px;">script output</sup><br><b>'+html.escape(sosc['@id'])+'</b> '+html.escape(sosc['@output'])+'</div>'

				v,z,e = '','','<i class="grey-text">N/A</i>'
				if p['state']['@state'] == 'open':
					if 'service' in p:
						if '@version' in p['service']:
							v = p['service']['@version']
						else:
							v = '<i class="grey-text">No Version</i>'

						if '@product' in p['service']:
							z = p['service']['@product']
						else:
							z = '<i class="grey-text">No Product</i>'

						if '@extrainfo' in p['service']:
							e = p['service']['@extrainfo']

						cpe = ''
						if 'cpe' in p['service']:
							if type(p['service']['cpe']) is list:
								for cpei in p['service']['cpe']:
									cpe += '<div class="grey-text" style="font-family:monospace;font-size:12px;">'+html.escape(cpei)+'</div>'
							else:
									cpe = '<div class="grey-text" style="font-family:monospace;font-size:12px;">'+html.escape(p['service']['cpe'])+'</div>'

						servicename = p['service']['@name']
					else:
						servicename = ''
							
					r['tr'][p['@portid']] = {
						'service': servicename,
						'protocol': p['@protocol'],
						'portid': p['@portid'],
						'product': z,
						'version': v,
						'cpe':cpe,
						'state': p['state']['@state'],
						'reason': p['state']['@reason'],
						'extrainfo': e,
						'pel': str(pel)
					}

					r['trhost'] += '<tr><td style="vertical-align:top;">'+\
					'<span style="color:#999;font-size:12px;">'+servicename+'</span><br>'+\
					'<span class="new badge blue" data-badge-caption="">'+p['@protocol']+' / '+p['@portid']+'</span>'+\
					'</td>'+\
					'<td>'+z+' / '+v+'<br><span style="font-size:12px;color:#999;">State: '+p['state']['@state']+'<br>Reason: '+p['state']['@reason']+'</span></td>'+\
					'<td style="vertical-align:top">'+e+'<br>'+cpe+'</td>'+\
					'<td><ul id="dropdown'+str(pel)+'" class="dropdown-content" style="min-width:300px;">'+\
					'	<li><a href="#!" class="btncpy" data-clipboard-text="curl -v -A \'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1\' -k \'http://'+html.escape(address)+':'+html.escape(p['@portid'])+'\'">Copy as curl command</a></li>'+\
					'	<li><a href="#!" class="btncpy" data-clipboard-text="nikto -host \'http://'+html.escape(address)+':'+html.escape(p['@portid'])+'\'">Copy as nikto command</a></li>'+\
					'	<li><a href="#!" class="btncpy" data-clipboard-text="telnet '+html.escape(address)+' '+html.escape(p['@portid'])+'">Copy as telnet command</a></li>'+\
					'</ul><a class="dropdown-trigger btn blue right" href="#!" data-target="dropdown'+str(pel)+'"><i class="material-icons">arrow_drop_down</i></a> '+\
					'<button onclick="javascript:apiPortDetails(\''+html.escape(address)+'\',\''+html.escape(p['@portid'])+'\');" class="btn blue right"><i class="material-icons">receipt</i></button></td>'+\
					'</tr>'
				elif p['state']['@state'] == 'filtered':
					if 'service' in p:
						servicename = p['service']['@name']
					else:
						servicename = ''

					r['tr'][p['@portid']] = {
						'service': servicename,
						'protocol': p['@protocol'],
						'portid': p['@portid'],
						'state': p['state']['@state'],
						'reason': p['state']['@reason'],
						'pel': str(pel)
					}
					r['trhost'] += '<tr><td><span class="new badge grey" data-badge-caption="">'+p['@protocol']+' / '+p['@portid']+'</span><br>'+\
					'<span style="color:#999;font-size:12px;">'+servicename+'</span></td>'+\
					'<td colspan="2" style="color:#999;font-size:12px;">State: filtered<br>Reason: '+p['state']['@reason']+'</td>'+\
					'<td><button onclick="javascript:apiPortDetails(\''+html.escape(address)+'\',\''+html.escape(p['@portid'])+'\');" class="btn blue right"><i class="material-icons">receipt</i></button></td></tr>'
				else:
					if 'service' in p:
						servicename = p['service']['@name']
					else:
						servicename = ''

					r['tr'][p['@portid']] = {
						'service': servicename,
						'protocol': p['@protocol'],
						'portid': p['@portid'],
						'state': p['state']['@state'],
						'reason': p['state']['@reason'],
						'pel': str(pel)
					}
					r['trhost'] += '<tr><td><span class="new badge grey" data-badge-caption="">'+p['@protocol']+' / '+p['@portid']+'</span><br>'+\
					'<span style="color:#999;font-size:12px;">'+servicename+'</span></td>'+\
					'<td colspan="2" style="color:#999;font-size:12px;">State: '+p['state']['@state']+'<br>Reason: '+p['state']['@reason']+'</td>'+\
					'<td><button onclick="javascript:apiPortDetails(\''+html.escape(address)+'\',\''+html.escape(p['@portid'])+'\');" class="btn blue right"><i class="material-icons">receipt</i></button></td></tr>'

		# this fix single host report
		if type(ik) is not dict:
			break;

	r['table'] = ''
	notesout,notesb64,removenotes = '','',''
	if scanmd5 in noteshost:
		if addressmd5 in noteshost[scanmd5]:
			notesb64 = noteshost[scanmd5][addressmd5]
			r['table'] += '<div class="card" style="background-color:#3e3e3e;">'+\
			'	<div class="card-content"><h5>Notes</h5>'+\
			'		'+base64.b64decode(urllib.parse.unquote(notesb64)).decode('ascii')+\
			'	</div>'+\
			'</div>'
			r['notes'] = base64.b64decode(urllib.parse.unquote(notesb64)).decode('ascii')

	cveout = ''
	if scanmd5 in cvehost:
		if addressmd5 in cvehost[scanmd5]:
			cvejson = json.loads(cvehost[scanmd5][addressmd5])
			cveids = {}

			for i in cvejson:
				if type(i) is list:
					listcve = i
					#cveout += 'list<hr>'
				elif type(i) is dict:
					listcve = [i]
					#cveout += 'dict<hr>'
				#continue

				for cveobj in listcve:
					cverefout = ''
					for cveref in cveobj['references']:
						cverefout += '<a href="'+cveref+'">'+cveref+'</a><br>'

					cveexdbout = ''
					if 'exploit-db' in cveobj:
						cveexdbout = '<br><div class="small" style="line-height:20px;"><b>Exploit DB:</b><br>'
						for cveexdb in cveobj['exploit-db']:
							if 'title' in cveexdb:
								cveexdbout += '<a href="'+cveexdb['source']+'">'+html.escape(cveexdb['title'])+'</a><br>'
						cveexdbout += '</div>'

					cveout += '<div id="'+html.escape(cveobj['id'])+'" style="line-height:28px;padding:10px;border-bottom:solid #666 1px;margin-top:10px;">'+\
					'	<span class="label red">'+html.escape(cveobj['id'])+'</span> '+html.escape(cveobj['summary'])+'<br><br>'+\
					'	<div class="small" style="line-height:20px;"><b>References:</b><br>'+cverefout+'</div>'+\
					cveexdbout+\
					'</div>'
					cveids[cveobj['id']] = cveobj['id']
				
			r['cveids'] = cveids
			r['cvelist'] = cveout

	r['js'] = '<script> '+\
	'$(document).ready(function() { '+\
	'	$("#scantitle").html("'+html.escape(scanfile)+'");'+\
	'	var clipboard = new ClipboardJS(".btncpy"); '+\
	'	clipboard.on("success", function(e) { '+\
	'		M.toast({html: "Copied to clipboard"}); '+\
	'	}); '+\
	'	$(".dropdown-trigger").dropdown(); '+\
	'	$("#detailspo").html(\'<center><h4><i class="fas fa-door-open green-text"></i> '+str(po)+'</h4><span class="small grey-text">OPEN PORTS</span></center>\');'+\
	'	$("#detailspc").html(\'<center><h4><i class="fas fa-door-closed red-text"></i> '+str(pc)+'</h4><span class="small grey-text">CLOSED PORTS</span></center>\');'+\
	'	$("#detailspf").html(\'<center><h4><i class="fas fa-filter grey-text"></i> '+str(pf)+'</h4><span class="small grey-text">FILTERED PORTS</span></center>\');'+\
	'}); '+\
	'</script>'

	return render(request, 'nmapreport/nmap_portdetails.html', r)


def main_index(request, subpath="",filterservice="", filterportid=""):
	r = {}
	
	if 'auth' not in request.session:
		return render(request, 'nmapreport/nmap_auth.html', r)
	else:
		r['auth'] = True
	
	print("Selected scanfile:", request.session.get("scanfile"))
	print("Selected scanfolder:", request.session.get("scanfolder"))

	xml_base = '/opt/xml'

	rpath = os.path.join(xml_base, subpath)
	if  not rpath.startswith(xml_base):
			rpath = xml_base

	request.session['path']= rpath
	r['path']=rpath
	if subpath:
		parent_path = os.path.normpath(os.path.join(subpath, ".."))
		print("parent_path:",parent_path)
		if  not parent_path.startswith("xml_base"):
			parent_path = xml_base

		if parent_path == ".":
			parent_path = xml_base
		r['parent_path'] = parent_path
	else:
		r['parent_path'] = None  # At root

	selected_file = request.session.get('scanfile')
	selected_folder = request.session.get('scanfolder')

	r['tr'] = {}
	r['stats'] = {'po': 0, 'pc': 0, 'pf': 0}
	xmlfilescount = 0
	jsonfilescount = 0
	data = [] 
	collector_info = {}
	# CASE 1: A specific file is selected
	if selected_file:
		try:
			if selected_file.endswith('.xml'):
					print("seletedfile")
					xml_path = os.path.join(xml_base, selected_file)
					
					print(xml_path)
					# with open(xml_path, 'r') as f:
					# 	oo = xmltodict.parse(f.read())
					# r['out2'] = json.dumps(oo['nmaprun'], indent=4)
					# print("if",r['out2'])

					return render(request, 'nmapreport/nmap_hostdetails.html', {
								'js': '<script> location.href="/index"; </script>'
					})
			# elif selected_file.endswith('.json'):
			# 	print("seletedjsonfile")
			# 	jsonpath = os.path.join(xml_base, selected_file)
			# 	print(jsonpath)
			# 	with open(jsonpath, 'r') as f:
			# 		try:
			# 			jdata = json.load(f)
			# 			# If structure is same as XML-converted, access 'nmaprun'
			# 			if 'open_ports' in jdata:
			# 				r['out2'] = json.dumps(jdata['open_ports'], indent=4)
			# 				print("if",r['out2'])
			# 			else:
			# 				r['out2'] = json.dumps(jdata, indent=4)
			# 				print("else:",r['out2'])
			# 		except Exception as e:
			# 			r['out2'] = f"Failed to parse JSON: {html.escape(str(e))}"
			# 		return render(request, 'nmapreport/nmap_hostdetails.html', {
			# 					'js': '<script> location.href="/index"; </script>'
			# 		})

		except Exception as e:
			r['out2'] = f"Failed to parse selected file: {html.escape(str(e))}"
			return render(request, 'nmapreport/browser.html', r)

	# CASE 2: A folder is selected
	elif selected_folder and os.path.isdir(selected_folder):
		
		return render(request, 'nmapreport/nmap_hostdetails.html', {
								'js': '<script> location.href="/index"; </script>'
					})

	# CASE 3: No selection, fallback to listing all in /opt/xml
	else:
		print("nothing selected")
		r['stats'] = {'po': 0, 'pc': 0, 'pf': 0}
		r['tr'] = {}
		xmlfilescount = 0

		# for folders 
		for entry in os.listdir(rpath):
			full_entry_path = os.path.join(rpath, entry)
			if os.path.isdir(full_entry_path):
				# Initialize per-folder port stats
				folder_portstats = {'po': 0, 'pc': 0, 'pf': 0}
				folder_hostcount = 0

				for fname in os.listdir(full_entry_path):
					if fname.endswith('.xml'):
						xml_path = os.path.join(full_entry_path, fname)
						try:
							with open(xml_path, 'r') as f:
								oo = xmltodict.parse(f.read())
								nmaprun = oo.get('nmaprun', {})
								hosts = nmaprun.get('host', [])
								if isinstance(hosts, list):
									folder_hostcount += len(hosts)
								elif isinstance(hosts, dict):
									folder_hostcount += 1
						
							stats = ports_stats(xml_path)
							folder_portstats['po'] += stats.get('po', 0)
							folder_portstats['pc'] += stats.get('pc', 0)
							folder_portstats['pf'] += stats.get('pf', 0)
						except:
							continue
				if folder_hostcount > 0:
					href = f'/setscanpath/{os.path.join(subpath, entry)}'  # allow selection
				else:
					href = f'/browse/{os.path.join(subpath, entry)}'  # only browse inside
			
				r['tr'][entry + "/"] = {
					'filename': os.path.join(subpath, entry),
					'is_folder': True,
					'start': 0,
					'startstr': strftime('%Y-%m-%d %H:%M:%S', localtime(os.stat(full_entry_path).st_ctime)),
					'hostnum': folder_hostcount,
					'href': href,
					'portstats': folder_portstats
				}

		# for files
		for fname in os.listdir(rpath): 
			if not fname.endswith('.xml') :
				continue

			xmlfilescount += 1
			xml_path = os.path.join(rpath, fname)
			fullname = os.path.join(subpath, fname)

			try:
				with open(xml_path, 'r') as f:
					oo = xmltodict.parse(f.read())
			except Exception:
				r['tr'][fname] = {
					'filename': html.escape(fullname),
					'start': 0,
					'startstr': 'Incomplete / Invalid',
					'hostnum': 0,
					'href': '#!',
					'portstats': {'po': 0, 'pc': 0, 'pf': 0}
				}
				continue

			r['out2'] = json.dumps(oo['nmaprun'], indent=4)
			o = json.loads(r['out2'])

			hostnum = str(len(o['host'])) if isinstance(o.get('host'), list) else '1' if 'host' in o else '0'
			viewhref = f'/setscanpath/{html.escape(fullname)}' if hostnum != '0' else '#!'
			
			portstats = ports_stats(xml_path)
			r['stats']['po'] += portstats.get('po', 0)
			r['stats']['pc'] += portstats.get('pc', 0)
			r['stats']['pf'] += portstats.get('pf', 0)

			r['tr'][fname] = {
				'filename': html.escape(fullname),
				'start': int(o.get('start', 0)),
				'startstr': o.get('@startstr', 'unknown'),
				'hostnum': hostnum,
				'href': viewhref,
				'portstats': portstats
			}

		r['tr'] = OrderedDict(sorted(r['tr'].items()))
		r['stats']['xmlcount'] = xmlfilescount

		return render(request, 'nmapreport/browser.html', r)


def index(request, filterservice="", filterportid=""):
	r = {}
	
	
	if 'auth' not in request.session:
		return render(request, 'nmapreport/nmap_auth.html', r)
	else:
		r['auth'] = True

	if 'scanfile' in request.session:
		oo = xmltodict.parse(open('/opt/xml/'+request.session['scanfile'], 'r').read())
		r['out2'] = json.dumps(oo['nmaprun'], indent=4)
		o = json.loads(r['out2'])
		meta = {
			'startstr': oo['nmaprun'].get('@startstr', 'Unknown'),
			'version': oo['nmaprun'].get('@version', 'Unknown'),
			'args': oo['nmaprun'].get('@args', ''),
			'xmlver': oo['nmaprun'].get('@xmloutputversion', ''),
			'scantype': '',
			'protocol': ''
		}

		scaninfo = oo['nmaprun'].get('scaninfo')
		if isinstance(scaninfo, dict):
			meta['scantype'] = scaninfo.get('@type', '')
			meta['protocol'] = scaninfo.get('@protocol', '')
		elif isinstance(scaninfo, list):
			meta['scantype'] = ', '.join(s.get('@type', '') for s in scaninfo)
			meta['protocol'] = ', '.join(s.get('@protocol', '') for s in scaninfo)

		# Repeat meta for each host
		hosts = o.get('host', [])
		if isinstance(hosts, dict):
			hosts = [hosts]
		o['host'] = hosts
		o['_metadata_per_host'] = [meta] * len(hosts)

		scanmd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
		r['scanfile'] = html.escape(str(request.session['scanfile']))
		r['scanmd5'] = scanmd5
		
	elif 'scanfolder' in request.session:
		folder_path = os.path.join('/opt/xml', request.session['scanfolder'])
		host_list = []
		metadata_per_host = []

		for filename in os.listdir(folder_path):
			if filename.endswith('.xml'):
				full_path = os.path.join(folder_path, filename)
				with open(full_path, 'r') as f:
					oo = xmltodict.parse(f.read())
					nmaprun = oo['nmaprun']

					meta = {
						'startstr': nmaprun.get('@startstr', 'Unknown'),
						'version': nmaprun.get('@version', 'Unknown'),
						'args': nmaprun.get('@args', 'Unknown'),
						'xmlver': nmaprun.get('@xmloutputversion', 'Unknown'),
						'scantype': '',
						'protocol': ''
					}

					if 'scaninfo' in nmaprun:
						if isinstance(nmaprun['scaninfo'], dict):
							meta['scantype'] = nmaprun['scaninfo'].get('@type', '')
							meta['protocol'] = nmaprun['scaninfo'].get('@protocol', '')
						elif isinstance(nmaprun['scaninfo'], list):
							meta['scantype'] = ', '.join(si.get('@type', '') for si in nmaprun['scaninfo'])
							meta['protocol'] = ', '.join(si.get('@protocol', '') for si in nmaprun['scaninfo'])

					hosts = nmaprun.get('host', [])
					if isinstance(hosts, dict):
						hosts = [hosts]
					for h in hosts:
						host_list.append(h)
						metadata_per_host.append(meta)

		o = {'host': host_list, '_metadata_per_host': metadata_per_host}
		scanmd5 = hashlib.md5(request.session['scanfolder'].encode('utf-8')).hexdigest()
		r['scanfile'] = html.escape(str(request.session['scanfolder']))
		r['scanmd5'] = scanmd5

		

	# scanmd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
	# r['scanfile'] = html.escape(str(request.session['scanfile']))
	# r['scanmd5'] = scanmd5
	

	# collector_info = {}
	# try:
	# 	with open('/opt/xml/collectorout.json', 'r') as f:
	# 		collector_data = json.load(f)
	# 		for entry in collector_data:
	# 			collector_info[entry['ip']] = {
	# 				'ftp_anonymous': entry.get('ftp_anonymous', False),
	# 				'telnet_guest': entry.get('telnet_guest', False)
	# 			}
			
	# except Exception as e:
	# 	print(f"Warning: could not load collector info: {e}")
	xml_base = "/opt/xml"
	selected_file = request.session.get("scanfile")
	selected_folder = request.session.get("scanfolder")

	if selected_file:
		start_path = os.path.join(xml_base, selected_file)
		if os.path.isfile(start_path):
			search_start = os.path.dirname(start_path)
		else:
			search_start = start_path
	elif selected_folder:
		search_start = os.path.join(xml_base, selected_folder)
	else:
		search_start = xml_base

	collector_info = load_collector_info(search_start)
		
	
	
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

	tableout = ''
	hostsup = 0   
	hostindex = 1
	ports = { 'open': 0, 'closed': 0, 'filtered': 0 }
	allostypelist, sscount, picount, cpe = {}, {}, {}, {}

	r['tr'] = {}
	r['stats'] = {}

	for meta_index, ik in enumerate(o['host']):
		i = ik if isinstance(ik, dict) else o['host']
		metadata_list = o.get('_metadata_per_host')
		if metadata_list and meta_index < len(metadata_list):
			host_meta = metadata_list[meta_index]
		else:
			host_meta = {
				'startstr': 'Unknown',
				'version': '',
				'args': '',
				'xmlver': '',
				'scantype': '',
				'protocol': ''
			}


		# this fix single host report
		# if type(ik) is dict:
		# 	i = ik
		# else:
		# 	i = o['host']

		hostname = ''
		if 'hostnames' in i and type(i['hostnames']) is dict:
			# hostname = json.dumps(i['hostnames'])
			if 'hostname' in i['hostnames']:
				#hostname += '<br>'
				if type(i['hostnames']['hostname']) is list:
					for hi in i['hostnames']['hostname']:
						hostname += '<div class="small grey-text"><b>'+hi['@type']+':</b> '+hi['@name']+'</div>'
				else:
					hostname += '<div class="small grey-text"><b>'+i['hostnames']['hostname']['@type']+':</b> '+i['hostnames']['hostname']['@name']+'</div>'

		po,pc,pf = 0,0,0
		ss,pp,ost = {},{},{}
		lastportid = 0

		if '@addr' in i['address']:
			address = i['address']['@addr']
		elif type(i['address']) is list:
			for ai in i['address']:
				if ai['@addrtype'] == 'ipv4':
					address = ai['@addr'] 

		addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()

		if i['status']['@state'] == 'up':
			if address not in cpe:
				hostsup = (hostsup + 1)

				r['tr'][address] = {
					'hostindex': '',
					'hostname': hostname,
					'po': 0,
					'pc': 0,
					'pf': 0,
					'totports': str(0),
					'addressmd5': addressmd5
				}

		cpe[address] = {}

		striggered = False
		e = ''
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

				if 'service' in p:
					if filterservice != "" and p['service']['@name'] == filterservice:
						striggered = True

					if filterportid != "" and p['@portid'] == filterportid:
						striggered = True

				pp[p['@portid']] = p['@portid']

				if 'service' in p:
					ss[p['service']['@name']] = p['service']['@name']

					if '@extrainfo' in p['service']:
						e = p['service']['@extrainfo']

					# cpehtml = ''
					if 'cpe' in p['service']:
						if type(p['service']['cpe']) is list:
							for cpei in p['service']['cpe']:
								cpe[address][cpei] = cpei
						else:
							cpe[address][p['service']['cpe']] = p['service']['cpe']
		

					if '@ostype' in p['service']:
						if p['service']['@ostype'] in allostypelist:
							allostypelist[p['service']['@ostype']] = (allostypelist[p['service']['@ostype']] +1)
						else:
							allostypelist[p['service']['@ostype']] = 1;

						ost[p['service']['@ostype']] = p['service']['@ostype']

					if p['service']['@name'] in sscount:
						sscount[p['service']['@name']] = (sscount[p['service']['@name']] + 1)
					else:
						sscount[p['service']['@name']] = 1

				if p['@portid'] in picount:
					picount[p['@portid']] = (picount[p['@portid']] + 1)
				else:
					picount[p['@portid']] = 1
					
				if p['state']['@state'] == 'closed':
					ports['closed'] = (ports['closed'] + 1)
					pc = (pc + 1)
				elif p['state']['@state'] == 'open':
					ports['open'] = (ports['open'] + 1)
					po = (po + 1)
				elif p['state']['@state'] == 'filtered':
					ports['filtered'] = (ports['filtered'] + 1)
					pf = (pf + 1)

			services = ''
			for s in ss:
				if filterservice != ss[s]:
					services += '<a href="/report/service/'+ss[s]+'/">'+ss[s]+'</a>, '
				else:
					services += '<span class="tmlabel" style="background-color:#ffcc00;color:#333;">'+ss[s]+'</span>, '

			ostype = ''
			for oty in ost:
				ostype += '<i class="'+fromOSTypeToFontAwesome(html.escape(ost[oty]))+'"></i> <span class="grey-text small">'+ost[oty].lower()+'</span> '

			tdports = ''
			for kp in pp:
				if filterportid != pp[kp]:
					tdports += '<a href="/report/portid/'+pp[kp]+'/">'+pp[kp]+'</a>, '
				else:
					tdports += '<span class="tmlabel" style="background-color:#ffcc00;color:#333;">'+pp[kp]+'</span>, '

			poclass = ''
			if po == 0:
				poclass = 'zeroportopen'

			labelout = '<span id="hostlabel'+str(hostindex)+'"></span>'
			newlabelout = '<div id="hostlabel'+str(hostindex)+'"></div><div id="hostlabelbb'+str(hostindex)+'"></div>'
			if scanmd5 in labelhost:
				if addressmd5 in labelhost[scanmd5]:
					labelcolor = labelToColor(labelhost[scanmd5][addressmd5])
					labelmargin = labelToMargin(labelhost[scanmd5][addressmd5])
					labelout = '<span id="hostlabel'+str(hostindex)+'" style="margin-left:'+labelmargin+'" class="rightlabel '+labelcolor+'">'+html.escape(labelhost[scanmd5][addressmd5])+'</span>'
					newlabelout = '<div id="hostlabel'+str(hostindex)+'" style="z-index:99;transform: rotate(-8deg);margin-top:-14px;margin-left:-40px;" class="leftlabel '+labelcolor+'">'+html.escape(labelhost[scanmd5][addressmd5])+'</div>'+\
										'<div id="hostlabelbb'+str(hostindex)+'" class="'+labelcolor+'" style="border-radius:0px 4px 0px 4px;z-index:98;position:absolute;width:18px;height:10px;margin-left:-54px;margin-top:-3px;"></div>'

			notesout,notesb64,removenotes = '','',''
			if scanmd5 in noteshost:
				if addressmd5 in noteshost[scanmd5]:
					notesb64 = noteshost[scanmd5][addressmd5]
					notesout = '<a id="noteshost'+str(hostindex)+'" class="grey-text" href="#!" onclick="javascript:openNotes(\''+hashlib.md5(str(address).encode('utf-8')).hexdigest()+'\', \''+notesb64+'\');"><i class="fas fa-comment"></i> contains notes</a>'
					removenotes = '<li><a href="#!" class="grey-text" onclick="javascript:removeNotes(\''+addressmd5+'\', \''+str(hostindex)+'\');">Remove notes</a></li>'

			cveout = ''
			cvecount = 0
			if scanmd5 in cvehost:
				if addressmd5 in cvehost[scanmd5]:
					cvejson = json.loads(cvehost[scanmd5][addressmd5])
					for ic in cvejson:
						if type(ic) is list:
							listcve = ic
						elif type(ic) is dict:
							listcve = [ic]

						for cvei in listcve:
							if 'id' in cvei:
								cvecount = (cvecount + 1)

					if cvecount > 0:
						cveout = '<a href="/report/'+address+'" class="grey-text"><i class="fas fa-exclamation-triangle"></i> '+str(cvecount)+' CVE found</a>'

			if (filterservice != "" and striggered is True) or (filterportid != "" and striggered is True) or (filterservice == "" and filterportid == ""):
				portstateout = '<div style="overflow:none;background-color:#444;" class="tooltipped" data-position="top" data-tooltip="'+str(po)+' open, '+str(pc)+' closed, '+str(pf)+' filtered">'+\
				'		<div class="perco" data-po="'+str(po)+'" style="padding-left:16px;padding-right:20px;"><b>'+str(po)+'</b></div>'+\
				' </div>'

				if (filterservice != "" and striggered is True):
					portstateout = '<div style="overflow:none;background-color:#444;" class="tooltipped" data-position="top" data-tooltip="'+str(po)+' open, '+str(pc)+' closed, '+str(pf)+' filtered">'+\
					'		<div class="perco" data-po="'+str(po)+'" data-pt="'+str((po + pf + pc))+'" style="padding-left:16px;padding-right:20px;"><b>'+str(po)+'</b></div>'+\
					'	</div>'

				tags = []
				extrainfosplit = e.split(' ')
				for eis in extrainfosplit:
					if re.search('[a-zA-Z0-9\_]+\/[0-9\.]+', eis) is not None:
						robj = re.search('([a-zA-Z0-9\_]+)\/([0-9\.]+)', eis)
						tags.append(robj.group(1)+' '+robj.group(2))


				r['tr'][address] = {
					'hostindex': str(hostindex),
					'hostname': hostname,
					'ostype': ostype,
					'notes': notesout,
					'cve': cveout,
					'portstate': portstateout,
					'po': po,
					'pc': pc,
					'pf': pf,
					'tags':tags,
					'totports': str((po + pf + pc)),
					'services': str(services[0:-2]),
					'ports': str(tdports[0:-2]),
					'addressmd5': addressmd5,
					'removenotes': removenotes,
					'labelout': labelout,
					'newlabelout': newlabelout,
					'notesb64': notesb64,
					'notesout': notesout,
					'cveout': cveout,
					'cvecount': cvecount,
					'startstr': host_meta.get('startstr', 'Unknown'),
					'nmapver': host_meta.get('version', ''),
					'nmapargs': host_meta.get('args', ''),
					'xmlver': host_meta.get('xmlver', ''),
					'scantype': host_meta.get('scantype', ''),
					'protocol': host_meta.get('protocol', ''),
					
				}
				if address in collector_info:
					r['tr'][address]['ftp_anonymous'] = collector_info[address]['ftp_anonymous']
					r['tr'][address]['telnet_guest'] = collector_info[address]['telnet_guest']
				else:
					r['tr'][address]['ftp_anonymous'] = False
					r['tr'][address]['telnet_guest'] = False

				hostindex = (hostindex + 1)

				# this fix single host report
				if type(ik) is not dict:
					break;
			else:
				if address in r['tr']:
					del r['tr'][address]
		else:
			if address in r['tr']:
				del r['tr'][address]


	totports = (ports['open']+ports['closed']+ports['filtered'])
	if filterservice == "" and filterportid == "":
		scaninfobox2 = '<canvas id="chart1"></canvas>'
		scaninfobox3 = '<canvas id="chart3" height="150"></canvas>'
	else:
		scaninfobox2 = '<div class="small">'+\
		'	<b class="orange-text">Filter port / service:</b> <b>'+html.escape(filterportid+filterservice)+'</b> <a href="/"><i class="fas fa-trash-alt"></i></a><br>'+\
		'	<b class="orange-text">Total Ports:</b> '+str(totports)+'<br>'+\
		'	<b class="orange-text">Open Ports:</b> '+str(ports['open'])+'<br>'+\
		'	<b class="orange-text">Closed Ports:</b> '+str(ports['closed'])+'<br>'+\
		'	<b class="orange-text">Filtered Ports:</b> '+str(ports['filtered'])+'</div>'
		scaninfobox3 = '<div id="detailstopports"></div>'

	scantype = ''
	if 'scaninfo' in o and '@type' in o['scaninfo']:
		scantype = o['scaninfo']['@type']

	if 'scaninfo' in o and type(o['scaninfo']) is list:
		for sinfo in o['scaninfo']:
			scantype += sinfo['@type']+', '
		scantype = scantype[0:-2]

	protocol = ''
	if 'scaninfo' in o and '@protocol' in o['scaninfo']:
		protocol = o['scaninfo']['@protocol']

	if 'scaninfo' in o and type(o['scaninfo']) is list:
		for sinfo in o['scaninfo']:
			protocol += sinfo['@protocol']+', '
		protocol = protocol[0:-2]

	r['stats'] = {
		'scaninfobox2': scaninfobox2,
		'scaninfobox3': scaninfobox3,
		# 'startstr': o['@startstr'],
		'scantype': scantype,
		'protocol': protocol,
		# 'nmapver': o['@version'],
		# 'nmapargs': o['@args'],
		# 'xmlver': o['@xmloutputversion'],
		'hostsup': str(hostsup),
		'popen': ports['open'],
		'pclosed': ports['closed'],
		'pfiltered': ports['filtered']
	}
	
	allss = ''
	allsslabels = ''
	allssdata = ''
	allssc = 0
	for i in sorted(sscount, key=sscount.__getitem__, reverse=True):
		if allssc <= 30:
			if filterservice != i:
				allss += '<a href="/report/service/'+html.escape(i)+'/">'+html.escape(i)+'('+str(sscount[i])+')</a>, '
			else:
				allss += '<span class="tmlabel" style="background-color:#ffcc00;color:#333;">'+html.escape(i)+'</span>, '

			allsslabels += '"'+html.escape(i)+'", '
			allssdata += ''+str(sscount[i])+','
			allssc = (allssc + 1)

	allpilabels = ''
	allpidata = ''
	allpilinks = ''
	allpic = 1
	for i in sorted(picount, key=picount.__getitem__, reverse=True):
		if allpic <= 5:
			allpilinks += '<a href="/report/portid/'+str(i)+'/">'+str(i)+'</a>, '
			allpilabels += '"'+html.escape(i)+'", '
			allpidata += ''+str(picount[i])+','
			allpic = (allpic + 1)
		elif allpic > 5 and allpic <= 10:
			allpilinks += '<a href="/report/portid/'+str(i)+'/">'+str(i)+'</a>, '
			allpic = (allpic + 1)

	allostypelinks = ''
	for i in sorted(allostypelist, key=allostypelist.__getitem__, reverse=True):
		allostypelinks += '<a href="">'+str(i)+'</a>, '


	r['stats']['services'] = allss[0:-2]
	r['stats']['portids'] = allpilinks[0:-2]
	r['stats']['ostypes'] = allostypelinks[0:-2]

	r['pretable'] = ''
	r['js'] = ''
	if filterservice == "" and filterportid == "":
		r['js'] += '<script>'+\
		'	$(document).ready(function() {'+\
		'		var ctx = document.getElementById("chart1").getContext("2d");'+\
		'		var myChart = new Chart(ctx, {'+\
		'			type: "doughnut", data: {labels:["Open", "Filtered", "Closed"], datasets: [{ data: ['+str(ports['open'])+','+str(ports['filtered'])+','+str(ports['closed'])+'], backgroundColor:["rgba(0,150,0,0.8)","rgba(255,200,0,0.8)","rgba(255,0,0,0.8)"], borderColor:"#ccc", borderWidth:0 }]}, options: {legend: { position: "right", labels: { fontColor: "#ccc" }  }}'+\
		'		});'+\
		'		var ctx = document.getElementById("chart3").getContext("2d");'+\
		'		var myChart = new Chart(ctx, {'+\
		'			type: "doughnut", data: {labels:['+allpilabels[0:-2]+'], datasets: [{ data: ['+allpidata[0:-1]+'], borderColor: "#fff", borderWidth:0,  backgroundColor:["#e6194b", "#3cb44b", "#ffe119", "#4363d8", "#f58231", "#911eb4", "#46f0f0", "#f032e6", "#bcf60c", "#fabebe", "#008080", "#e6beff", "#9a6324", "#fffac8", "#800000", "#aaffc3", "#808000", "#ffd8b1", "#000075", "#808080", "#ffffff", "#000000"] }]}, options: {legend: { position: "right", labels: { fontColor: "#ccc" }}}'+\
		'		});'+\
		'		var ctx = document.getElementById("chart2").getContext("2d");'+\
		'		var myChart = new Chart(ctx, {'+\
		'			type: "horizontalBar", data: { labels:['+allsslabels[0:-2]+'], datasets: [{ data: ['+allssdata[0:-1]+'], backgroundColor: "rgba(0,140,220,0.8)" }]}, options: {legend: { display: false }, scales: { xAxes: [{ ticks: { beginAtZero: true, fontColor: "#666" } }], yAxes: [{ ticks: { fontColor: "#666" } }] }  }'+\
		'		});'+\
		'	});'+\
		'</script>'
	else:
		r['pretablestyle'] = 'display:none;'

	r['js'] += '<script>'+\
	'	$(document).ready(function() {'+\
	'		/* $("#scantitle").html("'+html.escape(request.session.get('scanfile') or request.session.get('scanfolder'))+'"); */ '+\
	'		$(".dropdown-trigger").dropdown();'+\
	'		$(".tooltipped").tooltip();'+\
	'		$(".perco").each(function() { '+\
	'			var pwidth = ( (($(this).attr("data-po") * 100) / '+str(totports)+') ); '+\
	'			/* console.log(pwidth); */ '+\
	'			$(this).css("width", pwidth+"%" ); '+\
	'			if($(this).attr("data-po") < 1) { $(this).html("&nbsp;"); $(this).css("background-color","#666") } '+\
	'		});'+\
	'	$("#detailstopports").html(\'<span class="small">'+str(allss[0:-2])+'</span>\');'+\
	'	});'+\
	'</script>'

	cpedict = {}
	#r['cpestring'] = ''
	for cpeaddr in cpe:
		for cpei in cpe[cpeaddr]:
			if re.search('^cpe:.+:.+:.+:.+$', cpei) is not None:
				#r['cpestring'] += cpei+'<br>'
				if cpei not in cpedict:
					cpedict[cpei] = {}
				if cpeaddr not in cpedict[cpei]:
					cpedict[cpei][cpeaddr] = 1

	r['cpestring'] = ' <input type="hidden" id="cpestring" value="'+urllib.parse.quote_plus(base64.b64encode(json.dumps(cpedict).encode()))+'" /> '

	return render(request, 'nmapreport/nmap_hostdetails.html', r)

def scan_diff(request, f1, f2):
	r = {}

	if 'auth' not in request.session:
		return render(request, 'nmapreport/nmap_auth.html', r)
	else:
		r['auth'] = True

	try:
		if xmltodict.parse(open('/opt/xml/'+f1, 'r').read()) is not None:
			r['f1'] = f1
		if xmltodict.parse(open('/opt/xml/'+f2, 'r').read()) is not None:
			r['f2'] = f2
	except:
		r['f1'] = ''
		r['f2'] = ''

	return render(request, 'nmapreport/nmap_ndiff.html', r)

def about(request):
	r = {}

	if 'auth' not in request.session:
		return render(request, 'nmapreport/nmap_auth.html', r)
	else:
		r['auth'] = True

	return render(request, 'nmapreport/nmap_about.html', r)


		
