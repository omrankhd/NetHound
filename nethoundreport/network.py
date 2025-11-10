from django.shortcuts import render

import xmltodict, json,  os, hashlib
from collections import OrderedDict
from nethoundreport.functions import *

def visjs(request):
	r = {}

	if 'auth' not in request.session:
		return render(request, 'nethoundreport/nmap_auth.html', r)
	else:
		r['auth'] = True
		

	selected_file = request.session.get('scanfile')
	selected_folder = request.session.get('scanfolder')
	if selected_file:
		

		oo = xmltodict.parse(open('/opt/xml/'+request.session['scanfile'], 'r').read())
		r['out2'] = json.dumps(oo['nmaprun'], indent=4)
		o = json.loads(r['out2'])

		scanmd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()

		r['scanfile'] = request.session['scanfile']
		r['scanmd5'] = scanmd5

		addnodes = ''
		portnodes = {}

		for ik in o['host']:
			if type(ik) is dict:
				i = ik
			else:
				i = o['host']

			if i['status']['@state'] != 'up':
				continue

			# Determine IP address
			if '@addr' in i['address']:
				address = i['address']['@addr']
			elif isinstance(i['address'], list):
				for ai in i['address']:
					if ai['@addrtype'] == 'ipv4':
						address = ai['@addr']
			else:
				continue

			addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()

			# Add IP node and edge to scan root
			addnodes += f"addNode('addr{addressmd5}', '{address}', '\\uf0a0', '#090', '#999');\n"
			addnodes += f"edges.add({{ id: 'edge{addressmd5}', from: 'addr{addressmd5}', to: 'scan{scanmd5}', color:{{color: '#cccccc'}} }});\n"

			# Now handle port nodes
			if 'ports' in i and 'port' in i['ports']:
				ports = i['ports']['port']
				if isinstance(ports, dict):
					ports = [ports]  # handle single port case

				for p in ports:
					portid = p['@portid']
					portstate = p['state']['@state']

					# Set color and icon based on state
					if portstate == 'closed':
						color = '#f00'
						icon = '\\uf057'
					elif portstate == 'open':
						color = '#090'
						icon = '\\uf058'
					elif portstate == 'filtered':
						color = '#666'
						icon = '\\uf146'
					else:
						color = '#999'
						icon = '\\uf05e'

					portnode_id = f"port{addressmd5}{portid}"
					addnodes += f"addNode('{portnode_id}', '{portid}', '{icon}', '{color}', '#999');\n"
					addnodes += f"edges.add({{ id: 'edgeport{addressmd5}{portid}', from: 'addr{addressmd5}', to: '{portnode_id}', color:{{color: '#cccccc'}} }});\n"

					# Optional: add service/product/version/extrainfo
					if 'service' in p:
						product = p['service'].get('@product', '')
						version = p['service'].get('@version', '')
						extrainfo = p['service'].get('@extrainfo', '')

						label = f"{product} / {version}\\n{extrainfo}"
						servicenode_id = f"product{addressmd5}{portid}"
						addnodes += f"addNode('{servicenode_id}', '\\n{label}', '\\uf27a', '#666', '#999');\n"
						addnodes += f"edges.add({{ id: 'edgeproduct{addressmd5}{portid}', from: '{portnode_id}', to: '{servicenode_id}', color:{{color: '#cccccc'}} }});\n"

			if type(ik) is not dict:
				break;


		r['js'] = '<script>$(document).ready(function() {' +\
		'addNode("scan'+scanmd5+'", "'+request.session['scanfile']+'", "\\uf15b", "#ccc", "#ccc");\n' +\
		addnodes +\
		'});</script>'

		return render(request, 'nethoundreport/nmap_network.html', r)

# updates



 

	elif selected_folder and os.path.isdir(selected_folder):	

		
		folder_path = request.session['scanfolder']
		folder_name = os.path.basename(folder_path.rstrip('/'))
		scanmd5 = hashlib.md5(folder_name.encode('utf-8')).hexdigest()
		r['scanfolder'] = folder_name

		addnodes = f"addNode('scan{scanmd5}', '{folder_name}', '\\uf07b', '#ccc', '#ccc');\n"

		try:
			xml_files = [f for f in os.listdir(folder_path) if f.endswith('.xml')]
		except Exception as e:
			r['js'] = f"<script>alert('Could not read folder: {e}');</script>"
			return render(request, 'nethoundreport/nmap_network.html', r)

		for fname in xml_files:
			try:
				with open(os.path.join(folder_path, fname), 'r') as f:
					oo = xmltodict.parse(f.read())
				o = json.loads(json.dumps(oo['nmaprun'], indent=4))
			except Exception:
				continue

			hosts = o.get('host', [])
			if not isinstance(hosts, list):
				hosts = [hosts]

			for i in hosts:
				if i.get('status', {}).get('@state') != 'up':
					continue

				address = None
				addr_info = i.get('address', {})
				if isinstance(addr_info, list):
					for a in addr_info:
						if a.get('@addrtype') == 'ipv4':
							address = a.get('@addr')
				elif isinstance(addr_info, dict):
					address = addr_info.get('@addr')

				if not address:
					continue

				addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()
				addnodes += f"addNode('addr{addressmd5}', '{address}', '\\uf0a0', '#090', '#999');\n"
				addnodes += f"edges.add({{ id: 'edge{addressmd5}', from: 'addr{addressmd5}', to: 'scan{scanmd5}', color:{{color: '#cccccc'}} }});\n"

				ports = i.get('ports', {}).get('port', [])
				if isinstance(ports, dict):
					ports = [ports]

				for p in ports:
					portid = p.get('@portid')
					state = p.get('state', {}).get('@state', 'unknown')

					color, icon = {
						'closed': ('#f00', '\\uf057'),
						'open': ('#090', '\\uf058'),
						'filtered': ('#666', '\\uf146')
					}.get(state, ('#999', '\\uf05e'))

					portnode_id = f"port{addressmd5}{portid}"
					addnodes += f"addNode('{portnode_id}', '{portid}', '{icon}', '{color}', '#999');\n"
					addnodes += f"edges.add({{ id: 'edgeport{addressmd5}{portid}', from: 'addr{addressmd5}', to: '{portnode_id}', color:{{color: '#cccccc'}} }});\n"

					service = p.get('service', {})
					if isinstance(service, dict):
						service_nmae = service.get('@name', 'unknown')
						product = service.get('@product', 'No Product')
						version = service.get('@version', 'No Version')
						extrainfo = service.get('@extrainfo', '')
						label = f"{service_nmae} / {product} / {version}\\n{extrainfo}"
						servicenode_id = f"product{addressmd5}{portid}"
						addnodes += f"addNode('{servicenode_id}', '\\n{label}', '\\uf27a', '#666', '#999');\n"
						addnodes += f"edges.add({{ id: 'edgeproduct{addressmd5}{portid}', from: '{portnode_id}', to: '{servicenode_id}', color:{{color: '#cccccc'}} }});\n"

		r['js'] = f"<script>$(document).ready(function() {{\n{addnodes}}});</script>"
		return render(request, 'nethoundreport/nmap_network.html', r)

	else:
		r['js'] = '''
				<script>
				$(document).ready(function() {
					$('.modal').modal();
					$('#mynetwork').remove();
					$('#modaltitle').html('Error');
					$('#modalbody').html('Please select a folder first.');
					$('#modalfooter').html('<a href="/" class="btn red">Go to folder selection</a>');
					setTimeout(function() { $('#modal1').modal('open'); }, 1000);
				});
				</script>
			'''
		return render(request, 'nethoundreport/nmap_network.html', r)

# # updated file