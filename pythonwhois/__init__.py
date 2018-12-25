from . import net, parse

def get_whois(domain, normalized=[]):
	result = get_whois_main(domain, normalized)
	# unless creation_date is not found, consider the given one is subdomain
	# and check again with main domain
	# i.e. mail.xxx.com -> xxx.com

	subdomain = domain

	while True:
		if "creation_date" in result and result["creation_date"] != None:
			break
		parts = subdomain.split(".")
		if len(parts) <= 2:
			break
		subdomain = ".".join(parts[1:])
		result = get_whois_main(subdomain, normalized)
		if "creation_date" in result and result["creation_date"] != None:
			break
	return result

def get_whois_main(domain, normalized=[]):
	raw_data, server_list = net.get_whois_raw(domain, with_server_list=True)
	# Unlisted handles will be looked up on the last WHOIS server that was queried. This may be changed to also query
	# other servers in the future, if it turns out that there are cases where the last WHOIS server in the chain doesn't
	# actually hold the handle contact details, but another WHOIS server in the chain does.
	return parse.parse_raw_whois(raw_data, normalized=normalized, never_query_handles=False, handle_server=server_list[-1])

def whois(*args, **kwargs):
	raise Exception("The whois() method has been replaced by a different method (with a different API), since pythonwhois 2.0. Either install the older pythonwhois 1.2.3, or change your code to use the new API.")
