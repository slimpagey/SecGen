class ad::user{
	$json_inputs = base64('decode', $::base64_inputs)
	$secgen_params = parsejson($json_inputs)
	$domain_name = ''
	$group_name = ''
	$user = ''

	windows_ad::groupmembers{'Member groupplop':
  		ensure    => present,
  		groupname => '',
  		members   => '',
	}
}