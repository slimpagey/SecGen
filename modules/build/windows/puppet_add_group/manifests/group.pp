class ad::group{
	$json_inputs = base64('decode', $::base64_inputs)
	$secgen_params = parsejson($json_inputs)
	$group_name = ''
	$display_name = ''
	$dc = ''
	$tld = ''
	$cn = ''
	$group_scope = ''
	$catagory = ''
	$description = ''

	windows_ad::group{'':
  		ensure               => present,
  		displayname          => '',
  		path                 => 'CN=,DC=,DC=',
  		groupname            => '',
  		groupscope           => '',
  		groupcategory        => '',
  		description          => '',
	}
}