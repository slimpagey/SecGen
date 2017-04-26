class ad::user{
	$json_inputs = base64('decode', $::base64_inputs)
	$secgen_params = parsejson($json_inputs)
	$domain_name = ''
	$accnt_name = ''
	$first_name = ''
	$full_name = ''
	$lastname = ''
	$dc = ''
	$tld = ''
	$cn = ''
	$pass_expire = ''
	$pass_len = ''
	$email = ''

	windows_ad::user{'Add_user':
  		ensure               => present,
  		domainname           => 'jre.local',
  		path                 => 'OU=PLOP,DC=JRE,DC=LOCAL',
  		accountname          => 'test',
  		lastname             => 'test',                   
  		firstname            => 'test',                   
  		passwordneverexpires => true,
  		passwordlength       => 15,                       
  		password             => 'M1Gr3atP@ssw0rd',        
  		xmlpath              => 'C:\\users.xml',          
  		writetoxmlflag       => true,                    
  		emailaddress         => 'test@jre.local',
	}
}