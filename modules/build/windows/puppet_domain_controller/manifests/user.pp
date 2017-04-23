windows_ad::user{'Add_user':
  ensure               => present,
  domainname           => '',
  path                 => 'OU=PLOP,DC=JRE,DC=LOCAL',
  accountname          => '',
  lastname             => '',                  
  firstname            => '',                   
  passwordneverexpires => ,
  passwordlength       => ,                       
  password             => '',        
  xmlpath              => 'C:\\users.xml',          
  writetoxmlflag       => true,                    
  emailaddress         => '',
}