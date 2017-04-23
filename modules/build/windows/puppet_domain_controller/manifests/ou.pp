class windows_ad::organisationalunit { 'PLOP':
  ensure       => present,
  path         => 'DC=JRE,DC=LOCAL',
  ouName       => 'PLOP',
}