# Windows Domain Generation Tool 
# Rob Page - Leeds Beckett University (C3385644)
# 
# This is a testing version of SecGen's Windows Domain CTF
# generator. 
#
# rob@robertpage.uk / r.page4446@student.leedsbeckett.ac.uk

# This script builds a Windows Domain, without any config options
# Currently it will 
# > Build a Windows 2003 DC
# > Add a Windows XP machine to AD

# https://github.com/joefitzgerald/packer-windows

require 'getoptlong'

require_relative 'lib/helpers/print.rb' # SecGens Pretty Print

# Global Vars 
dcs = Hash.new 
dcs = Hash["dc1" => "Windows 2000", "dc2" => "Windows 2003",
 "dc3" => "Windows 2008", "dc4" => "Windows 2012"]
hosts = Hash.new 
hosts = Hash["h1" => "Windows 2000", "h2" => "Windows XP",
 "h3" => "Windows 7", "h4" => "Windows 8", "h5" => "Windows 10"] 
$r_hosts = Array.new() # Needs to be global, but why?
$r_dc = Array.new() # As above
$p_dns_dc = Hash.new
$p_dns_dc = Hash["dnsName" => "", "ensure" => "present,", 
	"serverName" => "", "FQDN" => "", "IPAddr" => "", "Record" => "A",
"TTL" => 12001]

# Banner / Argv
def bann
	Print.std "Windows SecGen
	#{$0} [options] <count>

	Options:
	-----------------------------------------------------
	-d, --domain
		Build a randomised Domain
	(If no options are selected it will default to this)
	-c [DC Type], --controller [DC type]
		Specify a specific Domain Controller
			DC Types: 
				2000 Server [2000]
				2003 Server [2003]
				2008 Server [2008]
				2012 Server [2012]
	(You can Specify more than one DC, by -c [DC1] [DC2])

	-m [Host type], --machine [Host type]
		Specify Domain joined hosts
			Host Types: 
				2000
				XP 
				W7
				W8
				W10
	(You can specify multiple hosts as such
		-m [Host] <count> [host] <count>)

	-h, --help 
		Displays this help text"
end

# Builds a random domain
def rand_domain(dc, host)
	i = 0
	dc_r = dc.keys.sample
	dc_ra = dc[dc_r]
	$r_dc << dc_ra
	Print.info "Selected Domain Controller => #{dc_ra}"
	host.each_key do 	
  	i = i + 1 
  end
  i = i.to_i
  host_c = rand(0..i)
  if host_c == 0
  	host_c = 1
  end
  until host_c == 0 do
  	host_r = host.keys.sample
  	host_ra = host[host_r]
  	Print.info "Selected Host => #{host_ra}"
  	$r_hosts << host_ra 
  	host_c = host_c - 1 
	end
	check_compat($r_dc, $r_hosts)
end

# Checks if the DC's and hosts are compatable
def check_compat(dc, hosts)
	Print.std "Checking Host/DC Compatability"
	Print.err "NOT BUILT YET!"
	build_dc_pupp(dc)
	# if compat == true, build dc
end

# Builds the Puppet Config for the DC
def build_dc_pupp(dc)
	dc.each do
		# Strips Square brackets and speech marks, why there are there I'll never know...
		Print.info "Building DC => #{dc}".tr('[]', '').tr('""', '')
		# Check if server name specified... 
		s_name = "ctf-dc01" # Take this from the user, or a list if random
		# Check that the s_name is not a duplicate
		# if s_name in arr then select new s_name or err
		Print.info "Server name set => #{s_name}"
		# Check if DNS Zone specified...
		d_zone = "foo.local" # take this from the user, or list if random
		Print.info "DNS Zone set => #{d_zone}"
	end
end

# Builds the host(s) machines Puppet Configs
def build_host()

end

# Holds DNS information, for hosts and multiple DC's
def dns_zone(zone)

end

# Adding Roles the Domain - Puppet Config
def add_roles()

end

# Build the Domain - Puppet Config
def build_domain()

end

# Checks if Vulns specified are compatable and adds them 
def check_vulns()

end

# Cmd Argv
opts = GetoptLong.new(
	[ '-h', '--help', GetoptLong::NO_ARGUMENT ],
	[ '-d', '--domain', GetoptLong::NO_ARGUMENT ],
	[ '-m', '--machine', GetoptLong::REQUIRED_ARGUMENT ],
	[ '-c', '--controller', GetoptLong::REQUIRED_ARGUMENT ],
)

# Argv process
if ARGV.length < 1 
	Print.err 'No option selected, doing random'
	puts 'Is that OK? (Y/N)'
	no_opt = gets.downcase!
	if no_opt == 'n'
		Print.info 'Select an option'
		puts
		bann 
		exit
	else
		rand_domain(dcs, hosts)
	end
else
	opts.each do |opt, arg|
		case opt
			when '-h'
				bann
				exit
			when '-d'
				Print.info "Selecting Random Domain Set Up"
				rand_domain(dcs, hosts)
			when '-m'
				Print.info 'MACHINE'
			when '-c'
				Print.info 'CONTROLLER'		
		end
	end
end