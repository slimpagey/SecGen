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
$bann_space = "                  "
dcs = Hash.new 
dcs = Hash["dc1" => "Windows 2000", "dc2" => "Windows 2003", "dc3" => "Windows 2008", "dc4" => "Windows 2012", "dc5" => "Windows 2016"]
hosts = Hash.new 
hosts = Hash["h1" => "Windows 2000", "h2" => "Windows XP", "h3" => "Windows 7", "h4" => "Windows 8", "h5" => "Windows 10"] 
$r_hosts = Array.new() # Needs to be global, but why?
$r_dc = Array.new() # As above
$p_dns_dc = Hash.new
$p_dns_dc = Hash["dnsName" => "", "ensure" => "present,", "serverName" => "", "FQDN" => "", "IPAddr" => "", "Record" => "A", 
	"TTL" => 12001]
# The below should be read from the scenario dir later on once that is populated. 
$cur_scenarios = Hash.new
$cur_scenarios = Hash["one" => "Weak Domain Admin Credentials", "two" => "LLMNR/NetBios-NS Spoofing"]
#$compatable = Hash.new
#$compatable =

# Banner / Argv
def bann
	Print.std "Windows SecGen
	#{$0} [options] <count>

	Options:
	-----------------------------------------------------
	-d, --domain
		Build a Randomised Domain
	(If no options are selected it will default to this)
	
	-c [DC Type], --controller [DC type]
		Specify a specific Domain Controller
			DC Types: 
				2000 Server [2000]
				2003 Server [2003]
				2008 Server [2008]
				2012 Server [2012]
				2016 Server [2016]
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
			[E.g: -m 2000 3 XP 1 <...>]
	
	-s [Scenario XML], --scenario [Scenario XML]
		The current Windows Domain Scenario's are:" 
	$cur_scenarios.each do |key, value|
		Print.std $bann_space + "#{value}".to_s.tr('[]', '').tr('""', '').tr('{}', '')+"," # Trimming shit from the hash table. 
	end
	Print.std"
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
	check_compat($r_dc, $r_hosts, true)
end

# Checks if the DC's and hosts are compatable
def check_compat(dc, hosts, is_rand)
	Print.std "Checking Host/DC Compatability"
	dc.each do | dcs |
		dcs.tr('[]', '').tr('""', '')
		case dcs
			when "Windows 2000"
				# This can be called from somewhere else later, I guess...
				$uncomp = 0
				comp = ["Windows 2000", "Windows XP"] # TODO
				hosts.each do | host |
					if comp.include?(host, comp)
						Print.std "Host #{host} is compatable with #{dcs}"
						#dc_2008(dcs)
						#join_domain(host)	
					else
						Print.err "Host #{host} Not Compatable!"
						#hosts.delete(host)
						$uncomp = $uncomp + 1 
					end
				end
					# Checks if randomly created domain, bit unfair to kick
					# out hosts if so...
				if is_rand
					honeypot(true, comp)
					until $uncomp == 0 do
						#Print.err $uncomp
						Print.info "Selecting new compatable host..."
						new_host = comp.sample
						Print.info "New host => #{new_host}"
						# Deletes k,v pair if uncompat host is in hash
						# my concern is that I should count how many are deleted
						# so I can add the same number of compatable hosts back
						#hosts.delete(host)
						# Adding the host back
						hosts = {:hx => "Windows XP"}
						$uncomp = $uncomp - 1 
					end
				end
			when "Windows 2003"
				# This can be called from somewhere else later, I guess...
				$uncomp = 0
				comp = ["Windows 2000", "Windows XP", "Windows 7"] # TODO
				hosts.each do | host |
					if comp.include?(host)
						Print.std "Host #{host} is compatable with #{dcs}"
						#dc_2008(dcs)
						#join_domain(host)	
					else
						Print.err "Host #{host} Not Compatable!"
						#hosts.delete(host)
						$uncomp = $uncomp + 1 
					end
				end
					# Checks if randomly created domain, bit unfair to kick
					# out hosts if so...
				if is_rand
					honeypot(true, comp)
					until $uncomp == 0 do
						#Print.err $uncomp
						Print.info "Selecting new compatable host..."
						new_host = comp.sample
						Print.info "New host => #{new_host}"
						# Deletes k,v pair if uncompat host is in hash
						# my concern is that I should count how many are deleted
						# so I can add the same number of compatable hosts back
						#hosts.delete(host)
						# Adding the host back
						hosts = {:hx => "Windows XP"}
						$uncomp = $uncomp - 1 
					end
				end
			when "Windows 2008"
				# This can be called from somewhere else later, I guess...
				$uncomp = 0
				comp = ["Windows 2000", "Windows XP", "Windows 7", "Windows 8", "Windows 10"] # TODO
				hosts.each do | host |
					if comp.include?(host)
						Print.std "Host #{host} is compatable with #{dcs}"
						#dc_2008(dcs)
						#join_domain(host)	
					else
						Print.err "Host #{host} Not Compatable!"
						#hosts.delete(host)
						$uncomp = $uncomp + 1 
					end
				end
					# Checks if randomly created domain, bit unfair to kick
					# out hosts if so...
				if is_rand
					honeypot(true, comp)
					until $uncomp == 0 do
						#Print.err $uncomp
						Print.info "Selecting new compatable host..."
						new_host = comp.sample
						Print.info "New host => #{new_host}"
						# Deletes k,v pair if uncompat host is in hash
						# my concern is that I should count how many are deleted
						# so I can add the same number of compatable hosts back
						#hosts.delete(host)
						# Adding the host back
						hosts = {:hx => "Windows XP"}
						$uncomp = $uncomp - 1 
					end
				end
			when "Windows 2012"
				# This can be called from somewhere else later, I guess...
				$uncomp = 0
				comp = ["Windows XP", "Windows 7", "Windows 8", "Windows 10"] # TODO
				hosts.each do | host |
					if comp.include?(host)
						Print.std "Host #{host} is compatable with #{dcs}"
						#dc_2008(dcs)
						#join_domain(host)	
					else
						Print.err "Host #{host} Not Compatable!"
						#hosts.delete(host)
						$uncomp = $uncomp + 1 
					end
				end
					# Checks if randomly created domain, bit unfair to kick
					# out hosts if so...
				if is_rand
					honeypot(true, comp)
					until $uncomp == 0 do
						#Print.err $uncomp
						Print.info "Selecting new compatable host..."
						new_host = comp.sample
						Print.info "New host => #{new_host}"
						# Deletes k,v pair if uncompat host is in hash
						# my concern is that I should count how many are deleted
						# so I can add the same number of compatable hosts back
						#hosts.delete(host)
						# Adding the host back
						hosts = {:hx => "Windows XP"}
						$uncomp = $uncomp - 1 
					end
				end
				#dc_2012(dcs)
			when "Windows 2016"
				# This can be called from somewhere else later, I guess...
				$uncomp = 0
				comp = ["Windows 7", "Windows 8", "Windows 10"] # TODO
				hosts.each do | host |
					if comp.include?(host)
						Print.std "Host #{host} is compatable with #{dcs}"
						#dc_2016(dcs)
						#join_domain(host)	
					else
						Print.err "Host #{host} Not Compatable!"
						#hosts.delete(host)
						$uncomp = $uncomp + 1 
					end
				end
					# Checks if randomly created domain, bit unfair to kick
					# out hosts if so...
				if is_rand
					honeypot(true, comp)
					until $uncomp == 0 do
						#Print.err $uncomp
						Print.info "Selecting new compatable host..."
						new_host = comp.sample
						Print.info "New host => #{new_host}"
						# Deletes k,v pair if uncompat host is in hash
						# my concern is that I should count how many are deleted
						# so I can add the same number of compatable hosts back
						#hosts.delete(host)
						# Adding the host back
						hosts = {:hx => "Windows XP"}
						$uncomp = $uncomp - 1 
					end
				end
			end
		end
	#Print.err "NOT BUILT YET!"
	#build_dc_pupp(dc)
	#build_host(hosts)
	# build arr of compat dcs with hosts like; 
	# arr.2000DC[XP, 2000, FOO]
	# if compat == true, build dc
end

# Builds the Puppet Config for the DC
# This should redundant or called after dc build. 
# Yeah - actually, should be called later with dc specific vars added 
# as func params, ja feel? course ja feel. 
def build_dc_pupp(dc)
#	dc.each do | dcs |
#		dcs.tr('[]', '').tr('""', '')
		# Strips Square brackets and speech marks, why there are there I'll never know...
		#Print.info "Building DC => #{dcs}"#.tr('[]', '').tr('""', '')
		# Check if server name specified... 
		#s_name = "ctf-dc01" # Take this from the user, or a list if random
		# Check that the s_name is not a duplicate
		# if s_name in arr then select new s_name or err
		#Print.info "Server name set => #{s_name}"
		## Check if DNS Zone specified...
		##d_zone = "foo.local" # take this from the user, or list if random
	##	#Print.info "DNS Zone set => #{d_zone}"
	#	case dcs
	#		when "Windows 2000"
	#			dc_2000(dcs)
	#		when "Windows 2003"
	#			dc_2003(dcs)
##			when "Windows 2008"
#				dc_2008(dcs)
#			when "Windows 2012"
#				dc_2012(dcs)
#			when "Windows 2016"
#				dc_2016(dcs)
#		end
#	end
end

# Builds the host(s) machines Puppet Configs
def build_host(host)
	n_c = 001 
	name = "ctf-h"
	# this is taking the entire hash table for host, and not iterating through each key, value ...!
	host.each do
		Print.info "Adding host => #{host}".tr('[]', '').tr('""', '')
		# check if hostname specified, use generator if not. 
		h_name = name.to_s+n_c.to_s
		n_c = n_c + 1
		Print.info "Host name set to => #{h_name}"
	end
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

# Build config for Windows 2000 Domain Controllers
def dc_2000(host)
	dc_name = "ctf-dc01"
	dc_domain = "example.com"
	dc_usr = Hash.new
	dc_usr = ["Domain Admin" => "Admin_da", "LA" => "Local_admin", "User" => "user001"]
	Print.info "Building Domain Controller => #{host}"
	Print.info "Reading DC Options....."
	dc_usr.each do | role |
		Print.info "Adding User => #{}"
	end
end

# Build config for Windows 2003 Domain Controllers
def dc_2003(host)
	Print.info "Building Domain Controller => #{host}"
end

# Build config for Windows 2008 Domain Controllers
def dc_2008(host)
	Print.info "Building Domain Controller => #{host}"
end

# Build config for Windows 2012 Domain Controllers
def dc_2012(host)
	Print.info "Building Domain Controller => #{host}"
end

# Build config for Windows 2016 Domain Controllers
def dc_2016(host)
	Print.info "Building Domain Controller => #{host}"
end

# Reads config to see if honeypot is specified. Adds if true 
# If random domain will randomly decide if honeypot should be added
# will add a command option to -d to specify that honeypot should NOT be added
def honeypot(is_rand, comp)
	# random domain 
	# if is_rand && allow_honeypot
	# then random domain with allow honeypots allowed
	if is_rand
		# Select random between true and false
		rand_honeypot = [true, false].sample
		# Add honeypot as true
		if rand_honeypot
			Print.info "Adding Honeypot!"
			new_host = comp.sample
			Print.info "Honeypot added => #{new_host}"
			# configure honey pot
		end
	end
end

# Cmd Argv
opts = GetoptLong.new(
	[ '-h', '--help', GetoptLong::NO_ARGUMENT ],
	[ '-d', '--domain', GetoptLong::NO_ARGUMENT ],
	[ '-m', '--machine', GetoptLong::REQUIRED_ARGUMENT ],
	[ '-c', '--controller', GetoptLong::REQUIRED_ARGUMENT ],
	[ '-s', '--scenario', GetoptLong::REQUIRED_ARGUMENT ],
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
				Print.std "Selecting Random Domain Set Up"
				rand_domain(dcs, hosts)
			when '-m'
				Print.info 'MACHINE'
			when '-c'
				Print.info 'CONTROLLER'		
		end
	end
end