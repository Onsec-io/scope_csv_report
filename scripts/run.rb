# frozen_string_literal: true

require 'resolv'
require 'net/http'
require 'uri'
require 'json'
require 'public_suffix'
require 'csv'
require 'yaml'
require 'find'
require 'set'
require 'ipaddr'

domains          = Set.new
real_bogons_list = []
$ip_cache        = {}
first_stage_data = []
whois_cache      = {}
output_data      = []

unless ENV.key?('X_IPREGISTRY_KEY') && ENV.key?('X_APILAYER_KEY')
  puts 'Please set the X_IPREGISTRY_KEY and X_APILAYER_KEY variables'
  exit 1
end

load '/opt/scripts/import_export.rb'
load '/opt/scripts/resolve_dns.rb'
load '/opt/scripts/get_whois_info.rb'
load '/opt/scripts/get_ip_info.rb'
load '/opt/scripts/is_bogon.rb'

bogons_ranges = [
  IPAddr.new('0.0.0.0/8').to_range,
  IPAddr.new('10.0.0.0/8').to_range,
  IPAddr.new('100.64.0.0/10').to_range,
  IPAddr.new('127.0.0.0/8').to_range,
  IPAddr.new('169.254.0.0/16').to_range,
  IPAddr.new('172.16.0.0/12').to_range,
  IPAddr.new('192.0.0.0/24').to_range,
  IPAddr.new('192.0.2.0/24').to_range,
  IPAddr.new('192.168.0.0/16').to_range,
  IPAddr.new('198.18.0.0/15').to_range,
  IPAddr.new('198.51.100.0/24').to_range,
  IPAddr.new('203.0.113.0/24').to_range,
  IPAddr.new('224.0.0.0/3').to_range
]

File.readlines('/opt/scripts/bogon_ip.txt').each do |line|
  next if line.strip.match(/(^#|^\s+|^$)/)

  real_bogons_list << line.strip
end

$bogons_int         = bogons_ranges.map { |range| ip_to_int(range.first.to_s)..ip_to_int(range.last.to_s) }
real_bogons_ranges  = real_bogons_list.map { |range| IPAddr.new(range).to_range }
$real_bogons_int    = real_bogons_ranges.map { |range| ip_to_int(range.first.to_s)..ip_to_int(range.last.to_s) }

src_file_paths = []
Find.find('/opt/input').each { |path| src_file_paths << path if path =~ /.txt$/ }

if src_file_paths.empty?
  puts 'No data in /opt/input'
  exit 1
end

src_file_paths.each do |file|
  File.readlines(file).each do |line|
    next unless line.strip.match(/^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/)

    domains.add(line.strip)
  end
end

puts "Total uniq domain names loaded: #{domains.count}"
puts "L2 domains: #{domains.map { |d| uri = URI.parse("http://#{d}"); PublicSuffix.parse(uri.host).domain }.uniq}"

# Stage 1. Getting IP addr data
domains.each do |domain|
  puts "Checking: #{domain}"

  uri = URI.parse("http://#{domain}")
  l2_domain = PublicSuffix.parse(uri.host).domain

  resolve_dns(domain).each do |ip_addr|
    if $ip_cache[ip_addr]
      ip_info = $ip_cache[ip_addr]['ip_info']
      ip_ptr  = $ip_cache[ip_addr]['ip_ptr']
    else
      ip_info = get_ip_info(ip_addr)
      ip_ptr  = resolve_reverse_dns(ip_addr)
      $ip_cache[ip_addr] = {}
      $ip_cache[ip_addr]['ip_info'] = ip_info
      $ip_cache[ip_addr]['ip_ptr'] = ip_ptr
    end

    first_stage_data << {
      l2_domain: l2_domain,
      domain: domain,
      ip_addr: ip_addr,
      ptr: ip_ptr,
      asn: ip_info[:asn],
      network: ip_info[:network],
      provider: ip_info[:provider],
      country: ip_info[:country],
      ip_type: ip_info[:type]
    }
  end
end

# Stage2. Getting info about L2 domains
uniq_l2_domains = first_stage_data.map { |x| x[:l2_domain] }.uniq

uniq_l2_domains.each do |l2_domain|
  next if whois_cache[l2_domain]

  whois_data = get_whois_info(l2_domain)
  whois_data[:name_servers] = (whois_data[:name_servers] + get_ns_records(l2_domain)).uniq
  whois_cache[l2_domain] = whois_data
end

# Stage3. Sorting data by L2 domain & IP addr
uniq_l2_domains.each do |l2_domain|
  selected_data_by_l2_domain = first_stage_data.select { |x| x[:l2_domain] == l2_domain }
  uniq_ip_addrs = selected_data_by_l2_domain.map { |x| x[:ip_addr] }.uniq

  uniq_ip_addrs.each do |ip_addr|
    selected_data_by_ip = selected_data_by_l2_domain.select { |x| x[:ip_addr] == ip_addr }
    domains = selected_data_by_ip.map { |x| x[:domain] }
    ip_data = selected_data_by_ip.first

    output_data << {
      l2_domain: l2_domain,
      asn: ip_data[:asn],
      ip_addr: ip_addr,
      ptr: ip_data[:ptr],
      network: ip_data[:network],
      provider: ip_data[:provider],
      country: ip_data[:country],
      ip_type: ip_data[:ip_type],
      registrar: whois_cache[l2_domain][:registrar],
      domain_org: whois_cache[l2_domain][:org],
      domain: domains.join("\n"),
      name_servers: whois_cache[l2_domain][:name_servers].join("\n")
    }
  end
end

if output_data.empty?
  puts 'No data was collected, check input domain names.'
  exit 1
end

save_debug_data(output_data, "/opt/output/csv_report_debug_#{Time.now.to_i}.yaml") if ENV.key?('DEBUG')
save_result_as_csv(output_data, '/opt/output/report.csv')
save_as_nmap_targets(output_data, '/opt/output')
save_ns_info(whois_cache, '/opt/output')

puts 'Done. Check output directory'
