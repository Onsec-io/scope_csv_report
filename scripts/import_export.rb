# frozen_string_literal: true

def save_result_as_csv(data, file_path)
  csv_data = CSV.generate(col_sep: "\t") do |csv|
    csv << data.first.keys.map(&:upcase)
    data.each { |element| csv << element.values }
  end

  File.open(file_path, 'w') { |file| file.write(csv_data) }
end

def save_as_nmap_targets(data, dst_dir)
  ipv4_addr = data.reject { |x| x[:ip_type] == 'bogon' }.map { |x| x[:ip_addr] }.select { |x| x.match(Resolv::IPv4::Regex) }.uniq
  ipv6_addr = data.reject { |x| x[:ip_type] == 'bogon' }.map { |x| x[:ip_addr] }.select { |x| x.match(Resolv::IPv6::Regex) }.uniq
  networks_v4 = data.reject { |x| x[:ip_type] == 'bogon' or x[:network].nil? }.map { |x| x[:network] }.select { |x| x.match(/[.]/) }.uniq
  File.open("#{dst_dir}/nmap_ipv4_targets.txt", 'w') { |f| f.write(ipv4_addr.join("\n")) } unless ipv4_addr.empty?
  File.open("#{dst_dir}/nmap_ipv6_targets.txt", 'w') { |f| f.write(ipv6_addr.join("\n")) } unless ipv6_addr.empty?
  File.open("#{dst_dir}/nmap_networks_v4.txt", 'w') { |f| f.write(networks_v4.join("\n")) } unless networks_v4.empty?
end

def save_ns_info(whois_cache, dst_dir)
  domain_ns_info = whois_cache.map { |k, v| "#{k},#{v[:name_servers].join(',')}" }
  File.open("#{dst_dir}/domain_ns_info.txt", 'w') { |f| f.write(domain_ns_info.join("\n")) } unless domain_ns_info.empty?
end

def save_debug_data(data, file_path)
  File.open(file_path, 'w') do |file|
    file.write data.to_yaml
  end
end

def load_debug_data(file_path)
  YAML.load_file(file_path)
end
