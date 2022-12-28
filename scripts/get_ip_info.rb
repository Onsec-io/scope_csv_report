def get_ip_info(ip_addr)
  result = { asn: '-', network: '-', provider: '-', country: '-', type: '-' }

  return result.merge({ type: 'bogon' }) if ip_addr.match(Resolv::IPv4::Regex) && is_bogon?(ip_addr)

  begin
    uri = URI.parse("https://api.ipregistry.co/#{ip_addr}?key=#{ENV['X_IPREGISTRY_KEY']}")
    headers = { 'User-agent': 'firefox 5.0' }
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.use_ssl = true
    request = Net::HTTP::Get.new(uri, headers)
    response = http.request(request)
    response_json = JSON.parse(response.body)

    return result.merge({ type: 'bogon' }) if response_json['code'] == 'RESERVED_IP_ADDRESS'

    result[:asn]      = response_json['connection']['asn']
    result[:network]  = response_json['connection']['route']
    result[:provider] = response_json['connection']['organization']
    result[:country]  = response_json['location']['country']['name']
    result[:type]     = response_json['security'].select { |_, v| v == true }.map { |k, _| k }.join("\n")
  rescue => e
    puts e.inspect
  end

  result
end
