# frozen_string_literal: true

def get_whois_info(l2_domain)
  result = { creation_date: '-', registrar: '-', org: '-', name_servers: [] }

  begin
    uri = URI.parse("https://api.apilayer.com/whois/query?domain=#{l2_domain}")
    headers = { 'apikey': ENV['X_APILAYER_KEY'] }
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.use_ssl = true
    request = Net::HTTP::Get.new(uri, headers)
    response = http.request(request)
    response_json = JSON.parse(response.body)

    result[:creation_date] = response_json['result']['creation_date'] if response_json['result']['creation_date']
    result[:registrar]     = response_json['result']['registrar']     if response_json['result']['registrar']
    result[:org]           = response_json['result']['org']           if response_json['result']['org']
    result[:name_servers]  = response_json['result']['name_servers'].map { |ns| ns.downcase.gsub(/[.]$/, '') }
  rescue => e
    puts e.inspect
  end

  result
end
