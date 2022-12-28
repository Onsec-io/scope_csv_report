def resolve_dns(dns_name)
  result = []
  Resolv::DNS.open do |dns|
    dns.getresources(dns_name, Resolv::DNS::Resource::IN::A).map { |x| result << x.address.to_s }
  end

  Resolv::DNS.open do |dns|
    dns.getresources(dns_name, Resolv::DNS::Resource::IN::AAAA).map { |x| result << x.address.to_s }
  end

  result
end

def resolve_reverse_dns(ip_addr)
  ptr = '-'
  begin
    ptr = Resolv.getname(ip_addr)
  rescue Resolv::ResolvError
  rescue => e
    puts e.inspect
  end
  ptr
end
