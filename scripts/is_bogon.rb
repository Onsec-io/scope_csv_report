# encoding: UTF-8

def is_bogon?(ip_addr)
  return true if bogon_check(ip_addr, $bogons_int)
  return true if bogon_check(ip_addr, $real_bogons_int)
  false
end


# The code below was taken from https://gist.github.com/anapsix/8babc0e4a943c8485ca1
# turning IP to integer for simple comparison
def ip_to_int(ip)
  ipi = 0
  ip = ip.to_s if ip.class == IPAddr
  ip.split(".").reverse.each_with_index { |v, i| ipi += 255**(i)*v.to_i }
  ipi
end


# check a suspect ip agains a given range
def within_range?(suspect, ip)
  # convert suspect to String
  suspect = suspect.to_s if suspect.class == IPAddr

  if ip.class != Range
    # convert ip to integer range if it is an IPAddr and not Range yet
    range_int = ip_to_int(ip.to_range.first.to_s)..ip_to_int(ip.to_range.last.to_s) if ip.class == IPAddr
  elsif ip.class == Range
    # confirm that ip is a Range of integers
    range_int = ip if ip.first.class == Integer
    # convert ip to Range of integers if it's a Range of IPAddr objects
    range_int = ip_to_int(ip.first.to_s)..ip_to_int(ip.last.to_s) if ip.first.class == IPAddr
  end

  # compare suspect with first and last integer values of integer Range
  if range_int.first <= ip_to_int(suspect) && range_int.last >= ip_to_int(suspect)
    return true # if suspect is part of ip range
  else
    return false # if suspect if outside of ip range
  end
end

# check an ip against given list
def bogon_check(ip, bogons_int_array)
  bogons_int_array.each { |range_int| return true if within_range?(ip, range_int) }
  false
end
