#/usr/bin/env ruby
require 'openssl'

if ARGV.length != 2
  puts "Usage: #{$0} <algorithm> <password>"
  exit 1
end

cipher = OpenSSL::Cipher.new ARGV[0]
password = ARGV[1]

cipher.encrypt
iv = cipher.random_iv
salt = OpenSSL::Random.random_bytes(16)
key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, 20000, cipher.key_len, OpenSSL::Digest::SHA256.new)

puts "key=#{key.unpack('H*')[0].upcase}"
puts "iv =#{iv.unpack('H*')[0].upcase}"

