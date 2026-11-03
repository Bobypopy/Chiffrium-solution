require 'openssl'
require 'digest'

def fingerprint(data)
  Digest::MD5.hexdigest(data)
end

def legacy
  OpenSSL::Cipher.new('des-cbc')
end
