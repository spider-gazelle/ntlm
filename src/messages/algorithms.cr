require "../ntlm"
require "openssl"
require "openssl/hmac"
require "digest/md5"

module NTLM
  extend self

  def create_NT_hashed_password_v2(password, user, domain)
    key = create_NT_hashed_password_v1(password)
    OpenSSL::HMAC.digest(:md5, key, "#{user.upcase}#{domain}".encode("UTF-16LE"))
  end

  def ntlm2sr_challenge_response(password_hash : Bytes, server_challenge : Bytes, client_challenge : Bytes)
    buff = IO::Memory.new(Bytes.new(24))
    buff.write(client_challenge)
    lm_response = buff.to_slice

    buff = IO::Memory.new(Bytes.new(16))
    buff.write(server_challenge)
    buff.write(client_challenge)
    sess = Digest::MD5.digest(buff)

    nt_response = challenge_response(password_hash, sess)
    {nt_response, lm_response}
  end

  def challenge_response(password_hash : Bytes, challenge : Bytes)
    # ensure hash is 21 bytes
    buff = IO::Memory.new(Bytes.new(21))
    buff.write(password_hash)
    password_hash = buff.to_slice
    challenge = challenge[0...8]

    buff = IO::Memory.new

    des = OpenSSL::Cipher.new("DES")
    des.encrypt
    des.key = generate_des_key(password_hash[0...7])
    buff.write(des.update(challenge))

    des.reset
    des.encrypt
    des.key = generate_des_key(password_hash[7...14])
    buff.write(des.update(challenge))

    des.reset
    des.encrypt
    des.key = generate_des_key(password_hash[14...21])
    buff.write(des.update(challenge))

    buff.to_slice
  end

  def create_sessionbasekey(password)
    md4 = OpenSSL::Digest.new("MD4")
    md4.update(create_NT_hashed_password_v1(password))
    md4.final
  end

  def create_NT_hashed_password_v1(password)
    md4 = OpenSSL::Digest.new("MD4")
    md4.update(password.encode("UTF-16LE"))
    md4.final
  end

  def create_LM_hashed_password_v1(password)
    # fix the password length to 14 bytes
    password = password.upcase
    padding = 14 - password.size
    password = "#{password}#{"\0" * padding}" if padding > 0
    lm_pw = password[0...14].to_slice
    magic_str = "KGS!@#$%"

    encrypted_data = IO::Memory.new

    des = OpenSSL::Cipher.new("DES")
    des.encrypt
    des.key = generate_des_key(lm_pw[0...7])
    encrypted_data.write(des.update(magic_str))

    des.reset
    des.encrypt
    des.key = generate_des_key(lm_pw[7...14])
    encrypted_data.write(des.update(magic_str))

    encrypted_data.to_slice
  end

  def generate_des_key(pass : Bytes)
    key = Bytes.new(8)
    key[0] = pass[0]
    key[1] = (pass[0] << 7) | (pass[1] >> 1)
    key[2] = (pass[1] << 6) | (pass[2] >> 2)
    key[3] = (pass[2] << 5) | (pass[3] >> 3)
    key[4] = (pass[3] << 4) | (pass[4] >> 4)
    key[5] = (pass[4] << 3) | (pass[5] >> 5)
    key[6] = (pass[5] << 2) | (pass[6] >> 6)
    key[7] = pass[6] << 1

    # set key odd parity
    bit = 0_u8
    key.each_with_index do |byte, i|
      (0..7).each do |k|
        bit = 0_u8
        t = byte >> k
        bit = (t ^ bit) & 0x1_u8
      end
      key[i] = (byte & 0xFE) | bit
    end

    key
  end
end
