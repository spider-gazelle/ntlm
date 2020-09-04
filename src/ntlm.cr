require "bindata"
require "base64"

module NTLM
  class Error < Exception; end

  enum Type
    Negotiate    = 1
    Challenge
    Authenticate
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832
  # http://davenport.sourceforge.net/ntlm.html#theNtlmMessageHeaderLayout
  @[Flags]
  enum FlagsLow
    # character set encoding MUST be Unicode
    CharactersUnicode
    # character set encoding MUST be OEM
    CharactersOEM
    # a TargetName field of the CHALLENGE MUST be supplied
    RequestTarget
    Reserved1
    # requests session key negotiation for message signatures
    NegotiateSign
    # requests session key negotiation for message confidentiality
    NegotiateSeal
    # requests connectionless authentication
    NegotiateDatagram
    # requests LAN Manager session key computation
    NegotiateLanManagerKey
    NegotiateNetware
    # requests usage of the NTLM v1
    NegotiateNTLM
    Reserved3
    # Sent by the client in the Type 3 message to indicate that an anonymous context has been established
    NegotiateAnonymous
    # the domain name is provided
    NegotiateDomainSupplied
    # indicates whether the Workstation field is present
    NegotiateWorkstationSupplied
    # indicate that the server and client are on the same machine
    NegotiateLocalCall
    # a session key is always generated, regardless of the NegotiateSignature value
    NegotiateAlwaysSign
  end

  @[Flags]
  enum FlagsHigh
    # TargetName MUST be a domain name
    TargetTypeDomain
    # TargetName MUST be a server name
    TargetTypeServer
    # indicate that the target authentication realm is a share
    TargetTypeShare
    # requests usage of the NTLM v2 (session security)
    NegotiateSessionSecurity
    # requests an identify level token
    NegotiateIdentity
    RequestAcceptResponse
    # requests the usage of the LMOWF
    RequestNonNTSessionKey
    # indicates that the TargetInfo fields in the CHALLENGE are populated
    NegotiateDomainInfo
    Reserved1
    # requests the protocol version number
    NegotiateVersion
    Reserved2
    Reserved3
    Reserved4
    # requests 128-bit session key negotiation
    Negotiate128Bit
    # requests an explicit key exchange
    NegotiateKeyExchange
    # requests 56-bit encryption
    Negotiate56Bit
  end

  class Header < BinData
    endian little

    string :protocol, value: ->{ "NTLMSSP" }
    enum_field UInt32, message_type : Type = Type::Negotiate
  end

  def self.negotiate(domain : String? = nil)
    msg1 = NTLM::Negotiate.new
    msg1.domain = domain.not_nil! if domain
    msg1
  end

  def self.negotiate_http(domain : String? = nil)
    "NTLM #{Base64.strict_encode negotiate(domain)}"
  end

  def self.authenticate(challenge : String, username : String, password : String)
    challenge = challenge.starts_with?("NTLM ") ? challenge[5..-1] : challenge
    data = IO::Memory.new Base64.decode(challenge)
    challenge = data.read_bytes(NTLM::Challenge)

    domain = challenge.domain
    server_challenge = challenge.challenge
    client_challenge = Random.new.random_bytes(8)

    nt_response, lm_response = NTLM.ntlm2sr_challenge_response(NTLM.create_NT_hashed_password_v1(password), server_challenge, client_challenge)

    auth = NTLM::Authenticate.new
    auth.domain = domain
    auth.user = username
    auth.lm_response = lm_response
    auth.nt_response = nt_response
    auth
  end

  def self.authenticate_http(challenge : String, username : String, password : String)
    "NTLM #{Base64.strict_encode authenticate(challenge, username, password)}"
  end
end

require "./messages/*"
