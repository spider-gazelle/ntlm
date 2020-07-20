require "../ntlm"

module NTLM
  enum AvId
    EOL                 = 0
    NetBIOSComputerName
    NetBIOSDomainName
    DnsComputerName
    DnsDomainName
    DnsTreeName

    # A 32-bit value indicating server or client configuratio
    AvFlags
    AvTimestamp
    AvSingleHost
    AvTargetName
    AvChannelBindings
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
  class AVPair < BinData
    endian little

    enum_field UInt16, id : AvId = AvId::EOL
    uint16 :length

    bytes :bytes, length: ->{ length }

    def unicode_value
      String.new(bytes, "UTF-16LE")
    end

    def oem_value
      String.new(bytes)
    end
  end

  # Server responds to the negotiation request with a challenge
  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
  class Challenge < BinData
    endian little

    string :protocol, value: ->{ "NTLMSSP" }
    enum_field UInt32, message_type : Type = Type::Challenge

    group :domain_loc do
      uint16 :length
      uint16 :allocated
      uint32 :offset
    end

    enum_field UInt16, flags_low : FlagsLow = FlagsLow::CharactersUnicode | FlagsLow::RequestTarget | FlagsLow::NegotiateNTLM
    enum_field UInt16, flags_high : FlagsHigh = FlagsHigh::None

    uint64 :challenge
    uint64 :context, onlyif: ->{ has_context? }

    group :domain_info_loc, onlyif: ->{ flags_high.negotiate_domain_info? } do
      uint16 :length
      uint16 :allocated
      uint32 :offset
    end

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b1a6ceb2-f8ad-462b-b5af-f18527c48175
    group :version, onlyif: ->{ flags_high.negotiate_version? } do
      uint8 :major
      uint8 :minor
      uint16 :build
      uint16 :reserved1
      uint8 :reserved2
      uint8 :ntlm_revision, value: ->{ 15_u8 }
    end

    remaining_bytes :buffer

    @domain : String = ""
    @domain_info : Array(AVPair) = [] of AVPair

    def has_context?
      flags_high.negotiate_domain_info? || flags_low.negotiate_local_call?
    end

    def domain : String
      return @domain unless @domain.empty?
      return @domain if domain_loc.length == 0
      start_byte = domain_loc.offset - buffer_start
      end_byte = start_byte + domain_loc.length
      @domain = if flags_low.characters_unicode?
                  String.new(buffer[start_byte...end_byte], "UTF-16LE")
                else
                  String.new(buffer[start_byte...end_byte])
                end
      @domain
    end

    def domain=(value : String)
      @domain = value
      update_buffer
      value
    end

    def domain_info : Array(AVPair)
      return @domain_info unless @domain_info.empty?
      if flags_high.negotiate_domain_info?
        return @domain_info if domain_info_loc.length == 0
        start_byte = domain_info_loc.offset - buffer_start
        end_byte = start_byte + domain_info_loc.length

        info = IO::Memory.new(buffer[start_byte...end_byte])
        loop do
          av = info.read_bytes(AVPair)
          break if av.id.eol?
          @domain_info << av
        end
      end
      @domain_info
    end

    def buffer_start
      byte = 32
      byte += 8 if has_context?
      byte += 8 if flags_high.negotiate_domain_info?
      byte += 8 if flags_high.negotiate_version?
      byte
    end

    def update_buffer
      # ensure the current values are known
      domain
      domain_info

      start_byte = buffer_start
      buff = IO::Memory.new

      self.domain_loc.offset = start_byte.to_u32
      if flags_low.characters_unicode?
        target_n = @domain.encode("UTF-16LE")
        self.domain_loc.length = target_n.size.to_u16
        self.domain_loc.allocated = target_n.size.to_u16
        buff.write target_n
      else
        self.domain_loc.length = @domain.bytesize.to_u16
        self.domain_loc.allocated = @domain.bytesize.to_u16
        buff << @domain
      end

      # information block
      if flags_high.negotiate_domain_info?
        self.domain_info_loc.offset = (start_byte + buff.pos).to_u32
        @domain_info.each do |av|
          buff.write_bytes(av, IO::ByteFormat::LittleEndian)
        end
        # EOL
        buff.write_bytes(AVPair.new, IO::ByteFormat::LittleEndian)
        length = ((start_byte + buff.pos).to_u32 - self.domain_info_loc.offset).to_u16
        self.domain_info_loc.length = length
        self.domain_info_loc.allocated = length
      end

      self.buffer = buff.to_slice
    end
  end
end
