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

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
  class Challenge < BinData
    endian little

    string :protocol, value: ->{ "NTLMSSP" }
    enum_field UInt32, message_type : Type = Type::Challenge

    group :target_name_loc do
      uint16 :length
      uint16 :allocated
      uint32 :offset
    end

    enum_field UInt16, flags_low : FlagsLow = FlagsLow::CharactersUnicode | FlagsLow::RequestTarget | FlagsLow::NegotiateNTLM
    enum_field UInt16, flags_high : FlagsHigh = FlagsHigh::None

    uint64 :challenge
    uint64 :context, onlyif: ->{ has_context? }

    group :target_info_loc, onlyif: ->{ flags_high.negotiate_target_info? } do
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

    @target_name : String = ""
    @target_info : Array(AVPair) = [] of AVPair

    def has_context?
      flags_high.negotiate_target_info? || flags_low.negotiate_local_call?
    end

    def target_name : String
      return @target_name unless @target_name.empty?
      return @target_name if target_name_loc.length == 0
      start_byte = target_name_loc.offset - buffer_start
      end_byte = start_byte + target_name_loc.length
      @target_name = if flags_low.characters_unicode?
                       String.new(buffer[start_byte...end_byte], "UTF-16LE")
                     else
                       String.new(buffer[start_byte...end_byte])
                     end
      @target_name
    end

    def target_name=(value : String)
      @target_name = value
      update_buffer
      value
    end

    def target_info : Array(AVPair)
      return @target_info unless @target_info.empty?
      if flags_high.negotiate_target_info?
        return @target_info if target_info_loc.length == 0
        start_byte = target_info_loc.offset - buffer_start
        end_byte = start_byte + target_info_loc.length

        info = IO::Memory.new(buffer[start_byte...end_byte])
        loop do
          av = info.read_bytes(AVPair)
          break if av.id.eol?
          @target_info << av
        end
      end
      @target_info
    end

    def buffer_start
      byte = 32
      byte += 8 if has_context?
      byte += 8 if flags_high.negotiate_target_info?
      byte += 8 if flags_high.negotiate_version?
      byte
    end

    def update_buffer
      # ensure the current values are known
      target_name
      target_info

      start_byte = buffer_start
      buff = IO::Memory.new

      self.target_name_loc.offset = start_byte.to_u32
      if flags_low.characters_unicode?
        target_n = @target_name.encode("UTF-16LE")
        self.target_name_loc.length = target_n.size.to_u16
        self.target_name_loc.allocated = target_n.size.to_u16
        buff.write target_n
      else
        self.target_name_loc.length = @target_name.bytesize.to_u16
        self.target_name_loc.allocated = @target_name.bytesize.to_u16
        buff << @target_name
      end

      # information block
      if flags_high.negotiate_target_info?
        self.target_info_loc.offset = (start_byte + buff.pos).to_u32
        @target_info.each do |av|
          buff.write_bytes(av, IO::ByteFormat::LittleEndian)
        end
        # EOL
        buff.write_bytes(AVPair.new, IO::ByteFormat::LittleEndian)
        length = ((start_byte + buff.pos).to_u32 - self.target_info_loc.offset).to_u16
        self.target_info_loc.length = length
        self.target_info_loc.allocated = length
      end

      self.buffer = buff.to_slice
    end
  end
end
