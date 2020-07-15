require "../ntlm"

module NTLM
  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2
  class Negotiate < BinData
    endian little

    string :protocol, value: ->{ "NTLMSSP" }
    enum_field UInt32, message_type : Type = Type::Negotiate

    enum_field UInt16, flags_low : FlagsLow = FlagsLow::CharactersUnicode | FlagsLow::RequestTarget | FlagsLow::NegotiateNTLM
    enum_field UInt16, flags_high : FlagsHigh = FlagsHigh::None

    group :domain_loc, onlyif: ->{ flags_low.negotiate_domain_supplied? || flags_low.negotiate_workstation_supplied? || flags_high.negotiate_version? } do
      uint16 :length
      uint16 :allocated
      uint32 :offset
    end

    group :workstation_loc, onlyif: ->{ flags_low.negotiate_domain_supplied? || flags_low.negotiate_workstation_supplied? || flags_high.negotiate_version? } do
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
    @workstation : String = ""

    def domain=(value : String)
      @domain = value.upcase
      self.flags_low = self.flags_low | FlagsLow::NegotiateDomainSupplied
      self.domain_loc.length = @domain.bytesize.to_u16
      self.domain_loc.allocated = @domain.bytesize.to_u16
      update_buffer
      value
    end

    def workstation=(value : String)
      @workstation = value.upcase
      self.flags_low = self.flags_low | FlagsLow::NegotiateWorkstationSupplied
      self.workstation_loc.length = @workstation.bytesize.to_u16
      self.workstation_loc.allocated = @workstation.bytesize.to_u16
      update_buffer
      value
    end

    def domain : String
      return @domain unless @domain.empty?
      if flags_low.negotiate_domain_supplied?
        return @domain if domain_loc.length == 0
        start_byte = domain_loc.offset - buffer_start
        end_byte = start_byte + domain_loc.length
        @domain = String.new(buffer[start_byte...end_byte])
      end
      @domain
    end

    def workstation : String
      return @workstation unless @workstation.empty?
      if flags_low.negotiate_workstation_supplied?
        return @domain if workstation_loc.length == 0
        start_byte = workstation_loc.offset - buffer_start
        end_byte = start_byte + workstation_loc.length
        @workstation = String.new(buffer[start_byte...end_byte])
      end
      @workstation
    end

    def buffer_start
      byte = 16
      byte += 8 if flags_low.negotiate_domain_supplied?
      byte += 8 if flags_low.negotiate_workstation_supplied?
      byte += 8 if flags_high.negotiate_version?
      byte
    end

    # NOTE:: currently destructive if OS version information was included
    def update_buffer
      # ensure the current values are known
      domain
      workstation

      start_byte = buffer_start
      buff = IO::Memory.new(@domain.bytesize + @workstation.bytesize)

      self.domain_loc.offset = start_byte.to_u32
      buff << @domain if flags_low.negotiate_domain_supplied?

      self.workstation_loc.offset = (start_byte + buff.pos).to_u32
      buff << @workstation if flags_low.negotiate_workstation_supplied?

      self.buffer = buff.to_slice
    end
  end
end
