require "../ntlm"

module NTLM
  # We only implement the NTLMv2 responses
  class ResponseV2 < BinData
    endian little

    bytes :response, length: ->{ 16 }
    remaining_bytes :client_challenge
  end

  # Client authenticates with the server using the challenge
  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce
  class Authenticate < BinData
    endian little

    string :protocol, value: ->{ "NTLMSSP" }
    enum_field UInt32, message_type : Type = Type::Authenticate

    group :lm_response_loc do
      uint16 :length
      uint16 :allocated
      uint32 :offset
    end

    group :nt_response_loc do
      uint16 :length
      uint16 :allocated
      uint32 :offset
    end

    group :domain_loc do
      uint16 :length
      uint16 :allocated
      uint32 :offset
    end

    group :user_loc do
      uint16 :length
      uint16 :allocated
      uint32 :offset
    end

    group :workstation_loc do
      uint16 :length
      uint16 :allocated
      uint32 :offset
    end

    group :session_key_loc do
      uint16 :length
      uint16 :allocated
      uint32 :offset
    end

    enum_field UInt16, flags_low : FlagsLow = FlagsLow::CharactersUnicode | FlagsLow::RequestTarget | FlagsLow::NegotiateNTLM
    enum_field UInt16, flags_high : FlagsHigh = FlagsHigh::None

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b1a6ceb2-f8ad-462b-b5af-f18527c48175
    group :version, onlyif: ->{ flags_high.negotiate_version? } do
      uint8 :major
      uint8 :minor
      uint16 :build
      uint16 :reserved1
      uint8 :reserved2
      uint8 :ntlm_revision, value: ->{ 15_u8 }
    end

    # The MIC is an HMAC_MD5 applied to the concatenation of the previous two NTLM massages using the session key
    # https://social.msdn.microsoft.com/Forums/en-US/74e16cb4-c534-407e-b9cd-ee70a796ee91/msnlmp-dummy-signature-and-mic-generation-ntlmsspnegotiatealwayssign
    bytes :mic, length: ->{ 16 }, onlyif: ->{
      flags_low.negotiate_always_sign? && flags_high.negotiate_key_exchange? &&
      !flags_low.negotiate_sign? && !flags_low.negotiate_seal?
    }

    remaining_bytes :buffer

    # String getters
    {% for name in [:domain, :user, :workstation] %}
      @{{name.id}} : String = ""

      def {{name.id}}
        return @{{name.id}} unless @{{name.id}}.empty?
        return @{{name.id}} if {{name.id}}_loc.length == 0
        start_byte = {{name.id}}_loc.offset - buffer_start
        end_byte = start_byte + {{name.id}}_loc.length
        @{{name.id}} = if flags_low.characters_unicode?
                         String.new(buffer[start_byte...end_byte], "UTF-16LE")
                       else
                         String.new(buffer[start_byte...end_byte])
                       end
        @{{name.id}}
      end
    {% end %}

    # ResponseV2 getters
    {% for name in [:lm_response, :nt_response] %}
      @{{name.id}} : ResponseV2? = nil

      def {{name.id}} : ResponseV2
        response = @{{name.id}}
        return response if response
        return ResponseV2.new if {{name.id}}_loc.length == 0
        start_byte = {{name.id}}_loc.offset - buffer_start
        end_byte = start_byte + {{name.id}}_loc.length

        buff = IO::Memory.new(buffer[start_byte...end_byte])
        @{{name.id}} = buff.read_bytes(ResponseV2)
      end
    {% end %}

    @session_key : Bytes? = nil

    # Session key getter
    def session_key : Bytes
      response = @session_key
      response = @session_key = Bytes.new(0) if session_key_loc.length == 0
      return response if response

      start_byte = session_key_loc.offset - buffer_start
      end_byte = start_byte + session_key_loc.length
      @session_key = buffer[start_byte...end_byte]
    end

    # configure the setters
    {% for name in [:domain, :user, :workstation, :lm_response, :nt_response, :session_key] %}
      def {{name.id}}=(value)
        @{{name.id}} = value
        update_buffer
        value
      end
    {% end %}

    def buffer_start
      byte = 64
      byte += 8 if flags_high.negotiate_version?
      byte += 16 if (flags_low.negotiate_always_sign? || flags_low.negotiate_sign?) && flags_high.negotiate_version?
      byte
    end

    {% begin %}
      def update_buffer
        # ensure the current values are known
        lm_response
        nt_response
        domain
        user
        workstation

        start_byte = buffer_start
        buff = IO::Memory.new

        {% for name in [:lm_response, :nt_response] %}
          start_offset = buff.pos
          buff.write_bytes({{name.id}}, IO::ByteFormat::LittleEndian)
          length = (buff.pos - start_offset).to_u16
          self.{{name.id}}_loc.offset = (start_byte + start_offset).to_u32
          self.{{name.id}}_loc.length = length
          self.{{name.id}}_loc.allocated = length
        {% end %}

        {% for name in [:domain, :user, :workstation] %}
          self.{{name.id}}_loc.offset = (start_byte + buff.pos).to_u32
          if flags_low.characters_unicode?
            unicode_string = @{{name.id}}.encode("UTF-16LE")
            self.{{name.id}}_loc.length = unicode_string.size.to_u16
            self.{{name.id}}_loc.allocated = unicode_string.size.to_u16
            buff.write unicode_string
          else
            self.{{name.id}}_loc.length = @{{name.id}}.bytesize.to_u16
            self.{{name.id}}_loc.allocated = @{{name.id}}.bytesize.to_u16
            buff << @{{name.id}}
          end
        {% end %}

        skey = session_key
        self.session_key_loc.offset = (start_byte + buff.pos).to_u32
        self.session_key_loc.length = skey.size.to_u16
        self.session_key_loc.allocated = skey.size.to_u16
        buff.write skey

        self.buffer = buff.to_slice
      end
    {% end %}
  end
end
