require "./spec_helper"

describe NTLM do
  it "should parse a minimal Authenticate message" do
    hexstring = "4e544c4d5353500003000000180018006a00000018001800" +
                "820000000c000c0040000000080008004c00000016001600" +
                "54000000000000009a0000000102000044004f004d004100" +
                "49004e00750073006500720057004f0052004b0053005400" +
                "4100540049004f004e00c337cd5cbd44fc9782a667af6d42" +
                "7c6de67c20c2d3e77c5625a98c1c31e81847466b29b2df46" +
                "80f39958fb8c213a9cc6"

    data = IO::Memory.new hexstring.hexbytes
    message = data.read_bytes(NTLM::Authenticate)
    message.protocol.should eq("NTLMSSP")
    message.message_type.should eq(NTLM::Type::Authenticate)

    message.flags_low.characters_unicode?.should eq(true)
    message.flags_low.negotiate_ntlm?.should eq(true)

    message.domain.should eq("DOMAIN")
    message.user.should eq("user")
    message.workstation.should eq("WORKSTATION")

    message.to_slice.hexstring.should eq(hexstring)
  end

  it "should update an Authenticate message" do
    hexstring = "4e544c4d5353500003000000180018006a00000018001800" +
                "820000000c000c0040000000080008004c00000016001600" +
                "54000000000000009a0000000102000044004f004d004100" +
                "49004e00750073006500720057004f0052004b0053005400" +
                "4100540049004f004e00c337cd5cbd44fc9782a667af6d42" +
                "7c6de67c20c2d3e77c5625a98c1c31e81847466b29b2df46" +
                "80f39958fb8c213a9cc6"

    data = IO::Memory.new hexstring.hexbytes
    message = data.read_bytes(NTLM::Authenticate)

    message.domain = "DOMAIN"
    hexnew = message.to_slice.hexstring

    data = IO::Memory.new hexnew.hexbytes
    message = data.read_bytes(NTLM::Authenticate)

    message.protocol.should eq("NTLMSSP")
    message.message_type.should eq(NTLM::Type::Authenticate)

    message.flags_low.characters_unicode?.should eq(true)
    message.flags_low.negotiate_ntlm?.should eq(true)

    message.domain.should eq("DOMAIN")
    message.user.should eq("user")
    message.workstation.should eq("WORKSTATION")

    message.to_slice.hexstring.size.should eq(hexstring.size)
  end

  it "should parse a NTLMv2 Authenticate message" do
    hexstring = "4e544c4d5353500003000000180018006000000018001800780000000c000c00" +
                "40000000080008004c0000000c000c00540000001000100090000000358288e0" +
                "54004500530054004e00540074006500730074004d0045004d00420045005200" +
                "404d1b6f6915258000000000000000000000000000000000ea8cc49f24da157f" +
                "13436637f77693d8b992d619e584c7ee727a5240822ec7af4e9100c43e6fee7f"

    data = IO::Memory.new hexstring.hexbytes
    message = data.read_bytes(NTLM::Authenticate)
    message.protocol.should eq("NTLMSSP")
    message.message_type.should eq(NTLM::Type::Authenticate)

    message.flags_low.characters_unicode?.should eq(true)
    message.flags_low.negotiate_ntlm?.should eq(true)
    message.flags_low.negotiate_sign?.should eq(true)
    message.flags_low.negotiate_seal?.should eq(true)
    message.flags_low.negotiate_always_sign?.should eq(true)

    message.flags_high.negotiate_session_security?.should eq(true)
    message.flags_high.negotiate_domain_info?.should eq(true)
    message.flags_high.negotiate128_bit?.should eq(true)
    message.flags_high.negotiate_key_exchange?.should eq(true)
    message.flags_high.negotiate56_bit?.should eq(true)

    message.domain.should eq("TESTNT")
    message.user.should eq("test")
    message.workstation.should eq("MEMBER")

    message.session_key.hexstring.should eq("727a5240822ec7af4e9100c43e6fee7f")

    message.to_slice.hexstring.should eq(hexstring)
  end
end
