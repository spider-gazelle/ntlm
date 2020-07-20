require "./spec_helper"

describe NTLM do
  it "should parse a minimal Challenge message" do
    hexstring = "4e544c4d53535000020000000000000000000000020200000123456789abcdef"
    data = IO::Memory.new hexstring.hexbytes
    message = data.read_bytes(NTLM::Challenge)
    message.protocol.should eq("NTLMSSP")
    message.message_type.should eq(NTLM::Type::Challenge)

    message.flags_low.characters_oem?.should eq(true)
    message.flags_low.negotiate_ntlm?.should eq(true)

    message.domain.should eq("")

    message.to_slice.hexstring.should eq(hexstring)
  end

  it "should parse a complex Challenge message" do
    hexstring = "4e544c4d53535000020000000c000c003000000001028100" +
                "0123456789abcdef0000000000000000620062003c000000" +
                "44004f004d00410049004e0002000c0044004f004d004100" +
                "49004e0001000c0053004500520056004500520004001400" +
                "64006f006d00610069006e002e0063006f006d0003002200" +
                "7300650072007600650072002e0064006f006d0061006900" +
                "6e002e0063006f006d0000000000"
    data = IO::Memory.new hexstring.hexbytes
    message = data.read_bytes(NTLM::Challenge)
    message.protocol.should eq("NTLMSSP")
    message.message_type.should eq(NTLM::Type::Challenge)

    message.flags_low.characters_unicode?.should eq(true)
    message.flags_low.negotiate_ntlm?.should eq(true)
    message.flags_high.target_type_domain?.should eq(true)
    message.flags_high.negotiate_domain_info?.should eq(true)

    message.domain.should eq("DOMAIN")
    message.domain_info.size.should eq(4)

    message.domain_info[0].unicode_value.should eq("DOMAIN")
    message.domain_info[1].unicode_value.should eq("SERVER")
    message.domain_info[2].unicode_value.should eq("domain.com")
    message.domain_info[3].unicode_value.should eq("server.domain.com")

    message.to_slice.hexstring.should eq(hexstring)
  end

  it "should update a complex Challenge message" do
    hexstring = "4e544c4d53535000020000000c000c003000000001028100" +
                "0123456789abcdef0000000000000000620062003c000000" +
                "44004f004d00410049004e0002000c0044004f004d004100" +
                "49004e0001000c0053004500520056004500520004001400" +
                "64006f006d00610069006e002e0063006f006d0003002200" +
                "7300650072007600650072002e0064006f006d0061006900" +
                "6e002e0063006f006d0000000000"
    data = IO::Memory.new hexstring.hexbytes
    message = data.read_bytes(NTLM::Challenge)

    message.domain = "DOMAIN"

    message.to_slice.hexstring.should eq(hexstring)
  end
end
