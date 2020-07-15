require "./spec_helper"

describe NTLM do
  it "should parse a minimal Negotiate message" do
    hexstring = "4e544c4d535350000100000002020000"
    data = IO::Memory.new hexstring.hexbytes
    message = data.read_bytes(NTLM::Negotiate)
    message.protocol.should eq("NTLMSSP")
    message.message_type.should eq(NTLM::Type::Negotiate)

    message.flags_low.characters_oem?.should eq(true)
    message.flags_low.negotiate_ntlm?.should eq(true)

    message.domain.should eq("")
    message.workstation.should eq("")

    message.to_slice.hexstring.should eq(hexstring)
  end

  it "should parse the most complex Negotiate message" do
    hexstring = "4e544c4d53535000010000000732000006000600330000000b000b0028000000050093080000000f574f524b53544154494f4e444f4d41494e"
    data = IO::Memory.new hexstring.hexbytes
    message = data.read_bytes(NTLM::Negotiate)
    message.protocol.should eq("NTLMSSP")
    message.message_type.should eq(NTLM::Type::Negotiate)

    message.flags_low.characters_oem?.should eq(true)
    message.flags_low.negotiate_ntlm?.should eq(true)

    message.flags_low.negotiate_domain_supplied?.should eq(true)
    message.domain.should eq("DOMAIN")

    message.flags_low.negotiate_workstation_supplied?.should eq(true)
    message.workstation.should eq("WORKSTATION")

    message.to_slice.hexstring.should eq(hexstring)
  end

  it "should update an existing Negotiate message" do
    hexstring = "4e544c4d53535000010000000732000006000600330000000b000b0028000000050093080000000f574f524b53544154494f4e444f4d41494e"
    data = IO::Memory.new hexstring.hexbytes
    message = data.read_bytes(NTLM::Negotiate)

    message.domain = "windom"
    hexnew = message.to_slice.hexstring

    data = IO::Memory.new hexnew.hexbytes
    message = data.read_bytes(NTLM::Negotiate)
    message.protocol.should eq("NTLMSSP")
    message.message_type.should eq(NTLM::Type::Negotiate)

    message.flags_low.characters_oem?.should eq(true)
    message.flags_low.negotiate_ntlm?.should eq(true)

    message.flags_low.negotiate_domain_supplied?.should eq(true)
    message.domain.should eq("WINDOM")

    message.flags_low.negotiate_workstation_supplied?.should eq(true)
    message.workstation.should eq("WORKSTATION")
  end

  it "should generate a new Negotiate message" do
    message = NTLM::Negotiate.new
    message.domain = "WINDOM"

    hexnew = message.to_slice.hexstring
    data = IO::Memory.new hexnew.hexbytes
    message = data.read_bytes(NTLM::Negotiate)
    message.protocol.should eq("NTLMSSP")
    message.message_type.should eq(NTLM::Type::Negotiate)

    message.flags_low.characters_unicode?.should eq(true)
    message.flags_low.negotiate_ntlm?.should eq(true)

    message.flags_low.negotiate_domain_supplied?.should eq(true)
    message.domain.should eq("WINDOM")

    message.flags_low.negotiate_workstation_supplied?.should eq(false)
    message.workstation.should eq("")
  end
end
