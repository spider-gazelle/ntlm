require "../ntlm"

module NTLM
  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce
  class Authenticate < BinData
    endian little

    custom header : Header = Header.new
  end
end
