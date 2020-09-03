require "./spec_helper"

describe NTLM do
  password = "Password"
  server_challenge = "0123456789abcdef".hexbytes
  client_challenge = ("\xaa" * 8).to_slice

  it "should create a NT hashed password" do
    hash = NTLM.create_NT_hashed_password_v1(password)
    hash.should eq "a4f49c406510bdcab6824ee7c30fd852".hexbytes
  end

  it "should create a LM hashed password" do
    hash = NTLM.create_LM_hashed_password_v1(password)
    hash.should eq "e52cac67419a9a224a3b108f3fa6cb6d".hexbytes
  end

  it "should create a session base key" do
    hash = NTLM.create_sessionbasekey(password)
    hash.should eq "d87262b0cde4b1cb7499becccdf10784".hexbytes
  end

  it "should generate challenge responses" do
    hash = NTLM.challenge_response(NTLM.create_NT_hashed_password_v1(password), server_challenge)
    hash.should eq "67c43011f30298a2ad35ece64f16331c44bdbed927841f94".hexbytes

    hash = NTLM.challenge_response(NTLM.create_LM_hashed_password_v1(password), server_challenge)
    hash.should eq "98def7b87f88aa5dafe2df779688a172def11c7d5ccdef13".hexbytes

    nt_response, lm_response = NTLM.ntlm2sr_challenge_response(NTLM.create_NT_hashed_password_v1(password), server_challenge, client_challenge)
    lm_response.should eq "aaaaaaaaaaaaaaaa00000000000000000000000000000000".hexbytes
    nt_response.should eq "7537f803ae367128ca458204bde7caf81e97ed2683267232".hexbytes
  end
end
