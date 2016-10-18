# encoding: utf-8

require "base64"
require "forwardable"

require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/base64"

describe LogStash::Filters::Base64 do
  let(:event) {
    LogStash::Event.new(
      "valid_base64" => "SGVsbG8gV29ybGQ=",
      "invalid_base64" => "ajosidf0as9däfk",
      "valid_plaintext" => "Hello World",
      "invalid_plaintext" => "Hallo Welt\r\n"
    )
  }
  
  context "when decoding valid base64" do
    subject {
      LogStash::Filters::Base64.new(
        "source" => "valid_base64",
        "destination" => "decoded_valid_base64",
        "direction" => "strict_decode64"
      )
    }
    
    before do
      allow(subject).to receive(:base64log).with(any_args)
      subject.register
      subject.filter(event)
    end
    
    it "should decode correctly" do
      expect(event.get("decoded_valid_base64")).to eql("Hello World")
    end
    
    it "should have placed a debug message" do
      expect(subject).to have_received(:base64log).with(:debug, anything, anything)
    end
    
    it "should not have thrown an error" do
      expect(subject).not_to have_received(:base64log).with(:error, anything, anything)
    end
  end
end
