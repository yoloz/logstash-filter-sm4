# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/sm4"

describe LogStash::Filters::Sm4 do
  describe "Add and decrypt Hello World" do
    let(:config) do <<-CONFIG
      filter {
        sm4 {
          message => "Hello World"
          # srcField => "message"
          # targetField => "targetF"
          key => "JeF8U9wHFOMfs2Y8"
          # iv => "JeF8U9wHFOMfs2Y8"
          mode => 1
        }
      }
    CONFIG
    end
    
    # sm4("message" => "some text") do
    #   expect(subject).to include("message")
    #   expect(subject.get('message')).to eq('Hello World')
    # end
  end
end
