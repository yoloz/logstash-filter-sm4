# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "java"

require File.expand_path('../sm4-0.1.0.jar', __FILE__)
java_import "org.logstash.sm4.SM4"

# This  filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::Sm4 < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #    {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "sm4"
  
  # 待处理字段.
  config :source, :validate => :string, :default => "message"
  # 处理后输出字段.
  config :target, :validate => :string, :default => "message"
  # 密钥key，数字及字母 16位,32位或>32位
  config :key, :validate => :string, :required => true
  # CBC模式，初始化向量，数字及字母 16位,32位或>32位
  config :iv, :validate => :string, :default => ""
  # 加密1,解密0
  config :mode, :validate=> :number, :require => true

  public
  def register
    # Add instance variables
    @logger = self.logger
    begin
      @sm4 = SM4.new(@key,@iv,@mode)
    rescue => e
      raise e
      # @logger.error("Failed to init SM4", :exception => e)
    end
  end # def register

  public
  def filter(event)

    if @source
      # Replace the event message with our message as configured in the
      # config file.
      begin
        cipher = @sm4.process event.get(@source)
        event.set(@target, cipher)
      rescue => e
        @logger.error("Failed to #{@mode == 0 ? "decrypt" : "encrypt"} "+ event.get(@source), :exception => e)  
      end
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Sm4
