# encoding: utf-8
require "forwardable"
require "base64"

require "logstash/filters/base"
require "logstash/namespace"

# This example filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an example.
class LogStash::Filters::Base64 < LogStash::Filters::Base
  
  VALID_DIRECTIONS = ["strict_encode64", "strict_decode64", "encode64", "decode64"]

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   example {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "base64"

  # Replace the message with this value.
  config :source, :validate => :string, :required => :true
  config :destination, :validate => :string
  config :direction, :validate => VALID_DIRECTIONS, :default => "strict_decode64"


  public
  def register
    if @destination.empty?
      @destination = @source
    end
    
    @logger.info("[BASE64 FILTER] Base64 filter registered",
      :source => @source,
      :destination => @destination,
      :direction => @direction
    )
  end # def register

  public
  def filter(event)
    encoding = @direction.include?("encode") ? "utf-8" : "BINARY"
    
    begin
      base64log(:debug, 
        "Write value using encoding #{encoding}", :event => event)
      
      value = Base64.send @direction.to_sym, event.get(@source)
      event.set(destination, value.force_encoding(encoding))
      
      filter_matched(event)
    rescue => e
      event.tag("_base64codingfailure")
      base64log(:error, "Caught exception while trying to process event",
        :event => event,
        :message => e.message,
        :class => e.class,
        :backtrace => e.backtrace
      )
    end
  end # def filter
  
  def base64log(urgency, msg, opts={})
    @logger.send urgency, "[BASE64 FILTER] #{msg}", opts.merge(
      :source => @source, :destination => @destination, :direction => @direction)
  end # def base64log
end # class LogStash::Filters::Example
