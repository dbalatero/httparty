require 'uri'

module HTTParty
  class Request #:nodoc:
    SupportedHTTPMethods = [Net::HTTP::Get, Net::HTTP::Post, Net::HTTP::Put, Net::HTTP::Delete, Net::HTTP::Post::Multipart]
    
    attr_accessor :http_method, :path, :options
    
    def initialize(http_method, path, o={})
      self.http_method = http_method
      self.path = path
      self.options = {
        :limit => o.delete(:no_follow) ? 0 : 5, 
        :default_params => {},
      }.merge(o)
    end

    def path=(uri)
      @path = URI.parse(uri)
    end
    
    def uri
      new_uri = path.relative? ? URI.parse("#{options[:base_uri]}#{path}") : path
      
      # avoid double query string on redirects [#12]
      unless @redirect
        new_uri.query = query_string(new_uri)
      end
      
      new_uri
    end
    
    def format
      options[:format]
    end
    
    def perform
      validate
      setup_raw_request
      handle_response(get_response)
    end

    private
      def http
        http = Net::HTTP.new(uri.host, uri.port, options[:http_proxyaddr], options[:http_proxyport])
        http.use_ssl = (uri.port == 443)
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http
      end

      def configure_basic_auth
        @raw_request.basic_auth(options[:basic_auth][:username], options[:basic_auth][:password])
      end

      def setup_raw_request
        if multipart?
          @file_handles = []
          io_objects = {}

          options[:multipart].each do |field_name, info|
            fp = File.open(info[:path])
            @file_handles << fp

            io_objects[field_name] = UploadIO.new(fp,
                                                  info[:type],
                                                  info[:path])
          end

          @raw_request = http_method.new(uri.request_uri,
                                         io_objects)

          # We have to duplicate and merge the headers set by the
          # multipart object to make sure that Net::HTTP 
          # doesn't override them down the line when it calls
          # initialize_http_header.
          #
          # Otherwise important headers like Content-Length,
          # Accept, and Content-Type will be deleted.
          original_headers = {}
          @raw_request.each do |key, value|
            original_headers[key] = value
          end

          options[:headers] ||= {}
          original_headers.merge!(options[:headers])
          options[:headers] = original_headers
        else
          @raw_request = http_method.new(uri.request_uri)
        end
        
        if post? && options[:query]
          @raw_request.set_form_data(options[:query])
        end
 
        @raw_request.body = options[:body].is_a?(Hash) ? options[:body].to_params : options[:body] unless options[:body].blank?
        @raw_request.initialize_http_header options[:headers]
        
        configure_basic_auth if options[:basic_auth]
      end

      def perform_actual_request
        http.request(@raw_request)
      end

      def get_response
        response = perform_actual_request
        options[:format] ||= format_from_mimetype(response['content-type'])

        # Once we have the response back, it's safe to close any open
        # file handles for multipart requests.
        if @file_handles
          @file_handles.each do |fp|
            fp.close
          end
        end

        response
      end
      
      def query_string(uri)
        query_string_parts = []
        query_string_parts << uri.query unless uri.query.blank?

        if options[:query].is_a?(Hash)
          query_string_parts << options[:default_params].merge(options[:query]).to_params
        else
          query_string_parts << options[:default_params].to_params unless options[:default_params].blank?
          query_string_parts << options[:query] unless options[:query].blank?
        end
        
        query_string_parts.size > 0 ? query_string_parts.join('&') : nil
      end
      
      # Raises exception Net::XXX (http error code) if an http error occured
      def handle_response(response)
        case response
          when Net::HTTPRedirection
            options[:limit] -= 1
            self.path = response['location']
            @redirect = true
            perform
          else
            parsed_response = parse_response(response.body)
            Response.new(parsed_response, response.body, response.code, response.message, response.to_hash)
          end
      end
      
      def parse_response(body)
        return nil if body.nil? or body.empty?
        case format
          when :xml
            Crack::XML.parse(body)
          when :json
            Crack::JSON.parse(body)
          when :yaml
            YAML::load(body)
          else
            body
          end
      end
  
      # Uses the HTTP Content-Type header to determine the format of the response
      # It compares the MIME type returned to the types stored in the AllowedFormats hash
      def format_from_mimetype(mimetype)
        return nil if mimetype.nil?
        AllowedFormats.each { |k, v| return v if mimetype.include?(k) }
      end
      
      def validate
        raise HTTParty::RedirectionTooDeep, 'HTTP redirects too deep' if options[:limit].to_i <= 0
        raise ArgumentError, 'only get, post, put and delete methods are supported' unless SupportedHTTPMethods.include?(http_method)
        raise ArgumentError, 'multipart must include at least one file' if multipart? && (options[:multipart].nil? || options[:multipart].empty?)
        raise ArgumentError, ':headers must be a hash' if options[:headers] && !options[:headers].is_a?(Hash)
        raise ArgumentError, ':basic_auth must be a hash' if options[:basic_auth] && !options[:basic_auth].is_a?(Hash)
        raise ArgumentError, ':query must be hash if using HTTP Post' if post? && !options[:query].nil? && !options[:query].is_a?(Hash)
      end
     
      def post?
        [Net::HTTP::Post, Net::HTTP::Post::Multipart].include?(http_method)
      end

      def multipart?
        Net::HTTP::Post::Multipart == http_method
      end
  end
end
