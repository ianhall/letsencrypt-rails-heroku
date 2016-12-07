module Letsencrypt
  class << self
    attr_accessor :configuration
  end

  def self.configure
    self.configuration ||= Configuration.new
    yield(configuration) if block_given?
  end

  def self.challenge_configured?
    configuration.acme_challenge_filename.present? &&
      configuration.acme_challenge_filename.starts_with?(".well-known/") &&
      configuration.acme_challenge_file_content.present?
  end

  def self.process
    # Check configuration looks OK
    unless configuration.valid?
      raise "letsencrypt-rails-heroku is configured incorrectly. Are you missing an environment variable or other configuration? You should have a heroku_token, heroku_app, acme_email and acme_domain configured either via a `Letsencrypt.configure` block in an initializer or as environment variables."
    end

    # Set up Heroku client
    heroku = PlatformAPI.connect_oauth configuration.heroku_token
    heroku_app = configuration.heroku_app

    # Create a private key
    print "Creating account key..."
    private_key = OpenSSL::PKey::RSA.new(4096)
    puts "Done!"

    client = Acme::Client.new(private_key: private_key, endpoint: configuration.acme_endpoint, connection_options: { request: { open_timeout: 5, timeout: 5 } })

    print "Registering with LetsEncrypt..."
    registration = client.register(contact: "mailto:#{configuration.acme_email}")

    registration.agree_terms
    puts "Done!"

    domains = configuration.acme_domain.split(',').map(&:strip)

    domains.each do |domain|
      puts "Performing verification for #{domain}:"

      authorization = client.authorize(domain: domain)
      challenge = authorization.http01

      print "Setting config vars on Heroku..."
      heroku.config_var.update(heroku_app, {
        'ACME_CHALLENGE_FILENAME' => challenge.filename,
        'ACME_CHALLENGE_FILE_CONTENT' => challenge.file_content
      })
      puts "Done!"

      # Wait for request to go through
      print "Giving config vars time to change..."
      sleep(5)
      puts "Done!"

      # Wait for app to come up
      print "Testing filename works (to bring up app)..."

      # Get the domain name from Heroku
      hostname = heroku.domain.list(heroku_app).first['hostname']
      open("http://#{hostname}/#{challenge.filename}").read
      puts "Done!"

      print "Giving LetsEncrypt some time to verify..."
      # Once you are ready to serve the confirmation request you can proceed.
      challenge.request_verification # => true
      challenge.verify_status # => 'pending'

      sleep(3)
      puts "Done!"

      unless challenge.verify_status == 'valid'
        puts "Problem verifying challenge."
        raise "Status: #{challenge.verify_status}, Error: #{challenge.error}"
      end

      puts ""
    end

    # Unset temporary config vars. We don't care about waiting for this to
    # restart
    heroku.config_var.update(heroku_app, {
      'ACME_CHALLENGE_FILENAME' => nil,
      'ACME_CHALLENGE_FILE_CONTENT' => nil
    })

    # Create CSR
    csr = Acme::Client::CertificateRequest.new(names: domains)

    # Get certificate
    certificate = client.new_certificate(csr) # => #<Acme::Client::Certificate ....>

    if configuration.acme_update_heroku_cert
      # Send certificates to Heroku via API

      # First check for existing certificates:
      certificates = heroku.sni_endpoint.list(heroku_app)

      begin
        if certificates.any?
          print "Updating existing certificate #{certificates[0]['name']}..."
          heroku.sni_endpoint.update(heroku_app, certificates[0]['name'], {
            certificate_chain: certificate.fullchain_to_pem,
            private_key: certificate.request.private_key.to_pem
          })
        else
          print "Adding new certificate..."
          heroku.sni_endpoint.create(heroku_app, {
            certificate_chain: certificate.fullchain_to_pem,
            private_key: certificate.request.private_key.to_pem
          })
        end
      rescue Excon::Error::UnprocessableEntity => e
        warn "Error adding certificate to Heroku. Response from Heroku’s API follows:"
        raise e.response.body
      end
      puts "Done!"
    end
    return certificate

  end

  class Configuration
    attr_accessor :acme_update_heroku_cert, :heroku_token, :heroku_app, :acme_email, :acme_domain, :acme_endpoint

    # Not settable by user; part of the gem's behaviour.
    attr_reader :acme_challenge_filename, :acme_challenge_file_content

    def initialize
      update_cert = ENV["ACME_UPDATE_HEROKU_CERT"].presence || 'true'
      if update_cert == 'true'
        @acme_update_heroku_cert = true
      else
        @acme_update_heroku_cert = false
      end
      @heroku_token = ENV["HEROKU_TOKEN"]
      @heroku_app = ENV["HEROKU_APP"]
      @acme_email = ENV["ACME_EMAIL"]
      @acme_domain = ENV["ACME_DOMAIN"]
      @acme_endpoint = ENV["ACME_ENDPOINT"].presence || 'https://acme-v01.api.letsencrypt.org/'
      @acme_challenge_filename = ENV["ACME_CHALLENGE_FILENAME"]
      @acme_challenge_file_content = ENV["ACME_CHALLENGE_FILE_CONTENT"]
    end

    def valid?
      heroku_token.present? && heroku_app.present? && acme_email.present? && acme_domain.present?
    end

  end
end
