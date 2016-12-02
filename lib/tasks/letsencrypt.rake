require 'open-uri'
require 'openssl'
require 'acme-client'
require 'platform-api'

namespace :letsencrypt do

  desc 'Renew your LetsEncrypt certificate'
  task :renew => :environment do
    begin
      Letsencrypt::process
    rescue => e
      abort e.message
    end
  end

end
