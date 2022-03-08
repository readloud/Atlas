require "rubygems"

Gem::Specification.new do |s|
    s.name = "virustotalapi"
    s.version = "0.0.1"
    s.license = "MIT"
    s.author = "Jun C. Valdez"
    s.email = "rubygems@sploitlabs.com"
    s.files = ["lib/virustotalapi.rb","README.rdoc", "History.txt","virustotalapi.gemspec"]
    s.summary = "Implementation of the VirusTotal API in Ruby" 
    s.description = %q{virustotalapi is Ruby module that interfaces with the VirusTotal API via HTTP POST and JSON responses. The code was derived from Takahiro Matsuji's snippet at https://gist.gituhub.com/520909}
end

