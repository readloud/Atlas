#!/usr/bin/env ruby
#
# Copyright (c) 2011 Jun C. Valdez
# Code is distributed under the terms of an MIT style license
# http://www.opensource.org/licenses/mit-license
#

require 'rubygems'
require 'json'
require 'rest-client'


module VirusTotal
  
  class API

    VTAPI_REQ_SUCESS = 1
    VTAPI_NOT_FOUND = 0
    VTAPI_REQ_EXCEEDED = -2
    VTAPI_KEY_ERROR = -1 

     ## Its small modification on VirusTotal::API to use APIv2 instead of APIv1 ##
#    GET_FILE_REPORT = 'https://www.virustotal.com/api/get_file_report.json'
#    SCAN_FILE = 'https://www.virustotal.com/api/scan_file.json'
#    GET_URL_REPORT = 'https://www.virustotal.com/api/get_url_report.json'
#    SCAN_URL = 'https://www.virustotal.com/api/scan_url.json'

    GET_FILE_REPORT = 'https://www.virustotal.com/vtapi/v2/file/report.json'
    SCAN_FILE       = 'https://www.virustotal.com/vtapi/v2/file/scan.json'
    GET_URL_REPORT  = 'http://www.virustotal.com/vtapi/v2/url/report'
    SCAN_URL        = 'https://www.virustotal.com/vtapi/v2/url/scan'
  
    attr_reader :vtapistatus
    
    def initialize(key)
      @apikey = key 
    end
    
    def get_file_report(hash)
      json = RestClient.post(GET_FILE_REPORT, 'key' => @apikey, 'resource' => hash)
      dict = JSON.parse(json)
      @vtapistatus = dict['result']
      dict['report'] 
    end
    
    def scan_file(file)
      json = RestClient.post(SCAN_FILE,
                            'key' => @apikey,
                            'file' => File.new(file, 'rb'),
                            'multipart' => true)
      dict = JSON.parse(json)
      @vtapistatus = dict['result']
      dict['scan_id'] 
    end
    
    def get_url_report(url)
      json = RestClient.post(GET_URL_REPORT, 'key' => @apikey, 'resource' => url)
      dict = JSON.parse(json)
      @vtapistatus = dict['result']
      dict['report'] 
    end
    
    def scan_url(url)
      json = RestClient.post(SCAN_URL, 'key' => @apikey, 'url' => url)
      dict = JSON.parse(json)
      @vtapistatus = dict['result']
      dict['scan_id'] 
    end
    
  end
end

