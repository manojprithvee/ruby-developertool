require 'faraday'
require 'json'
module ToolsHelper
def getipdetails(ip)
begin
abc=JSON.parse(Faraday.get("http://ip-api.com/json/"+ip).body)
puts 
if !abc.nil? and !abc["status"].nil? and abc["status"]=="success" and !abc["isp"].nil?
return abc["isp"]
else 
return nil
end
rescue
return nil
end
end
