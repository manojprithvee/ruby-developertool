require 'faraday'
require 'json'
module ToolsHelper
def getipdetails(ip)
return JSON.parse(Faraday.get("http://ip-api.com/json/"+ip).body)["isp"]
end
end
