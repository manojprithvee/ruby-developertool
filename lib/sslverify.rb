class Sslverify
    def self.output_json(hostname)
        return `sslyze --regular www.developertool.biz --json_out -`
    end
    def self.output_xml(hostname)
        return `sslyze --regular www.developertool.biz --xml_out -`
    end
    def self.output_text(hostname)
        return `sslyze --regular #{hostname}`
    end
end