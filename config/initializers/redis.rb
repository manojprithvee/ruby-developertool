uri = URI.parse("redis://h:p2f281cdce7e0a114699dd4580c3273f279b67a2cf6f5309917052b5b681943d9@ec2-54-225-230-45.compute-1.amazonaws.com:13469")
REDIS = Redis.new(:url => uri)