require 'resque/scheduler'
require 'resque/scheduler/server'
require 'resque'
Resque.redis = "127.0.0.1:6379/4"
Resque.redis.namespace = "developertool:resque"
Resque::Server.use(Rack::Auth::Basic) do |user, password|
  password == "secret"
end