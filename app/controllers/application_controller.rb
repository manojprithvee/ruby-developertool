require 'date'
class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  before_filter :get_xmas
def get_xmas
    today=Date.today
    range= (Date.new(today.year, 12, 1)..Date.new(today.year+1, 1, 1))
    @xmas = false
    if range.include? today
      @xmas = true
    end
end
end
