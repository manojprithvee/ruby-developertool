require 'sslverify'
class ApiController < ApplicationController
  def sslverify
  @result=`sslyze --regular #{params[:host]}`
  render :layout => nil
  end
end
