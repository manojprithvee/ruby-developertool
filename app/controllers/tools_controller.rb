class ToolsController < ApplicationController
 include ToolsHelper
 
  def word_count
  expires_in 1.day, public: true, must_revalidate: true
  end

  def differ_text
  end

  def password_gen
  end

  def hash_generator
  end

  def url_encode
  end

  def string_search
  end

  def code_format
  end

  def about
  end

  def contact
  end
  def index
  end
  def privacypolicy
  end
  def base64encode
  end
  def ipaddress
  end
  def xpath
  end
  def sslverify
  end
end
