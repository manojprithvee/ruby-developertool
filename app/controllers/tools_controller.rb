class ToolsController < ApplicationController
 include ToolsHelper
 
  def word_count
  expires_in 1.day, public: true, must_revalidate: true
  end

  def differ_text
  expires_in 1.day, public: true, must_revalidate: true
  end

  def password_gen
  expires_in 1.day, public: true, must_revalidate: true
  end

  def hash_generator
  expires_in 1.day, public: true, must_revalidate: true
  end

  def url_encode
  expires_in 1.day, public: true, must_revalidate: true
  end

  def string_search
  expires_in 1.day, public: true, must_revalidate: true
  end

  def code_format
  expires_in 1.day, public: true, must_revalidate: true
  end

  def about
  expires_in 1.day, public: true, must_revalidate: true
  end

  def contact
  expires_in 1.day, public: true, must_revalidate: true
  end
  def index
  expires_in 1.day, public: true, must_revalidate: true
  end
  def privacypolicy
  expires_in 1.month, public: true, must_revalidate: true
  end
  def base64encode
  expires_in 1.day, public: true, must_revalidate: true
  end
  def ipaddress
  expires_in 1.day, public: true, must_revalidate: true
  end
  def xpath
  expires_in 1.day, public: true, must_revalidate: true
  end
  def sslverify
  expires_in 1.day, public: true, must_revalidate: true
  end
  def website_down_notifer
  expires_in 1.day, public: true, must_revalidate: true
  end 
end
