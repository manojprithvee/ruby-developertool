require 'test_helper'

class ApiControllerTest < ActionController::TestCase
  test "should get sslverify" do
    get :sslverify
    assert_response :success
  end

end
