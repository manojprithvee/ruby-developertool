require 'test_helper'

class ToolsControllerTest < ActionController::TestCase
  test "should get word_count" do
    get :word_count
    assert_response :success
  end

  test "should get differ_text" do
    get :differ_text
    assert_response :success
  end

  test "should get password_gen" do
    get :password_gen
    assert_response :success
  end

  test "should get hash_generator" do
    get :hash_generator
    assert_response :success
  end

  test "should get url_encode" do
    get :url_encode
    assert_response :success
  end

  test "should get string_search" do
    get :string_search
    assert_response :success
  end

  test "should get code_format" do
    get :code_format
    assert_response :success
  end

end
