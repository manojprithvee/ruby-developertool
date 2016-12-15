class ExampleMailer < ActionMailer::Base
  default from: "yobroeeee@gmail.com"
  def sample_email(user)
    @user = user
    mail(to: @user['email'], subject: "Web Site Live Checker | Developertool.biz")
  end
end