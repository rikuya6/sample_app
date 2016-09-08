class PasswordResetsController < ApplicationController
  before_action :get_user,          only: [:edit, :update]
  before_action :valid_user,        only: [:edit, :update]
  before_action :check_expiration,  only: [:edit, :update]

  def new
  end

  def create
    @user = User.find_by(email: params[:password_reset][:email].downcase)
    if @user
      @user.create_reset_digest
      @user.send_password_reset_email
      flash[:info] = 'パスワード再設定メールをご確認ください。'
      redirect_to root_url
    else
      flash.now[:danger] = 'メールアドレスが見つかりませんでした。'
      render 'new'
    end
  end

  def edit
  end

  def update
    if params[:user][:password].empty?
      @user.errors.add(:password, "can't be empty")
      render 'edit'
    elsif @user.update_attributes(user_params)
      log_in @user
      flash[:success] = 'パスワードをリセットしました。'
      redirect_to @user
    else
      render 'edit'
    end
  end

  private

    def user_params
      params.require(:user).permit(:password, :password_confirmation)
    end

    # Beforeフィルタ

    def get_user
      @user = User.find_by(email: params[:email])
    end

    # 正しいユーザを確認する
    def valid_user
      unless @user && @user.activated? &&
        @user.authenticated?(:reset, params[:id])
        redirect_to root_url
      end
    end

    # 再設定用トークンが期限切れかどうかを確認する
    def check_expiration
      if @user.password_reset_expired?
        flash[:danger] = 'パスワードリセットは期限切れです。'
        redirect_to new_password_reset_url
      end
    end
end
