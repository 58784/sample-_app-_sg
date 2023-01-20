class UsersController < ApplicationController
  before_action :find_user, only: %w[show]
  
  def new
    @user = User.new
  end
  
  def create
    @user = User.new(user_params)
    if @user.save
      reset_session
      log_in @user
      flash[:success] = "Welcome to the Sample App!"
      redirect_to @user
    else
      flash.now[:danger] = "Signup failed."
      render :new, status: :unprocessable_entity
    end
  end
  
  def show
  end
  
  private
  
    def user_params
      params.require(:user).permit(:name, :email, :password, :password_confirmation)
    end
    
    def find_user
      @user = User.find(params[:id])
    end
end
