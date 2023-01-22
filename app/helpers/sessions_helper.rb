module SessionsHelper
  # 渡されたユーザーでログインする
  def log_in(user)
    session[:user_id] = user.id
    session[:session_token] = user.session_token # セッションリプレイ攻撃から保護する
  end
  
  # 永続セッションのためにユーザーをデータベースに記憶する
  # permanent = 永続的（20年）
  # encrypted = 暗号化
  def remember(user)
    user.remember #モデルで定義したremember。記憶トークンを作成、ハッシュ化してDBに保存
    cookies.permanent.encrypted[:user_id] = user.id
    cookies.permanent[:remember_token] = user.remember_token
  end
  
  # 記憶トークンcookieに対応するユーザーを返す
  def current_user
    if (user_id = session[:user_id])
      user = User.find_by(id: user_id)
      if user && session[:session_token] == user.session_token
        @current_user = user
      end
    elsif (user_id = cookies.encrypted[:user_id])
      user = User.find_by(id: user_id)
      if user && user.authenticated?(cookies[:remember_token])
      # if user&.authenticated?(cookies[:remember_token])
        log_in user
        @current_user = user
      end
    end
  end
  
  # ユーザーがログインしていればtrue、その他ならfalseを返す
  def logged_in?
    !current_user.nil?
  end
  
  # 永続的セッションを破棄する
  def forget(user)
    user.forget #モデルで定義したforget。DBの記憶ダイジェストにnilを登録。
    cookies.delete(:user_id)
    cookies.delete(:remember_token)
  end
  
  # 現在のユーザーをログアウトする
  def log_out
    forget(current_user)
    reset_session
    @currenr_user = nil  # 安全のため
  end
end
