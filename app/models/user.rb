class User < ApplicationRecord
  attr_accessor :remember_token
  before_save { self.email = email.downcase }
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i
  
  validates :name,  presence: true, length: {maximum: 50 }
  
  validates :email, presence: true, length: {maximum: 255 }, uniqueness: true
  validates :email, format: { with: VALID_EMAIL_REGEX }
  
  has_secure_password
  validates :password, presence: true, length: { minimum: 6 }
  
  # 渡された文字列のハッシュ値を返す
  def User.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
                                                  BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
  end
  
  # ランダムなトークンを返す
  def User.new_token
    SecureRandom.urlsafe_base64
  end
  
  # 永続セッションのためにユーザーをDBに記憶する
  def remember
    self.remember_token = User.new_token # rememberのtoken(ランダム文字列)として、新しく作成してる
    update_attribute(:remember_digest, User.digest(remember_token)) # 作成後、tokenをdigest化（ハッシュ化）して:remember_digestとしてカラムに保存
    remember_digest  
  end
  
  # セッションハイジャック防止のためにセッショントークンを返す
  # この記憶ダイジェストを再利用しているのは単に利便性のため
  def session_token
    remember_digest || remember
  end
  
  # 暗号化された文字列(remember_digest)が
  # 検証したい文字列（remember_token）から暗号化する文字列と
  # 一致するかを検証している
  def authenticated?(remember_token)
    return false if remember_digest.nil?
    BCrypt::Password.new(remember_digest).is_password?(remember_token)
  end
  
  # ユーザーの永続ログイン情報を破棄する
  def forget
    update_attribute(:remember_digest, nil)
  end
end
