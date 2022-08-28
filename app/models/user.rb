require "openssl"
class User < ApplicationRecord
  ITERATIONS = 20_000
  DIGEST = OpenSSL::Digest.new("SHA256")

  has_many :questions

  before_validation :username_downcase

  def username_downcase
    username.downcase!
  end

  validates :email, format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :username, length: { maximum: 40 }
  validates :email, :username, presence: true
  validates :email, :username, uniqueness: true

  validates_each :username do |record, attr, value|
    record.errors.add(attr, "can only contain Latin letters, numbers, and _") if value !~ /^[a-z0-9_]{1,}$/i
  end

  attr_accessor :password

  validates_presence_of :password, on: :create
  validates_confirmation_of :password

  before_save :encrypt_password

  def encrypt_password
    return unless password.present?

    self.password_salt = User.hash_to_string(OpenSSL::Random.random_bytes(16))

    self.password_hash = User.hash_to_string(
      OpenSSL::PKCS5.pbkdf2_hmac(password, password_salt, ITERATIONS, DIGEST.length, DIGEST)
    )
  end

  def self.hash_to_string(password_hash)
    password_hash.unpack1("H*")
  end

  def self.authenticate(email, password)
    user = find_by(email: email)

    if user.present? && user.password_hash == User.hash_to_string(
      OpenSSL::PKCS5.pbkdf2_hmac(password, user.password_salt, ITERATIONS, DIGEST.length, DIGEST)
    )
      user
    end
  end
end
