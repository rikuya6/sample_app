# == Schema Information
#
# Table name: microposts
#
#  id         :integer          not null, primary key
#  content    :text
#  user_id    :integer
#  created_at :datetime         not null
#  updated_at :datetime         not null
#  picture    :string
#

class Micropost < ActiveRecord::Base

  mount_uploader :picture, PictureUploader

  # 関連
  belongs_to :user

  # スコープ
  default_scope -> { order(created_at: :desc) }

  # バリデーション
  validates :user_id, presence: true

  validates :content, #presence: true,
                      length: { maximum: 140 }
  validate :picture_size

  private

    def picture_size
      if picture.size > 5.megabytes
        errors.add(:picture, 'should be less than 5MB')
      end
    end
end
