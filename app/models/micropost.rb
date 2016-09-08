# == Schema Information
#
# Table name: microposts
#
#  id         :integer          not null, primary key
#  content    :text
#  user_id    :integer
#  created_at :datetime         not null
#  updated_at :datetime         not null
#

class Micropost < ActiveRecord::Base
  belongs_to :user

  default_scope -> { order(created_at: :desc) }

  validates :user_id, presence: true

  validates :content, #presence: true,
                      length: { maximum: 140 }
end