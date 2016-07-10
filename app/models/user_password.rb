class UserPassword < ActiveRecord::Base
	self.primary_key = 'username'

	include Swagger::Blocks

	swagger_schema :UserPassword do
		key :required, [
			:username,
			:password
		]
		property :username do
			key :type, :string
		end
		property :password do
			key :type, :string
		end
	end
end
