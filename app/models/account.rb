class Account < ActiveRecord::Base
	include Swagger::Blocks

	swagger_schema :Account do
		key :required, [
			:id, 
			:name, 
			:store_account_key
		]
		property :id do
			key :type, :string
			key :format, :uuid
		end
		property :name do
			key :type, :string
		end
		property :email do
			key :type, :string
		end
		property :store_api_key do
			key :type, :boolean
		end
		property :created_date do
			key :type, :string
			key :format, :datetime
		end
	end
end
