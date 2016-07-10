module Api
module V1

class AdminController < ApplicationController
	include Swagger::Blocks

	swagger_path '/v1/admin/start' do
		operation :post do
			key :description, 'Initialized the application with the admin password. The default password is "admin".'
			key :operationId, 'adminStart'
			parameter do
				key :name, :admin_password
				key :in, :body
				key :description, 'The admin password'
				key :required, true
				schema do
					key :type, :object
					property :password do
						key :type, :string
					end
				end
			end
			response 200 do
				key :description, 'The response'
				schema do
					key :type, :object
					property :message do
						key :type, :string
					end
				end
			end
			response :default do
				key :description, 'Unexpected error'
				schema do
					key :'$ref', :ErrorListModel
				end
			end
		end #operation :post
	end #swagger_path

	swagger_path '/v1/admin/compute_admin_hash' do
		operation :post do
			key :description, 'Generates the @@admin_password_hash_hash to be set in base_api_controller. You, the administrator, should come up with a unique password and not use the default password of "admin".'
			key :operationId, 'adminComputeHash'
			parameter do
				key :name, :admin_password
				key :in, :body
				key :description, 'The new admin password'
				key :required, true
				schema do
					key :type, :object
					property :password do
						key :type, :string
					end
				end
			end
			response 200 do
				key :description, 'The new @@admin_password_hash_hash. Update your app/controllers/api/v1/base_api_controller.rb with this new hash.'
				schema do
					key :type, :object
					property :admin_password_hash_hash do
						key :type, :string
					end
				end
			end
			response :default do
				key :description, 'Unexpected error'
				schema do
					key :'$ref', :ErrorListModel
				end
			end
		end #operation :post
	end #swagger_path


	respond_to :json


	def start
		admin_password_hash = generate_hash_from_request_password()

		if admin_password_hash.nil?
			return
		end

		if !BaseApiController.initialize(admin_password_hash)
			render json: { :message => "The password provided was incorrect" }, status: 200
			return
		end

		render json: { :message => "Application successfully initialized" }, status: 200
	end


	def compute_hash
		admin_password_hash = generate_hash_from_request_password()

		if admin_password_hash.nil?
			return
		end
		
		render json: { :admin_password_hash_hash => Digest::SHA256.hexdigest([admin_password_hash].pack('H*')) }, status: 200
	end


protected
	def generate_hash_from_request_password
		if !BaseApiController.application_key.nil? && BaseApiController.application_key != ''
			render json: { :message => "Application has already been initialized" }, status: 200
			return nil
		end

		json = BaseApiController.parse_request(request, params)
		password = json['password']

		if password.nil? || password == ''
			render json: { :errors => ["Password was not provided"] }, status: 422
			return nil
		end

		return BaseApiController.argon2i_raw(password, 'jBl(5.*XZgizwCX?', 30, 15, 64)
	end
end

end
end
