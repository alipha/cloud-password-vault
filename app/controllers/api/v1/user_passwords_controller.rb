module Api
module V1

class UserPasswordsController < BaseApiController
	include Swagger::Blocks

	swagger_path '/v1/user_passwords' do
		operation :delete do
			key :description, 'Deletes the user and associated password from your account if the user exists. Otherwise, does nothing.'
			key :operationId, 'deleteUserPassword'
			parameter do
				key :name, :user
				key :in, :body
				key :description, 'The username to delete'
				key :required, true
				schema do
					key :type, :object
					property :username do
						key :type, :string
					end
 				end
			end
			parameter do
				key :name, :api_key
				key :in, :query
				key :description, 'Your API token. Provide the whole 101-character token'
				key :required, true
				key :type, :string
			end
			response 204 do
				key :description, 'The user was deleted or did not exist'
			end
			response :default do
				key :description, 'Unexpected error'
				schema do
					key :'$ref', :ErrorListModel
				end
			end
		end #operation :delete
	end #swagger_path

	swagger_path '/v1/user_passwords' do
		operation :post do
			key :description, 'Creates a user with the specified password or updates the user password if the user already exists'
			key :operationId, 'createUserPassword'
			parameter do
				key :name, :user_password
				key :in, :body
				key :description, 'The username/password combination to insert or update'
				key :required, true
				schema do
					key :'$ref', :UserPassword
				end
			end
			parameter do
				key :name, :api_key
				key :in, :query
				key :description, 'Your API token. Provide the whole 101-character token'
				key :required, true
				key :type, :string
			end
			response 204 do
				key :description, 'The operation was successful'
			end
			response :default do
				key :description, 'Unexpected error'
				schema do
					key :'$ref', :ErrorListModel
				end
			end
		end #operation :post
	end #swagger_path

	swagger_path '/v1/user_passwords/verify' do
		operation :post do
			key :description, 'Verifies whether the password is valid for the specified user'
			key :operationId, 'verifyUserPassword'
			parameter do
				key :name, :user_password
				key :in, :body
				key :description, 'The username/password combination to verify'
				key :required, true
				schema do
					key :'$ref', :UserPassword
				end
			end
			parameter do
				key :name, :api_key
				key :in, :query
				key :description, 'Your API token. Provide the whole 101-character token'
				key :required, true
				key :type, :string
			end
			response 200 do
				key :description, 'The password validity'
				schema do
					key :type, :object
					property :valid_password do
						key :type, :boolean
					end
				end
			end
			response :default do
				key :description, 'Unexpected error'
				schema do
					key :'$ref', :ErrorListModel
				end
			end
		end #operation :get
	end #swagger_path


	respond_to :json

	before_filter :authenticate_account!

	@@password_cost = 13
	@@dummy_password_hash = BaseApiController.argon2_encode("fake password", true, @@password_cost, "fake secret")
	@@invalid_username_error = 'Username must be provided and cannot be blank'
	@@invalid_password_error = 'Password must be provided and cannot be blank'


	def verify
		if !parse_username_and_password()
			return
		end

		username_hash = hash_username(@username)
		user_password = UserPassword.find_by(username: username_hash)

		if !user_password.nil?
			valid_password = argon2_verify(@password, user_password.password, get_password_secret(@username))
		else
			argon2_verify("dummy password", @@dummy_password_hash, get_password_secret("dummy username"))
			valid_password = false
		end

		render json: { :valid_password => valid_password }, status: 200
	end


	def create
		if !parse_username_and_password()
			return
		end

		username_hash = hash_username(@username)
		password_hash = hash_password(@username, @password)

		user_password = UserPassword.find_by(username: username_hash)
		new_user_password = UserPassword.new

		found = !user_password.nil?

		if !found
			user_password = new_user_password
		end

		user_password.username = username_hash
		user_password.password = password_hash

		if user_password.save
			if !found
				update_user_count 1  #todo: if this fails, the user_count will be incorrect
			end
			audit_user_password (found ? 'U' : 'C'), user_password
			render nothing: true, status: 204
		else
			#todo: better validation and error messages
			render json: { :errors => user_password.errors }, status: 422
		end
	end


	def destroy
		@username = @json['username']

		if @username.nil? || @username == ''
			render json: { :errors => [@@invalid_username_error] }, status: 422
			return
		end

		username_hash = hash_username(@username)

		user_password = UserPassword.find_by(username: username_hash)

		found = !user_password.nil?

		if found
			audit_user_password 'D', user_password
		end

		if !found || user_password.delete
			if found
				update_user_count -1  #todo: if this fails, the user_count will be incorrect
			end
			render nothing: true, status: 204
		else
			#todo: better validation and error messages
			render json: { :errors => user_password.errors }, status: 422
		end
	end


protected
	def update_user_count(amount)
		user_count = decrypt('CBC', BaseApiController.application_key, @account.user_count).to_i
		user_count += amount
		@account.user_count = encrypt('CBC', BaseApiController.application_key, user_count.to_s)
		@account.save
		#todo: error handling
	end


	def audit_user_password(action, user_password)
		values = {
			:username => user_password.username,
			:password => user_password.password,
			:action => action
		}

		history = UserPasswordHistory.new(values)
		history.save  #todo: log error?
	end


	def parse_username_and_password
		@username = @json['username']
		@password = @json['password']

		if @username.nil? || @username == ''
			render json: { :errors => [@@invalid_username_error] }, status: 422
			return false
		end

		if @password.nil? || @password == ''
			render json: { :errors => [@@invalid_password_error] }, status: 422
			return false
		end

		return true
	end


	def hash_username(username)
		return argon2_encode(username, false, @@password_cost - 1, BaseApiController.application_salt + [@account_key].pack('H*'))
	end


	def hash_password(username, password)
		return argon2_encode(password, true, @@password_cost, get_password_secret(username))
	end


	def get_password_secret(username)
		pass_salt_raw = decrypt('ECB', [@account_key].pack('H*'), @account.pass_salt)
		return BaseApiController.application_salt + pass_salt_raw + username	
	end
end

end
end
