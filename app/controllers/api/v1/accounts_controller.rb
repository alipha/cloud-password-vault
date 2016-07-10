module Api
module V1

class AccountsController < BaseApiController 
	include Swagger::Blocks

	swagger_path '/v1/accounts/{id}' do
		operation :get do
			key :description, 'Returns information about your own account'
			key :operationId, 'getAccountById'
			parameter do
				key :name, :id
				key :in, :path
				key :description, 'Your account_id. The part before the colon in your api_key. Has a format of xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
				key :required, true
				key :type, :string
				key :format, :uuid
			end
			parameter do
				key :name, :api_key
				key :in, :query
				key :description, 'Your API token. Provide the whole 101-character token'
				key :required, true
				key :type, :string
			end
			response 200 do
				key :description, 'An Account object'
				schema do
					key :'$ref', :Account
				end
			end
			response :default do
				key :description, 'Unexpected error'
				schema do
					key :'$ref', :ErrorListModel
				end
			end
		end #operation :get
		operation :put do
			key :description, 'Update the information in your own account'
			key :operationId, 'updateAccount'
			parameter do
				key :name, :id
				key :in, :path
				key :description, 'Your account_id. The part before the colon in your api_key. Has a format of xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
				key :required, true
				key :type, :string
				key :format, :uuid
			end
			parameter do
				key :name, :api_key
				key :in, :query
				key :description, 'Your API token. Provide the whole 101-character token'
				key :required, true
				key :type, :string
			end
			parameter do
				key :name, :account
				key :in, :body
				key :description, 'Account to create'
				key :required, true
				schema do
					key :type, :object
					key :required, [:name, :store_api_key]
					property :name do
						key :type, :string
					end
					property :email do
						key :type, :string
					end
					property :store_api_key do
						key :type, :boolean
					end
				end
			end
			response 200 do
				key :description, 'The update was successful'
				schema do
					key :type, :object
					property :message do
						key :type, :string
					end
				end
			end
			response 204 do
				key :description, 'The update was successful'
			end
			response :default do
				key :description, 'Unexpected error'
				schema do
					key :'$ref', :ErrorListModel
				end
			end
		end #operation :put	
		operation :delete do
			key :description, 'Deletes your account'
			key :operationId, 'deleteAccountById'
			parameter do
				key :name, :id
				key :in, :path
				key :description, 'Your account_id. The part before the colon in your api_key. Has a format of xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
				key :required, true
				key :type, :string
				key :format, :uuid
			end
			parameter do
				key :name, :api_key
				key :in, :query
				key :description, 'Your API token. Provide the whole 101-character token'
				key :required, true
				key :type, :string
			end
			response 204 do
				key :description, 'The delete was successful'
			end
			response :default do
				key :description, 'Unexpected error'
				schema do
					key :'$ref', :ErrorListModel
				end
			end
		end #operation :delete
	end #swagger_path

	swagger_path '/v1/accounts' do
		operation :post do
			key :description, 'Creates an account. You must call this before all other APIs'
			key :operationId, 'createAccount'
			key :produces, ['application/json']
			parameter do
				key :name, :account
				key :in, :body
				key :description, 'Account to create'
				key :required, true
				schema do
					key :type, :object
					key :required, [:name, :store_api_key]
					property :name do
						key :type, :string
					end
					property :email do
						key :type, :string
					end
					property :store_api_key do
						key :type, :boolean
					end
				end
			end
			response 200 do
				key :description, 'The account_id and api_key of the newly-created account. YOU MUST STORE THESE IN A SAFE PLACE AND NOT LOSE THEM.'
				schema do
					key :type, :object
					property :account_id do
						key :type, :string
						key :format, :uuid
					end
					property :api_key do
						key :type, :string
					end
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


	respond_to :json

	before_filter :authenticate_account!, except: [:create]

	@@store_account_key_warning = 'You elect to have us NOT store a copy of your api_key and that you take FULL RESPONSIBILITY for not losing your api_key. If you lose your api_key, ALL of the user passwords you have stored on this server will BE LOST PERMANENTLY. There is ABSOLUTELY NO WAY for us to recover the user passwords without your api_key. Really.'
	@@store_account_key_error = 'store_api_key is required and must have a value of "true" or "false". If "true": We will store a copy of your api_key in case you lose it. This is less secure in the unlikely event our server is compromised. If "false": ' + @@store_account_key_warning 


	def show
		result = {
			:id => @account.id,
			:name => @account.name,
			:email => @account.email,
			:store_api_key => !@account.account_key.nil?,
			:created_date => @account.created_date,
			#:TEST_active => @account.active,
			#:TEST_pass_salt => decrypt('ECB', [@account_key].pack('H*'), @account.pass_salt).unpack('H*')[0],
			#:TEST_account_key => @account.account_key.nil? ? '' : decrypt('ECB', BaseApiController.application_key, @account.account_key).unpack('H*')[0],
			:TEST_user_count => decrypt('CBC', BaseApiController.application_key, @account.user_count)
		}

		render json: result
	end


	def create
		store_account_key = parse_bool(@json['store_api_key'])

		if store_account_key.nil?
			render json: { :errors => [@@store_account_key_error] }, status: 422
			return
		end

		account = Account.new
		account.id = SecureRandom.uuid
		account.name = @json['name']
		account.email = @json['email']
		account.user_count = encrypt('CBC', BaseApiController.application_key, '0')
		account.active = 1
		#todo: credit_card_token

		account_key_raw = SecureRandom.random_bytes(32)
		account_key_hex = account_key_raw.unpack('H*')[0]

		if store_account_key
			# ECB should only ever be used on the raw bytes of randomly generated keys/salts which are divisible by 16 bytes
			account.account_key = encrypt_account_key(account_key_raw)
		end
		account.account_key_hash = Digest::SHA256.hexdigest(account_key_raw)

		pass_salt_raw = SecureRandom.random_bytes(32)
		# ECB should only ever be used on the raw bytes of randomly generated keys/salts which are divisible by 16 bytes
		account.pass_salt = encrypt('ECB', account_key_raw, pass_salt_raw)

		result = {
			:account_id => account.id,
			:api_key => account.id + ':' + account_key_hex,
			:message => "Backup your api_key to a safe place. It is required for all future requests. " + 
				(!store_account_key ? @@store_account_key_warning : '')
			#:TEST_pass_salt => pass_salt_raw.unpack('H*')[0]
		}

		if account.save
			audit_account 'C', account
			render json: result, status: 201
		else
			#todo: better validation and error messages
			render json: { :errors => account.errors }, status: 422
		end
	end


	def update
		store_account_key = parse_bool(@json['store_api_key'])

		if store_account_key.nil?
			store_account_key = !@account.account_key.nil?
		end

		updated_values = {
			:name => @json['name'].nil? ? @account.name : @json['name'],
			:email => @json['email'].nil? ? @account.email : @json['email'],
			:account_key => store_account_key ? encrypt_account_key([@account_key].pack('H*')) : nil
		}
		#todo: credit_card_token
		
		@account.update(updated_values)

		if @account.save
			audit_account 'U', @account

			if !store_account_key
				render json: { :message => @@store_account_key_warning }, status: 200
			else
				render nothing: true, status: 204
			end
		else
			#todo: better validation and error messages
			render json: { :errors => @account.errors }, status: 422
		end
	end


	def destroy
		@account.active = 0

		if @account.save
			audit_account 'D', @account
			render nothing: true, status: 204
		else
			#todo: better validation and error messages
			render json: { :errors => @account.errors }, status: 422
		end
	end


protected
	def audit_account(action, account)
		values = {
			:account_id => account.id,
			:name => account.name,
			:email => account.email,
			:credit_card_token => account.credit_card_token,
			:account_key_hash => account.account_key_hash,
			:pass_salt => account.pass_salt,
			:active => account.active,
			:action => action
		} 

		history = AccountHistory.new(values)
		history.save  #todo: log error?
	end


	def parse_bool(value)
		if value.nil?
			return nil
		end

		if !!value == value
			return value
		end
		
		if value == 1 || value.strip.downcase == 'true'
			return true
		elsif value == 0 || value.strip.downcase == 'false'
			return false
		end

		return nil
	end


	def encrypt_account_key(account_key_raw)
		return encrypt('ECB', BaseApiController.application_key, account_key_raw) 
	end
end

end
end
