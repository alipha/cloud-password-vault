require 'fast_secure_compare/fast_secure_compare'
require 'argon2'

module Api
module V1

class BaseApiController < ApplicationController

    before_filter :start_request

	#TODO: This is for the default password of "admin". UPDATE YOUR PASSWORD USING /api/v1/admin/compute_admin_hash
	@@admin_password_hash_hash = '31e2b295a04c60c59d01193be6bd11f152142c7277baacf160cd37d1d2ea2bf0'


	def self.application_key
		return @@application_key ||= ''
	end


	def self.application_salt
		return @@application_salt ||= ''
	end


	def self.initialize(admin_password_hash)
		if !FastSecureCompare.compare(@@admin_password_hash_hash, Digest::SHA256.hexdigest([admin_password_hash].pack('H*')))
			return false
		end

		@@application_key = [admin_password_hash[0..63]].pack('H*')
		@@application_salt = [admin_password_hash[64..127]].pack('H*')
		return true
	end


    protected
        def authenticate_account!
	        if !load_account
				api_key_str = (@api_key.nil? ? "(none provided)" : @api_key)
				response = { :errors => ["401 Unauthorized: The provided api_key is not valid: " + api_key_str] }
    	        render json: response, status: :unauthorized
    	    end
	    end


    	def start_request
			if BaseApiController.application_key == ''
				render json: { :errors => ["500 Internal server error: The application needs to be initialized."] }, status: 500
				return
			end

			parse_request
		end


		def parse_request
			@json = BaseApiController.parse_request(request, params)
		end


		def self.parse_request(request, params)
			if request.body.size > 2
	        	json = JSON.parse(request.body.read)
			else
				json = {}
			end

			json = json.merge(params)
			json.delete('controller')
			json.delete('action')
			return json
        end


		def load_account
			@api_key = @json["api_key"]

			if !@api_key
				return false
			end

			@account_id, @account_key = @api_key.split(':', 2)

			@account = Account.find_by_id(@account_id)

			if @account.nil? || @account.active == 0
				return false
			end

			provided_hash = Digest::SHA256.hexdigest([@account_key].pack('H*'))

			if !FastSecureCompare.compare(@account.account_key_hash, provided_hash)
				@account = nil
				return false
			end

			return true
		end


		def encrypt(mode, key, text)
			cipher = OpenSSL::Cipher.new('AES-256-' + mode)
	        cipher.encrypt
    	    cipher.key = key

			if mode != 'ECB'
	        	iv = cipher.random_iv.unpack('H*')[0]
			else
				iv = ''
				cipher.padding = 0
			end

			return iv + (cipher.update(text) + cipher.final).unpack('H*')[0]
		end


		def decrypt(mode, key, encrypted_hex)
			cipher = OpenSSL::Cipher.new('AES-256-' + mode)
			cipher.decrypt
			cipher.key = key 

			if mode != 'ECB'
				cipher.iv = [encrypted_hex[0..31]].pack('H*')
				encrypted_hex = encrypted_hex[32..-1]
			else
				cipher.padding = 0
			end

			return cipher.update([encrypted_hex].pack('H*')) + cipher.final
		end


		def argon2_encode(password, random_salt, m_cost, secret)
			return BaseApiController.argon2_encode(password, random_salt, m_cost, secret)
		end


		def self.argon2_encode(password, random_salt, m_cost, secret)
			if random_salt
				salt = SecureRandom.random_bytes(16)
			else
				salt = 'A' * 16
			end

			return Argon2::Engine.hash_argon2i_encode(password, salt, 3, m_cost, secret)
		end


		def argon2_verify(password, hash, secret)
			Argon2::Engine.argon2i_verify(password, hash, secret)
		end


		def self.argon2i_raw(password, salt, t_cost, m_cost, out_len)
		    result = ''
		    FFI::MemoryPointer.new(:char, out_len) do |buffer|
				ret = Argon2::Ext.argon2i_hash_raw(t_cost, 1 << m_cost, 1, password,
					password.length, salt, salt.length,
					buffer, out_len)
				raise Argon2::ArgonHashFail, Argon2::ERRORS[ret.abs] unless ret == 0
				result = buffer.read_string(out_len)
			end
		    result.unpack('H*').join
		end
end

end
end
