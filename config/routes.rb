Rails.application.routes.draw do
	resources :apidocs, only: [:index]
	namespace :api do
		namespace :v1 do
			resources :accounts, :only => [:show, :create, :update, :destroy]
			post '/user_passwords', to: 'user_passwords#create'
			delete '/user_passwords', to: 'user_passwords#destroy'
			post '/user_passwords/verify', to: 'user_passwords#verify'
			post '/admin/start', to: 'admin#start'
			post '/admin/compute_admin_hash', to: 'admin#compute_hash'
		end
	end
end
