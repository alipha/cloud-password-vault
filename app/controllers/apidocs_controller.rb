class ApidocsController < ActionController::Base
    include Swagger::Blocks

    swagger_root do
        key :swagger, '2.0'
        info do
            key :version, '1.0.0'
            key :title, 'Cloud Password Vault for Businesses'
            key :description, 'A simple interface for securely storing and verifying user passwords.'
#            key :termsOfService, 'http://helloreverb.com/terms/'
            contact do
                key :name, 'Alipha (Kevin Spinar)'
            end
#            license do
#                key :name, 'MIT'
#            end
        end
#        tag do
#           key :name, 'pet'
#           key :description, 'Pets operations'
#           externalDocs do
#               key :description, 'Find more info here'
#               key :url, 'https://swagger.io'
#           end
#       end
        key :host, 'alipha.cloudapp.net'
        key :basePath, '/api'
        key :consumes, ['application/json']
        key :produces, ['application/json']
    end

    # A list of all classes that have swagger_* declarations.
    SWAGGERED_CLASSES = [
        Api::V1::AccountsController,
		Api::V1::UserPasswordsController,
		Api::V1::AdminController,
        Account,
		UserPassword,
        ErrorListModel,
        self,
    ].freeze

    def index
        render json: Swagger::Blocks.build_root_json(SWAGGERED_CLASSES)
    end
end
