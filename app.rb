require 'sinatra'
require 'json'
require 'jwt' # json web token
require 'octokit'
require 'active_support/all'

begin
  GITHUB_APP_ID      = ENV.fetch('GITHUB_APP_ID')
  GITHUB_PRIVATE_KEY = ENV.fetch('GITHUB_APP_PRIVATE_KEY',
                                           File.read('private-key.pem'))
  APP_NAME           = ENV.fetch('APP_NAME', 'changelog_manager')
rescue KeyError
  $stderr.puts "To run this script, please set the following environment variables:"
  $stderr.puts "- GITHUB_APP_ID: GitHub App ID"
  $stderr.puts "- GITHUB_APP_PRIVATE_KEY: GitHub App Private Key"
  exit 1
end


configure do
  # logging is enabled by default in classic style applications,
  # so `enable :logging` is not needed
  file = File.new("#{settings.root}/log/#{settings.environment}.log", 'a+')
  file.sync = true
  use Rack::CommonLogger, file
end

post '/event_handler' do
  # request.body.rewind
  # payload_body = request.body.read
  # verify_signature(payload_body) # will return 500 error if bad

  webhook_data = JSON.parse(request.body.read)
  case request.env['HTTP_X_GITHUB_EVENT']
  when 'pull_request'
    # get that out of webhook data...
    installation_id = get_installation_id(webhook_data)
    client = Octokit::Client.new(access_token: get_access_token(installation_id))
    parse_pr_payload(webhook_data, client)
  when 'installation'
    parse_installation_payload(webhook_data)
  end
end




helpers do
  def process_pull_request(pull_request, client)
    # logger.info "processing pull_request:\n#{pull_request.inspect}"
    repo   = pull_request['base']['repo']['full_name']
    number = pull_request['number']
    sha    = pull_request['head']['sha']
    url    = pull_request['html_url']

    logger.info "processing pull_request: #{number} #{url}"



    # pull_request_files(repo, number, options = {}) ⇒ Array<Sawyer::Resource> (also: #pull_files)
    # List files on a pull request.
    files = client.pull_request_files(repo, number).map{|h|h['filename']}
    got_changelog_files =
      files.any?{|f|!!f.match(/^\.changelog_entries\/[a-f0-9]{32}\.json$/)}
      # files.any?{|f|f.match?(/^\.changelog_entries\/[a-f0-9]{32}\.json$/)} # ruby 2.4
      logger.debug ": #{files.inspect}"

    create_status(got_changelog_files, repo, sha, client)

  end

  def create_status(files_found, repo, sha, client)
    state       = files_found ? 'success' : 'failure'
    description = "#{files_found ? '' : 'no '} changelog entry found"
    #create_status(repo, sha, state, options = {}) ⇒ Sawyer::Resource
    client.create_status(
      repo,
      sha,
      state, # The state: pending, success, failure, error
      {description: description,
       context: APP_NAME}
       # context is what comes before the description
       # default — no changelog entry found
       # <context> - <description>
    )
  end
  # To authenticate as a GitHub App, generate a private key. Use this key to sign
  # a JSON Web Token (JWT), and encode using the RS256 algorithm. GitHub checks
  # that the request is authenticated by verifying the token with the
  # integration's stored public key. https://git.io/vQOLW
  def get_jwt_token
    private_key = OpenSSL::PKey::RSA.new(GITHUB_PRIVATE_KEY)

    payload = {
      # issued at time
      iat: Time.now.to_i,
      # JWT expiration time (10 minute maximum)
      exp: 5.minutes.from_now.to_i,
      # GitHub App's identifier
      iss: GITHUB_APP_ID
    }

    JWT.encode(payload, private_key, "RS256")
  end

  def get_installation_id(webhook_data)
    if webhook_data['installation']
      return webhook_data['installation']['id']
    end
    nil
  end
  def get_access_token(installation_id)
      # Get JWT for App and get access token for an installation
    jwt_client = Octokit::Client.new(:bearer_token => get_jwt_token)
    jwt_client.default_media_type = "application/vnd.github.machine-man-preview+json"
    token_hash = jwt_client.create_installation_access_token(installation_id)
    # {:token=>"v1.d1b42909.....711e86ec35361", :expires_at=>2017-08-05 16:59:07 UTC}
    token_hash[:token]
  end

  # def verify_signature(payload_body)
  #   signature = 'sha1=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'),
  #                                                 ENV['SECRET_TOKEN'],
  #                                                 payload_body)
  #   if ! Rack::Utils.secure_compare(signature, request.env['HTTP_X_HUB_SIGNATURE'])
  #     return halt 500, "Signatures didn't match!"
  #   end
  # end

  def parse_pr_payload(payload, client)
    if %w(opened edited reopened synchronize).include? payload['action']
      pull_request = payload['pull_request']
      if pull_request['state'] == 'open'
        process_pull_request(pull_request, client)
      end
    end
  end

  # A GitHub App is installed by a user on one or more repositories.
  # The installation ID is passed in the webhook event. This returns all
  # repositories this installation has access to.
  #--------------------------------------
  #  When an App is added by a user, it will generate a webhook event. Parse an
  # `installation` webhook event, list all repositories this App has access to,
  # and create an issue.
  def parse_installation_payload(webhook_data)
    if webhook_data["action"] == "created" || webhook_data["action"] == "added"
      # installation_id = webhook_data["installation"]["id"]
      installation_id = get_installation_id(webhook_data)

      # Get JWT for App and get access token for an installation
      jwt_client = Octokit::Client.new(:bearer_token => get_jwt_token)
      jwt_client.default_media_type = "application/vnd.github.machine-man-preview+json"
      app_token = jwt_client.create_app_installation_access_token(installation_id)

      # Create octokit client that has access to installation resources
      @client = Octokit::Client.new(access_token: app_token[:token] )
      @client.default_media_type = "application/vnd.github.machine-man-preview+json"

      #TODO LET THEM KNOW IT WORKED
    end
  end

end




