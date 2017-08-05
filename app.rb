require 'sinatra'
require 'json'
require 'octokit'

configure do
  # logging is enabled by default in classic style applications,
  # so `enable :logging` is not needed
  file = File.new("#{settings.root}/log/#{settings.environment}.log", 'a+')
  file.sync = true
  use Rack::CommonLogger, file
end
# !!! DO NOT EVER USE HARD-CODED VALUES IN A REAL APP !!!
# Instead, set and test environment variables, like below
ACCESS_TOKEN = ENV['GITHUB_ACCESS_TOKEN']

before do
  @client ||= Octokit::Client.new(:access_token => ACCESS_TOKEN)
end

post '/event_handler' do
  payload = JSON.parse(params[:payload])

  case request.env['HTTP_X_GITHUB_EVENT']
  when 'pull_request'
    # logger.info "received a pull request event"
    if %w(opened edited reopened synchronize).include? payload['action']
      pull_request = payload['pull_request']
      if pull_request['state'] == 'open'
        process_pull_request(pull_request, logger)
      else
        logger.debug "ignoring #{pull_request['number']}. Isn't open."
      end
    else
      logger.info "unexpected action: #{payload['action']}"
    end
  end
end

helpers do
  def process_pull_request(pull_request, logger)
    # logger.info "processing pull_request:\n#{pull_request.inspect}"
    repo   = pull_request['base']['repo']['full_name']
    number = pull_request['number']
    sha    = pull_request['head']['sha']
    url    = pull_request['html_url']
    logger.info "processing pull_request: #{number} #{url}"

    # puts "It's #{pull_request['title']}"

    #pull_request_files(repo, number, options = {}) ⇒ Array<Sawyer::Resource> (also: #pull_files)
    # List files on a pull request.
    files = @client.pull_request_files(repo, number).map{|h|h['filename']}
    got_changelog_files =
      files.any?{|f|!!f.match(/^\.changelog_entries\/[a-f0-9]{32}\.json$/)}
      # files.any?{|f|f.match?(/^\.changelog_entries\/[a-f0-9]\.json$/)} # ruby 2.4
      logger.info ": #{files.inspect}"

    #create_status(repo, sha, state, options = {}) ⇒ Sawyer::Resource
    state       = got_changelog_files ? 'success' : 'failure'
    description = "#{got_changelog_files ? '' : 'no '} changelog entry found"
    @client.create_status(
      repo,
      sha,
      state, # The state: pending, success, failure, error
      {description: description,
       context: 'changelog_manager'}
       # context is what comes before the description
       # default — no changelog entry found
       # <context> - <description>
    )
  end
end


