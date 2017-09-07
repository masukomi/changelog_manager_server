import json
from http.client import HTTPSConnection

import requests
from flask import Flask, request, abort, jsonify
from datetime import datetime, timedelta
import time
import re
from flask.views import View
from github import MainClass as GithubClient, InstallationAuthorization
from github.GithubException import BadCredentialsException, UnknownObjectException, GithubException

import jwt

import os

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
private_key_file = os.environ.get('GITHUB_APP_PRIVATE_KEY', 'clmanager.pem')
private_key_file = os.path.join(APP_ROOT, private_key_file)
GITHUB_APP_ID = os.environ.get('GITHUB_APP_ID', '4533')
RE_EXPR = re.compile('^\\.changelog_entries\\/[a-f0-9]{32}\\.json$')

application = Flask(__name__)


class GithubIntegration(object):
    """
    Class to obtain tokens for a GitHub integration. adapted from Upstream to support python3
    """

    def __init__(self, integration_id, private_key):
        """
        :param integration_id: int
        :param private_key: string
        """
        self.integration_id = integration_id
        self.private_key = private_key

    def create_jwt(self):
        """
        Creates a signed JWT, valid for 60 seconds.
        :return:
        """
        now = int(time.time())
        payload = {
            "iat": now,
            "exp": now + 60,
            "iss": self.integration_id
        }
        return jwt.encode(
            payload,
            key=self.private_key,
            algorithm="RS256"
        )

    def get_access_token(self, installation_id, user_id=None):
        """
        Get an access token for the given installation id.
        POSTs https://api.github.com/installations/<installation_id>/access_tokens
        :param user_id: int
        :param installation_id: int
        :return: :class:`github.InstallationAuthorization.InstallationAuthorization`
        """
        body = None
        if user_id:
            body = json.dumps({"user_id": user_id})
        conn = HTTPSConnection("api.github.com")
        jwt_token = self.create_jwt().decode()
        print('jwt_token is' + jwt_token)
        conn.request(
            method="POST",
            url="/installations/{}/access_tokens".format(installation_id),

            headers={
                "Authorization": "Bearer {}".format(jwt_token),
                "Accept": "application/vnd.github.machine-man-preview+json",
                "User-Agent": "PyGithub/Python"
            },
            body=body
        )
        response = conn.getresponse()
        response_text = response.read()

        response_text = response_text.decode('utf-8')

        conn.close()
        if response.status == 201:
            data = json.loads(response_text)
            return InstallationAuthorization.InstallationAuthorization(
                requester=None,  # not required, this is a NonCompletableGithubObject
                headers={},  # not required, this is a NonCompletableGithubObject
                attributes=data,
                completed=True
            )
        elif response.status == 403:
            raise BadCredentialsException(
                status=response.status,
                data=response_text
            )
        elif response.status == 404:
            raise UnknownObjectException(
                status=response.status,
                data=response_text
            )
        raise GithubException(
            status=response.status,
            data=response_text
        )

class EventHookView(View):
    def __init__(self):
        self.data = request.json
        self.installation_id = self._get_installation_id()
        with open(private_key_file, 'rb') as f:
            self.integration = GithubIntegration(GITHUB_APP_ID, f.read().decode())
            self.access_token = self.integration.get_access_token(self.installation_id).token
        print(self.access_token)
        self.client = GithubClient.Github(self.access_token)#client_id=CLIENT_ID, client_secret=CLIENT_SECRET)

        self.installation = self.client.get_installation(self.installation_id)

    def process_pull_request(self):
        repo_id = self.data['pull_request']['base']['repo']['full_name']
        number = self.data['number']
        sha = self.data['pull_request']['head']['sha']
        url = self.data['pull_request']['html_url']
        repository = self.client.get_repo(repo_id)
        commits = repository.get_pull(number).get_commits()
        for commit in commits:
            [print(file, RE_EXPR.match(file.filename)) for file in commit.files]
        return [self.create_status(commit, any(RE_EXPR.match(file.filename) for file in commit.files))
                for commit in commits ]

    def dispatch_request(self):
        if 'X-GitHub-Event' not in request.headers:
            abort(500)
        if request.headers['X-GitHub-Event'] == 'installation':
            return jsonify({'installation_data': self.data})
        elif request.headers['X-GitHub-Event'] == "pull_request":
            result = self.process_pull_request()
            return jsonify(result)

    def _get_installation_id(self):
        return self.data['installation'].get('id', None) if self.data['installation'] and type(
            self.data['installation']) is dict else None

    def create_status(self, commit, has_changelog_entry):
        result = commit.create_status(state='success' if has_changelog_entry else 'failure',
                                      description='{0}changelog entry found'.format(
                                          '' if has_changelog_entry else 'No '))
        return {'status_id':result.id, 'state':result.state}


@application.route('/authorize', methods=['POST', ])
def github_authorize():
    return {
        'status': 'ok'
    }


@application.route('/')
def hello_world():
    return 'Change Log Manager Event Hook'


application.add_url_rule('/event_hook', view_func=EventHookView.as_view('event_'), methods=['POST'])

if __name__ == '__main__':
    import os

    application.run("0.0.0.0", debug=True)
