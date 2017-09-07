import json
import os
import unittest
import logging
import sys


logging.basicConfig(stream=sys.stderr)
log = logging.getLogger("")
log.setLevel(logging.DEBUG)


THIS_DIRECTORY = os.path.dirname(__file__)

PULL_REQUEST_HEADER = {"Request method": "POST",
                        "content-type": "application/json",
                        "User-Agent": "GitHub-Hookshot/8e9b331",
                        "X-GitHub-Delivery": "7b0bc620-8bff-11e7-9f2b-2df35b020fe6",
                        "X-GitHub-Event": "pull_request"}


class TestChangelogManagerServer(unittest.TestCase):
    def setUp(self):
        from application import application
        self.app = application.test_client()
        self.app.testing = True

    def test_request_with_changelog(self):
        result = self.app.post('/event_hook',
                               headers=PULL_REQUEST_HEADER,
                               data=open(os.path.join(THIS_DIRECTORY, 'test', 'pull_request_with_changelog.json')))

        data = json.loads(result.data)
        self.assertTrue(any([x['state'] == 'failure' for x in data]))
        self.assertFalse(all([x['state'] == 'failure' for x in data]))

    def test_request_without_changelog(self):
        result = self.app.post('/event_hook',
                               headers=PULL_REQUEST_HEADER,
                               data=open(os.path.join(THIS_DIRECTORY, 'test', 'pull_request_without_changelog.json')))

        data = json.loads(result.data)
        self.assertFalse(any([x['state'] == 'success' for x in data]))
        self.assertTrue(all([x['state'] == 'failure' for x in data]))
