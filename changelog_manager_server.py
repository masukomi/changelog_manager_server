from flask import Flask

app = Flask(__name__)


@app.route('/')
def hello_world():
    return 'Hello World!'

@app.route('/event_hook')
def github_event_hook():
    return {
        'status': 'ok'}


if __name__ == '__main__':
    app.run()
