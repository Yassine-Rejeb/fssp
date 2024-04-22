# Import your Flask application instance
from app import app
from gunicorn.app.base import BaseApplication
from gunicorn.config import Config

class FlaskGunicornApplication(BaseApplication):
    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        for key, value in self.options.items():
            if key in self.cfg.settings and value is not None:
                self.cfg.set(key.lower(), value)

    def load(self):
        return self.application

if __name__ == "__main__":
    options = {
        "bind": "0.0.0.0:1999",
        "workers": 2,
        "debug": True
    }
    FlaskGunicornApplication(app, options).run()
