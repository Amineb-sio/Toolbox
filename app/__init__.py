from flask import Flask

def create_app():
    app = Flask(__name__)

    # Configuration Flask
    app.config["SECRET_KEY"] = "votre_clé_secrète"

    # Enregistrer les blueprints (modules Flask)
    from .views import main

    app.register_blueprint(main)

    return app
