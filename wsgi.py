from auth import AUTH_MODE


def create_app():
    if AUTH_MODE != "entra":
        raise RuntimeError("The WSGI deployment entry point requires SOC_AUTH_MODE=entra.")
    from webapp import app
    return app


app = create_app()
