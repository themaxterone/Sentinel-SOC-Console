import os

from auth import AUTH_MODE
from webapp import app

if __name__ == "__main__":
    if AUTH_MODE == "local":
        print("[READY] SOC listening at http://127.0.0.1:5000", flush=True)
        app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
    else:
        from waitress import serve

        host = os.environ.get("SOC_BIND_HOST", "127.0.0.1")
        port = int(os.environ.get("PORT", "5000"))
        print(f"[READY] SOC listening at http://{host}:{port}", flush=True)
        serve(
            app,
            host=host,
            port=port,
            threads=max(4, int(os.environ.get("SOC_HTTP_THREADS", "16"))),
        )