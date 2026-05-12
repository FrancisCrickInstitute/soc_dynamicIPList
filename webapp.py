from flask import Flask, send_file, abort, make_response, send_file
import os

app = Flask(__name__)

FILE_PATH = "Dynamic_IP_BlockList.txt"

print("Looking for file at:", os.path.abspath(FILE_PATH))
print("File exists:", os.path.exists(FILE_PATH))


@app.route("/")
def home():
    return "Flask is working"

@app.route("/Dynamic_IP_BlockList.txt", methods=["GET"])
def download_file():
    if not os.path.exists(FILE_PATH):
        return abort(404, description="File not found")

    response = make_response(
        send_file(
            FILE_PATH,
            as_attachment=True,
            download_name="Dynamic_IP_BlockList.txt",
            conditional=False
        )
    )

    # Optional cache control (still useful)
    response.headers["Cache-Control"] = "no-store"
    return response

def download_file():
    print("DOWNLOAD ROUTE HIT")

    if not os.path.exists(FILE_PATH):
        print("FILE NOT FOUND:", os.path.abspath(FILE_PATH))
        return abort(404, description="File not found")

    return send_file(FILE_PATH, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6000)
