from flask import Flask, send_file, abort, make_response, send_file
import os

app = Flask(__name__)

IP_FILE_PATH = "Dynamic_IP_BlockList.txt"
DOMAIN_FILE_PATH = "Dynamic_Domain_BlockList.txt"

print("Looking for IP file at:", os.path.abspath(IP_FILE_PATH))
print("IP file exists:", os.path.exists(IP_FILE_PATH))
print("Looking for Domain file at:", os.path.abspath(DOMAIN_FILE_PATH))
print("Domain file exists:", os.path.exists(DOMAIN_FILE_PATH))


@app.route("/")
def home():
    return "Flask is working"

@app.route("/<filename>", methods=["GET"])
def download_file(filename):
    file_path = FILES.get(filename)

    if not file_path or not os.path.exists(file_path):
        return abort(404, description="File not found")

    response = make_response(
        send_file(
            file_path,
            as_attachment=True,
            download_name=filename,
            conditional=False
        )
    )

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
