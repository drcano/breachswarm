"""XXE target — an XML import endpoint whose parser resolves external entities, so a SYSTEM entity
reads a local file and the endpoint reflects it back. The sensitive file path is disclosed in the
service banner (as real apps leak config), so recon -> XXE file-read -> flag.

Solve: POST /api/import with an XXE payload whose entity is file:///tmp/company_secret.flag ->
the response reflects the file contents (the flag). Deliberately vulnerable. Flask + lxml.
"""
import os
from flask import Flask, request, jsonify, Response
from lxml import etree

app = Flask(__name__)
FLAG = "flag{xxe_3xt3rnal_3nt1ty_f1l3_r34d}"
SECRET_PATH = "/tmp/company_secret.flag"
try:
    with open(SECRET_PATH, "w") as f:
        f.write(FLAG + "\n")
except Exception:
    pass


@app.route("/")
def index():
    # banner discloses the config path (recon surface) — the file the XXE should target
    return (f"Shipment Import API v3. POST an XML document to /api/import (Content-Type text/xml) "
            f"and I'll parse and echo its <title>. Server config: SECRET_STORE={SECRET_PATH}")


@app.route("/api/import", methods=["POST"])
def do_import():
    body = request.get_data()
    if not body:
        return jsonify({"error": "empty body; POST an XML document"}), 400
    try:
        # VULN: resolve_entities + load_dtd + no_network=False -> external SYSTEM entities resolve
        # (including file://), so &xxe; injects local file contents.
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
        root = etree.fromstring(body, parser=parser)
        title = root.findtext(".//title") if root is not None else None
        if title is None:
            title = root.text if root is not None else ""
        return Response(f"<result><parsed-title>{title}</parsed-title></result>",
                        mimetype="application/xml")
    except Exception as e:
        return jsonify({"error": "parse error", "detail": str(e)[:200]}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
