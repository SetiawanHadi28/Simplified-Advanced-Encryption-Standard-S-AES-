# -*- coding: utf-8 -*-
"""
app.py
======
Aplikasi Flask untuk simulasi kriptografi Simplified AES (S-AES).
Menyediakan halaman Home, Encrypt, Decrypt, About S-AES, dan References,
lengkap dengan visualisasi step-by-step dari seluruh proses algoritma.
"""

from flask import Flask, render_template, request
import saes

app = Flask(
    __name__,
    static_folder="static",
    template_folder="templates"
)
app.config["JSON_AS_ASCII"] = False


# --------------------------------------------------------------------------
# JINJA FILTERS — dipakai di template untuk memformat nilai biner/hex
# --------------------------------------------------------------------------

@app.template_filter("bin4")
def bin4(n):
    return format(int(n), "04b")


@app.template_filter("bin8")
def bin8(n):
    return format(int(n), "08b")


@app.template_filter("bin16")
def bin16(n):
    return format(int(n), "016b")


@app.template_filter("hex1")
def hex1(n):
    return format(int(n), "X")


@app.template_filter("hex2")
def hex2(n):
    return format(int(n), "02X")


@app.template_filter("hex4")
def hex4(n):
    return format(int(n), "04X")


@app.template_filter("state_int")
def state_int_filter(state):
    return saes.state_to_int(state)


# --------------------------------------------------------------------------
# CONTEXT PROCESSOR — data yang selalu tersedia di semua template
# --------------------------------------------------------------------------

@app.context_processor
def inject_globals():
    return {
        "sbox": saes.SBOX,
        "inv_sbox": saes.INV_SBOX,
        "rcon1": saes.RCON1,
        "rcon2": saes.RCON2,
        "app_name": "S-AES Simulator",
    }


# --------------------------------------------------------------------------
# ROUTES — HALAMAN
# --------------------------------------------------------------------------

@app.route("/")
def home():
    return render_template("home.html", active_page="home")


@app.route("/encrypt", methods=["GET", "POST"])
def encrypt_page():
    result = None
    error = None
    plaintext = ""
    key = ""

    if request.method == "POST":
        plaintext = request.form.get("plaintext", "").strip()
        key = request.form.get("key", "").strip()

        if not saes.is_valid_binary16(plaintext):
            error = "Plaintext harus berupa bilangan biner sepanjang tepat 16 bit (hanya karakter 0 dan 1)."
        elif not saes.is_valid_binary16(key):
            error = "Key harus berupa bilangan biner sepanjang tepat 16 bit (hanya karakter 0 dan 1)."
        else:
            result = saes.encrypt(plaintext, key)

    return render_template(
        "encrypt.html",
        active_page="encrypt",
        result=result,
        error=error,
        plaintext=plaintext,
        key=key,
    )


@app.route("/decrypt", methods=["GET", "POST"])
def decrypt_page():
    result = None
    error = None
    ciphertext = ""
    key = ""

    if request.method == "POST":
        ciphertext = request.form.get("ciphertext", "").strip()
        key = request.form.get("key", "").strip()

        if not saes.is_valid_binary16(ciphertext):
            error = "Ciphertext harus berupa bilangan biner sepanjang tepat 16 bit (hanya karakter 0 dan 1)."
        elif not saes.is_valid_binary16(key):
            error = "Key harus berupa bilangan biner sepanjang tepat 16 bit (hanya karakter 0 dan 1)."
        else:
            result = saes.decrypt(ciphertext, key)

    return render_template(
        "decrypt.html",
        active_page="decrypt",
        result=result,
        error=error,
        ciphertext=ciphertext,
        key=key,
    )


@app.route("/about")
def about_page():
    return render_template("about.html", active_page="about")


@app.route("/references")
def references_page():
    mix_matrix = [[1, 4], [4, 1]]
    inv_mix_matrix = [[9, 2], [2, 9]]
    return render_template(
        "references.html",
        active_page="references",
        mix_matrix=mix_matrix,
        inv_mix_matrix=inv_mix_matrix,
    )


# --------------------------------------------------------------------------
# ERROR HANDLERS
# --------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
