"""Part 6 operator warning popup assets for the Part 1 HMI."""

from flask import Blueprint


warning_popup = Blueprint(
    "p6_warning",
    __name__,
    static_folder="static",
    static_url_path="/p6/static",
)
