"""
routes_submit.py — HTTP surface for worksheet submission and rubric grading.

The last piece of the move off Google. Same identity model as the graded quiz:
a one-time code per (assignment, student), no student password anywhere.

THE DOWNLOAD ENDPOINT IS THE SECURITY-CRITICAL ROUTE
    Everything a student uploads is attacker-controlled bytes, and the teacher
    who reads it is logged in with the session that can see and change every
    mark. So `download` never renders anything inline:

      * `Content-Disposition: attachment` with a quoted, filtered filename
      * `Content-Type: application/octet-stream` — never the uploaded type, and
        never guessed from the extension
      * `X-Content-Type-Options: nosniff` so a browser cannot decide for itself
      * a `sandbox` CSP with no allowances, so even if a browser were coaxed
        into rendering it, there is no script, no plugin and no same-origin

    An uploaded `.svg` or `.html` served inline from this origin is stored XSS
    into the grading account. The deliverables are screenshots and PDFs, so
    refusing to render costs nothing.
"""

from __future__ import annotations

import io
import json
import os
import re

# CSV exports go to a file teachers open in Excel/Sheets — the stdlib csv
# module doesn't neutralize a leading =/+/-/@, which spreadsheet apps can read
# as a live formula (CWE-1236). defusedcsv prefixes it. The alias is not
# cosmetic: Semgrep's csv-writer-injection rule matches the name `csv.writer`
# syntactically, so importing defusedcsv *as* `csv` still trips it — the
# rename is what clears CI.
from defusedcsv import csv as safe_csv

from flask import (Blueprint, abort, current_app, redirect, render_template,
                   request, session, url_for, Response)

import auth
import submission as S

bp = Blueprint("submit", __name__)


def _db():
    return current_app.config["GET_DB"]()


def _now():
    return current_app.config["NOW"]()


def _csrf():
    return current_app.config["ISSUE_CSRF"]()


def _check_csrf():
    current_app.config["CHECK_CSRF"]()


def _uploads():
    return current_app.config["UPLOAD_DIR"]


def _owned(assignment_id):
    a = S.get_assignment(_db(), assignment_id)
    if a is None or a["teacher_id"] != auth.current_teacher_id():
        abort(404)                # 404 not 403 — probing must reveal nothing
    return a


# --- teacher ---------------------------------------------------------------

@bp.route("/work")
@auth.login_required
def index():
    rows = _db().execute(
        "SELECT a.*,"
        " (SELECT COUNT(*) FROM submit_codes c WHERE c.assignment_id = a.id) AS issued,"
        " (SELECT COUNT(*) FROM submissions s WHERE s.assignment_id = a.id"
        "    AND s.submitted_at IS NOT NULL) AS handed_in"
        " FROM assignments a WHERE a.teacher_id = ? ORDER BY a.course_slug, a.id DESC",
        (auth.current_teacher_id(),)).fetchall()
    return render_template("work_index.html", assignments=rows, csrf_token=_csrf())


@bp.route("/work/new", methods=["GET", "POST"])
@auth.login_required
def new():
    if request.method == "GET":
        return _new_form()
    _check_csrf()
    f = request.form
    rubric = []
    for name, pts in zip(f.getlist("criterion"), f.getlist("max")):
        if not name.strip():
            continue
        try:
            weight = float(pts or 0)
        except (TypeError, ValueError):
            # A malformed form must not 500. This is reachable from a hand-built
            # POST, and a stack trace is both a bad experience and an
            # information leak.
            return _new_form(error=f"“{pts}” isn't a number of points."), 200
        if weight <= 0:
            return _new_form(error=f"“{name.strip()}” needs points above 0."), 200
        rubric.append({"criterion": name.strip()[:120], "max": weight})

    try:
        aid = S.create_assignment(
            _db(), teacher_id=auth.current_teacher_id(),
            title=f.get("title", "").strip() or "Worksheet",
            week_slug=(f.get("week_slug") or "").strip() or None,
            instructions=f.get("instructions", "").strip()[:8000],
            due_at=(f.get("due_at") or "").strip() or None,
            rubric=rubric or None, now=_now(),
            course_slug=(f.get("course_slug") or "").strip() or None)
    except ValueError as exc:
        return _new_form(error=str(exc)), 200
    return redirect(url_for("submit.detail", assignment_id=aid))


def _new_form(error=None):
    import content as C
    courses = C.list_courses()
    # The week dropdown must list the weeks of the course being picked. With one
    # course that is unambiguous; with several, a flat list of every course's
    # weeks would let an assignment link to another course's material — so it is
    # scoped to the default and the picker is the thing that narrows it.
    return render_template("work_new.html", weeks=C.list_weeks(),
                           courses=courses,
                           rubric=S.DEFAULT_RUBRIC, csrf_token=_csrf(), error=error)


@bp.route("/work/<int:assignment_id>")
@auth.login_required
def detail(assignment_id):
    a = _owned(assignment_id)
    return render_template("work_detail.html", a=a, rubric=S.rubric_of(a),
                           total=S.total_points(a),
                           rows=S.gradebook_rows(_db(), assignment_id),
                           csrf_token=_csrf())


@bp.route("/work/<int:assignment_id>/codes", methods=["POST"])
@auth.login_required
def codes(assignment_id):
    _owned(assignment_id)
    _check_csrf()
    ids = [s.strip() for s in
           (request.form.get("student_ids") or "").replace(",", "\n").split("\n")]
    ids = [s for s in ids if s and not s.startswith("#")]
    if ids:
        S.issue_codes(_db(), assignment_id, ids, _now())
    return redirect(url_for("submit.detail", assignment_id=assignment_id))


@bp.route("/work/<int:assignment_id>/codes.csv")
@auth.login_required
def codes_csv(assignment_id):
    _owned(assignment_id)
    rows = _db().execute("SELECT student_id, code FROM submit_codes"
                         " WHERE assignment_id = ? ORDER BY student_id",
                         (assignment_id,)).fetchall()
    buf = io.StringIO()
    w = safe_csv.writer(buf)
    w.writerow(["student_id", "code"])
    for r in rows:
        w.writerow([r["student_id"], r["code"]])
    return Response(buf.getvalue(), mimetype="text/csv", headers={
        "Content-Disposition": f'attachment; filename="work-codes-{assignment_id}.csv"'})


@bp.route("/work/<int:assignment_id>/mark/<int:submission_id>", methods=["GET", "POST"])
@auth.login_required
def mark(assignment_id, submission_id):
    a = _owned(assignment_id)
    sub = _db().execute("SELECT * FROM submissions WHERE id = ? AND assignment_id = ?",
                        (submission_id, assignment_id)).fetchone()
    if sub is None:
        abort(404)

    if request.method == "POST":
        _check_csrf()
        for i, row in enumerate(S.rubric_of(a)):
            raw = request.form.get(f"points_{i}", "").strip()
            S.grade(_db(), submission_id, row["criterion"],
                    None if raw == "" else float(raw),
                    request.form.get(f"comment_{i}", ""), _now())
        return redirect(url_for("submit.detail", assignment_id=assignment_id))

    marks = {r["criterion"]: r for r in _db().execute(
        "SELECT * FROM rubric_scores WHERE submission_id = ?",
        (submission_id,)).fetchall()}
    earned, possible, complete = S.score(_db(), submission_id)
    return render_template("work_mark.html", a=a, sub=sub,
                           rubric=S.rubric_of(a), marks=marks,
                           files=S.list_files(_db(), submission_id),
                           late=S.is_late(_db(), sub),
                           score=(earned, possible, complete),
                           csrf_token=_csrf())


@bp.route("/work/<int:assignment_id>/results.csv")
@auth.login_required
def results_csv(assignment_id):
    _owned(assignment_id)
    buf = io.StringIO()
    w = safe_csv.writer(buf)
    w.writerow(["student_id", "submitted", "late", "files", "earned", "possible",
                "percent", "fully_graded"])
    for r in S.gradebook_rows(_db(), assignment_id):
        w.writerow([r["student_id"], int(r["submitted"]), int(r["late"]), r["files"],
                    "" if r["earned"] is None else f"{r['earned']:.2f}",
                    "" if r["possible"] is None else f"{r['possible']:.2f}",
                    "" if r["percent"] is None else f"{r['percent']:.2f}",
                    int(r["fully_graded"])])
    return Response(buf.getvalue(), mimetype="text/csv", headers={
        "Content-Disposition": f'attachment; filename="work-{assignment_id}.csv"'})


@bp.route("/work/<int:assignment_id>/release", methods=["POST"])
@auth.login_required
def release(assignment_id):
    _owned(assignment_id)
    _check_csrf()
    _db().execute("UPDATE assignments SET released = NOT released WHERE id = ?",
                  (assignment_id,))
    _db().commit()
    return redirect(url_for("submit.detail", assignment_id=assignment_id))


# --- the one security-critical route --------------------------------------

_FILENAME_OK = re.compile(r'[^A-Za-z0-9._ ()฀-๿-]')


@bp.route("/work/file/<int:file_id>")
def download(file_id):
    """Download an uploaded file. NEVER rendered inline — see the module docstring.

    Authorised either as the owning teacher, or as the student whose session
    holds that submission. Both checks are on the server; the URL carries no
    capability of its own.
    """
    row = _db().execute(
        "SELECT f.*, s.assignment_id, s.id AS sub_id, s.student_id, a.teacher_id"
        " FROM submission_files f"
        " JOIN submissions s ON s.id = f.submission_id"
        " JOIN assignments a ON a.id = s.assignment_id"
        " WHERE f.id = ?", (file_id,)).fetchone()
    if row is None:
        abort(404)

    is_teacher = auth.current_teacher_id() == row["teacher_id"]
    is_owner = session.get("submission_id") == row["sub_id"]
    if not (is_teacher or is_owner):
        abort(404)

    got = S.open_file(_db(), file_id, _uploads())
    if got is None:
        abort(404)
    display, data = got

    # Strip anything that could confuse the header parse. RFC 6266 filename*
    # would be nicer for Thai names, but a conservative ASCII-safe fallback
    # plus UTF-8 filename* covers both without hand-rolling encoding rules.
    safe = _FILENAME_OK.sub("_", display) or "download"
    from urllib.parse import quote
    return Response(data, headers={
        # never the uploaded content type, never guessed from the extension
        "Content-Type": "application/octet-stream",
        "Content-Disposition":
            f'attachment; filename="{safe.encode("ascii", "replace").decode()}"; '
            f"filename*=UTF-8''{quote(display)}",
        "X-Content-Type-Options": "nosniff",
        # belt and braces: if a browser rendered it anyway, nothing runs
        "Content-Security-Policy": "sandbox; default-src 'none'",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "private, no-store",
    })


# --- student ---------------------------------------------------------------

def _current():
    sid = session.get("submission_id")
    if sid is None:
        return None
    return _db().execute("SELECT * FROM submissions WHERE id = ?", (sid,)).fetchone()


@bp.route("/submit", methods=["GET", "POST"])
def entry():
    if request.method == "GET":
        return render_template("submit_entry.html", csrf_token=_csrf(), error=None)
    _check_csrf()
    raw = request.form.get("code")
    # Classify BEFORE attempting either table's redeem() — see the mirror of
    # this in routes_assess.py's quiz_entry() for why: a code colliding
    # across attempt_codes and submit_codes must never silently authenticate
    # as whichever side's redeem() this route happens to call.
    import codes
    try:
        kind = codes.find_kind(_db(), raw)
    except RuntimeError:
        current_app.logger.exception("codes.find_kind: code in both tables")
        kind = None
    if kind == "quiz":
        # A quiz code typed into this box by mistake. Unlike the /quiz
        # direction, this rescue's own redeem() CAN still fail (already
        # submitted, window closed) — that failure must reach the page as
        # itself, not as this box's generic "not valid".
        import assessment as A
        try:
            att = A.redeem(_db(), raw, _now())
        except A.AttemptError as quiz_exc:
            return render_template("submit_entry.html", csrf_token=_csrf(),
                                   error=str(quiz_exc), code=raw), 200
        session["attempt_id"] = att["id"]
        return redirect(url_for("assess.quiz_take"))
    if kind != "submit":
        return render_template("submit_entry.html", csrf_token=_csrf(),
                               error="That code isn't valid.", code=raw), 200
    sub = S.redeem(_db(), raw, _now())
    session["submission_id"] = sub["id"]
    return redirect(url_for("submit.workspace"))


@bp.route("/submit/work", methods=["GET", "POST"])
def workspace():
    sub = _current()
    if sub is None:
        return redirect(url_for("submit.entry"))
    a = S.get_assignment(_db(), sub["assignment_id"])
    now = _now()
    error = None
    # A student staring at a page that just silently re-renders after an
    # upload has no way to tell "it saved" from "nothing happened" — surface
    # which POST action just succeeded so the template can say so explicitly.
    saved_action = None

    if request.method == "POST":
        _check_csrf()
        try:
            action = request.form.get("action")
            if action == "note":
                S.set_note(_db(), sub, request.form.get("note", ""), now)
            elif action == "delete":
                S.delete_file(_db(), sub, request.form.get("file_id", type=int),
                              now, _uploads())
            else:
                up = request.files.get("file")
                if up is None or not up.filename:
                    raise S.SubmitError("Choose a file first.")
                S.store_file(_db(), sub, display_name=up.filename,
                             data=up.read(), now=now, upload_dir=_uploads())
            saved_action = action or "upload"
        except S.SubmitError as exc:
            error = str(exc)
        sub = _db().execute("SELECT * FROM submissions WHERE id = ?",
                            (sub["id"],)).fetchone()

    earned, possible, complete = S.score(_db(), sub["id"])
    marks = _db().execute("SELECT * FROM rubric_scores WHERE submission_id = ?",
                          (sub["id"],)).fetchall() if a["released"] else []
    return render_template(
        "submit_work.html", a=a, sub=sub, files=S.list_files(_db(), sub["id"]),
        can_upload=S.can_upload(_db(), sub, now), late=S.is_late(_db(), sub),
        rubric=S.rubric_of(a), marks={m["criterion"]: m for m in marks},
        released=bool(a["released"]),
        score=(earned, possible, complete) if a["released"] else None,
        max_mb=S.MAX_FILE_BYTES // (1024 * 1024),
        max_files=S.MAX_FILES_PER_SUBMISSION,
        csrf_token=_csrf(), error=error, saved_action=saved_action)
