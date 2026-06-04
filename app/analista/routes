# app/analista/routes.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, make_response
from flask_login import login_required, current_user
from app.core.models import LogAuditoria, Usuario
import csv, io
from datetime import datetime

analista_bp = Blueprint("analista", __name__)


def requer_analista(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.perfil not in ("analista", "admin"):
            flash("Acesso restrito.", "danger")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


@analista_bp.route("/logs")
@login_required
@requer_analista
def logs():
    query = LogAuditoria.query

    fluxo = request.args.get("fluxo")
    evento = request.args.get("evento")
    user_id = request.args.get("user_id")

    if fluxo:
        query = query.filter(LogAuditoria.tipo_fluxo == fluxo)
    if evento:
        query = query.filter(LogAuditoria.tipo_evento == evento)
    if user_id:
        query = query.filter(LogAuditoria.user_id == user_id)

    registros = query.order_by(LogAuditoria.criado_em.desc()).limit(200).all()
    usuarios = Usuario.query.all()

    metricas = {
        "total": LogAuditoria.query.count(),
        "bloqueios": LogAuditoria.query.filter_by(tipo_evento="conta_bloqueada").count(),
        "resets_ok": LogAuditoria.query.filter_by(tipo_evento="reset_ok").count(),
        "otp_fail": LogAuditoria.query.filter_by(tipo_evento="otp_fail").count(),
    }

    return render_template("analista/logs.html", registros=registros, usuarios=usuarios, metricas=metricas)


@analista_bp.route("/logs/exportar")
@login_required
@requer_analista
def exportar():
    registros = LogAuditoria.query.order_by(LogAuditoria.criado_em.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "user_id", "tipo_fluxo", "tipo_evento", "endereco_ip", "criado_em"])
    for r in registros:
        writer.writerow([r.id, r.user_id, r.tipo_fluxo, r.tipo_evento, r.endereco_ip, r.criado_em])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=logs_auditoria.csv"
    response.headers["Content-type"] = "text/csv"
    return response