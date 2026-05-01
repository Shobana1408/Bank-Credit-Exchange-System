from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from models.audit_log import add_audit_log, fetch_audit_logs, count_audit_logs
from config import Config
from models.db import get_connection

app = Flask(__name__)
app.config.from_object(Config)

def get_db_connection():
    import mysql.connector
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Shobanasql_14",
        database="bank_credit_exchange"
    )

def add_audit_log(user_id, action_type, table_name, record_id, description):
    if not user_id:
        print("Audit log skipped: missing user_id")
        return

    connection = get_connection()
    if not connection:
        print("Audit log failed: database connection failed")
        return

    cursor = connection.cursor()
    try:
        cursor.execute("""
            INSERT INTO audit_log
            (user_id, action_type, table_name, record_id, description)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, action_type, table_name, record_id, description))
        connection.commit()
        print("Audit log inserted successfully")
    except Exception as e:
        connection.rollback()
        print("Audit log failed:", e)
    finally:
        cursor.close()
        connection.close()


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapper


def role_required(*allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                flash("Please login first.", "error")
                return redirect(url_for("login"))

            user_role = session.get("role")
            if user_role not in allowed_roles:
                flash("You do not have permission to access this page.", "error")
                return redirect(url_for("dashboard"))
            return view_func(*args, **kwargs)
        return wrapper
    return decorator


@app.context_processor
def inject_user_context():
    return {
        "current_user_role": session.get("role"),
        "current_user_name": session.get("full_name"),
        "is_logged_in": "user_id" in session
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute("SELECT * FROM bank_user WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user["password_hash"], password):
                session["user_id"] = user["user_id"]
                session["full_name"] = user["full_name"]
                session["role"] = user["role"]
                session["bank_id"] = user["bank_id"]

                add_audit_log(
                    user["user_id"],
                    "LOGIN",
                    "bank_user",
                    user["user_id"],
                    "User logged in"
                )

                flash("Login successful.", "success")
                return redirect(url_for("dashboard"))

            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        finally:
            cursor.close()
            connection.close()

    return render_template("login.html")

@app.route("/logout")
def logout():
    user_id = session.get("user_id")

    if user_id:
        add_audit_log(
            user_id,
            "LOGOUT",
            "bank_user",
            user_id,
            "User logged out"
        )

    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        bank_id = request.form.get("bank_id")
        full_name = request.form.get("full_name")
        designation = request.form.get("designation")
        email = request.form.get("email")
        phone_number = request.form.get("phone_number")
        username = request.form.get("username")
        password = request.form.get("password")
        role = request.form.get("role")

        password_hash = generate_password_hash(password)

        connection = get_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO bank_user
                (bank_id, full_name, designation, email, phone_number, username, password_hash, role, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (bank_id, full_name, designation, email, phone_number, username, password_hash, role, "Active")
            )
            connection.commit()

            user_id = cursor.lastrowid
            if session.get("user_id"):
                add_audit_log(
                    session["user_id"],
                    "INSERT",
                    "bank_user",
                    user_id,
                    f"Bank user '{full_name}' registered as {role}"
                )

            flash("Registration successful.", "success")
            return redirect(url_for("login"))

        except Exception as e:
            connection.rollback()
            flash(f"Registration failed: {str(e)}", "error")
            return redirect(url_for("register"))

        finally:
            cursor.close()
            connection.close()

    return render_template("register.html")


@app.route("/dashboard")
@login_required
def dashboard():
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("SELECT COUNT(*) AS total_borrowers FROM borrower")
        total_borrowers = cursor.fetchone()["total_borrowers"]

        cursor.execute("SELECT COUNT(*) AS total_loans FROM loan")
        total_loans = cursor.fetchone()["total_loans"]

        cursor.execute("SELECT COUNT(*) AS active_loans FROM loan WHERE loan_status = 'Active'")
        active_loans = cursor.fetchone()["active_loans"]

        cursor.execute("SELECT COUNT(*) AS pending_repayments FROM repayment WHERE payment_status = 'Pending'")
        pending_repayments = cursor.fetchone()["pending_repayments"]

        cursor.execute("SELECT COUNT(*) AS credit_inquiries FROM credit_inquiry")
        credit_inquiries = cursor.fetchone()["credit_inquiries"]

        cursor.execute("SELECT COUNT(*) AS open_disputes FROM dispute WHERE dispute_status = 'Open'")
        open_disputes = cursor.fetchone()["open_disputes"]

        cursor.execute("SELECT COUNT(*) AS consents_granted FROM consent WHERE consent_status = 'Granted'")
        consents_granted = cursor.fetchone()["consents_granted"]

        cursor.execute("SELECT COUNT(*) AS audit_logs FROM audit_log")
        audit_logs = cursor.fetchone()["audit_logs"]

        stats = {
            "total_borrowers": total_borrowers,
            "total_loans": total_loans,
            "active_loans": active_loans,
            "pending_repayments": pending_repayments,
            "credit_inquiries": credit_inquiries,
            "open_disputes": open_disputes,
            "consents_granted": consents_granted,
            "audit_logs": audit_logs
        }

        return render_template("dashboard.html", stats=stats)

    finally:
        cursor.close()
        connection.close()


@app.route("/borrower/add", methods=["GET", "POST"])
@login_required
def add_borrower():
    if request.method == "POST":
        full_name = request.form.get("full_name")
        dob = request.form.get("dob")
        gender = request.form.get("gender")
        aadhaar_number = request.form.get("aadhaar_number")
        pan_number = request.form.get("pan_number")
        email = request.form.get("email")
        phone_number = request.form.get("phone_number")
        address = request.form.get("address")
        city = request.form.get("city")
        state = request.form.get("state")
        pincode = request.form.get("pincode")
        employment_type = request.form.get("employment_type")
        annual_income = request.form.get("annual_income")

        connection = get_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO borrower
                (full_name, dob, gender, aadhaar_number, pan_number, email, phone_number, address, city, state, pincode, employment_type, annual_income)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (full_name, dob, gender, aadhaar_number, pan_number, email, phone_number, address, city, state, pincode, employment_type, annual_income)
            )
            connection.commit()

            borrower_id = cursor.lastrowid
            add_audit_log(
                session["user_id"],
                "INSERT",
                "borrower",
                borrower_id,
                f"Borrower '{full_name}' added"
            )

            flash("Borrower added successfully.", "success")
            return redirect(url_for("view_borrowers"))

        except Exception as e:
            connection.rollback()
            flash(f"Failed to add borrower: {str(e)}", "error")
            return redirect(url_for("add_borrower"))

        finally:
            cursor.close()
            connection.close()

    return render_template("borrower/add_borrower.html")

@app.route("/borrowers")
@login_required
def view_borrowers():
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM borrower")   # IMPORTANT
        borrowers = cursor.fetchall()

        print("DEBUG:", borrowers)  # 👈 check terminal

        return render_template("view_borrowers.html", borrowers=borrowers)

    except Exception as e:
        print("ERROR:", e)
        flash(f"Error loading borrowers: {str(e)}", "error")
        return redirect(url_for("dashboard"))

    finally:
        cursor.close()
        connection.close()
@app.route("/borrower/delete/<int:borrower_id>", methods=["POST"])
@role_required("Admin")
def delete_borrower(borrower_id):
    connection = get_connection()
    if not connection:
        flash("Database connection failed.", "error")
        return redirect(url_for("view_borrowers"))

    cursor = connection.cursor()
    try:
        cursor.execute("DELETE FROM borrower WHERE borrower_id = %s", (borrower_id,))
        connection.commit()

        user_id = session.get("user_id")
        add_audit_log(user_id, "DELETE", "borrower", borrower_id, f"Borrower deleted: ID {borrower_id}")

        flash("Borrower deleted successfully.", "success")
    except Exception as e:
        connection.rollback()
        flash(f"Failed to delete borrower: {str(e)}", "error")
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("view_borrowers"))


@app.route("/loan/apply", methods=["GET", "POST"])
@login_required
def apply_loan():
    if request.method == "POST":
        borrower_id = request.form.get("borrower_id")
        bank_id = request.form.get("bank_id")
        loan_type_id = request.form.get("loan_type_id")
        applied_amount = request.form.get("applied_amount")
        application_date = request.form.get("application_date")
        remarks = request.form.get("remarks")

        connection = get_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO loan_application
                (borrower_id, bank_id, loan_type_id, applied_amount, application_date, application_status, remarks)
                VALUES (%s, %s, %s, %s, %s, 'Pending', %s)
                """,
                (borrower_id, bank_id, loan_type_id, applied_amount, application_date, remarks)
            )
            connection.commit()

            application_id = cursor.lastrowid
            add_audit_log(
                session["user_id"],
                "INSERT",
                "loan_application",
                application_id,
                "Loan application submitted"
            )
            flash("Loan application submitted successfully.", "success")
            return redirect(url_for("view_loan_applications"))

        except Exception as e:
            connection.rollback()
            flash(f"Failed to apply loan: {str(e)}", "error")
            return redirect(url_for("apply_loan"))

        finally:
            cursor.close()
            connection.close()

    return render_template("loan/apply_loan.html")

@app.route("/loan/applications")
@login_required
def view_loan_applications():
    applications = []
    connection = get_connection()
    if not connection:
        flash("Database connection failed.", "error")
        return render_template("loan/view_loan_applications.html", applications=applications)

    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT * 
            FROM loan_application
            ORDER BY application_id DESC
        """)
        applications = cursor.fetchall()
    finally:
        cursor.close()
        connection.close()

    return render_template("loan/view_loan_applications.html", applications=applications)


@app.route("/loan/approve/<int:application_id>", methods=["GET", "POST"])
@role_required("Admin", "Manager")
def approve_loan(application_id):
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM loan_application WHERE application_id = %s", (application_id,))
        application = cursor.fetchone()

        if not application:
            flash("Loan application not found.", "error")
            return redirect(url_for("view_loan_applications"))

        if request.method == "POST":
            loan_amount = request.form.get("loan_amount")
            interest_rate = request.form.get("interest_rate")
            tenure_months = request.form.get("tenure_months")
            sanction_date = request.form.get("sanction_date")
            loan_status = request.form.get("loan_status", "Active")

            cursor.execute(
                """
                INSERT INTO loan
                (application_id, borrower_id, bank_id, loan_type_id, loan_amount, interest_rate, tenure_months, sanction_date, loan_status, outstanding_balance)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    application_id,
                    application["borrower_id"],
                    application["bank_id"],
                    application["loan_type_id"],
                    loan_amount,
                    interest_rate,
                    tenure_months,
                    sanction_date,
                    loan_status,
                    loan_amount
                )
            )

            cursor.execute(
                "UPDATE loan_application SET application_status = 'Approved' WHERE application_id = %s",
                (application_id,)
            )

            connection.commit()

            add_audit_log(
                session["user_id"],
                "INSERT",
                "loan",
                application_id,
                f"Loan approved for application {application_id}"
            )

            flash("Loan approved successfully.", "success")
            return redirect(url_for("view_loans"))

        return render_template("loan/approve_loan.html", application=application)

    except Exception as e:
        connection.rollback()
        flash(f"Failed to approve loan: {str(e)}", "error")
        return redirect(url_for("view_loan_applications"))

    finally:
        cursor.close()
        connection.close()


@app.route("/loans")
@login_required
def view_loans():
    loans = []
    connection = get_connection()
    if not connection:
        flash("Database connection failed.", "error")
        return render_template("loan/view_loans.html", loans=loans)

    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT
                loan_id,
                application_id,
                borrower_id,
                bank_id,
                loan_type_id,
                loan_amount,
                interest_rate,
                tenure_months,
                sanction_date,
                loan_status,
                outstanding_balance
            FROM loan
            ORDER BY loan_id DESC
        """)
        loans = cursor.fetchall()
    finally:
        cursor.close()
        connection.close()

    return render_template("loan/view_loans.html", loans=loans)


@app.route("/repayment/add", methods=["GET", "POST"])
def add_repayment():
    if request.method == "POST":
        loan_id = request.form.get("loan_id")
        installment_no = request.form.get("installment_no")
        due_date = request.form.get("due_date")
        paid_date = request.form.get("paid_date") or None
        due_amount = request.form.get("due_amount")
        paid_amount = request.form.get("paid_amount") or 0
        payment_status = request.form.get("payment_status")
        payment_mode = request.form.get("payment_mode")

        # 🔥 VERY IMPORTANT FIX
        if payment_mode:
            payment_mode = payment_mode.strip()
        if payment_mode == "":
            payment_mode = None

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO repayment 
                (loan_id, installment_no, due_date, paid_date, due_amount, paid_amount, payment_status, payment_mode)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                loan_id,
                installment_no,
                due_date,
                paid_date,
                due_amount,
                paid_amount,
                payment_status,
                payment_mode
            ))

            conn.commit()
            flash("Repayment added successfully", "success")

        except Exception as e:
            conn.rollback()
            flash(f"Failed to add repayment: {e}", "danger")

        finally:
            cursor.close()
            conn.close()

        return redirect(url_for("add_repayment"))

    return render_template("repayment/add_repayment.html")

@app.route("/loan/repayments")
@login_required
def repayment_history():
    repayments = []
    search = request.args.get("search", "").strip()
    status = request.args.get("status", "").strip()

    connection = get_connection()
    if not connection:
        flash("Database connection failed.", "error")
        return render_template("loan/repayment_history.html", repayments=repayments, search=search, status=status)

    cursor = connection.cursor(dictionary=True)
    try:
        query = """
            SELECT
                repayment_id,
                loan_id,
                installment_no,
                due_date,
                paid_date,
                due_amount,
                paid_amount,
                payment_status,
                payment_mode
            FROM repayment
            WHERE 1=1
        """
        params = []

        if search:
            query += " AND CAST(loan_id AS CHAR) LIKE %s"
            params.append(f"%{search}%")

        if status:
            query += " AND payment_status = %s"
            params.append(status)

        query += " ORDER BY repayment_id DESC"

        cursor.execute(query, tuple(params))
        repayments = cursor.fetchall()
    finally:
        cursor.close()
        connection.close()

    return render_template("loan/repayment_history.html", repayments=repayments, search=search, status=status)


@app.route("/repayment/delete/<int:repayment_id>", methods=["POST"])
@role_required("Admin")
def delete_repayment(repayment_id):
    connection = get_connection()
    if not connection:
        flash("Database connection failed.", "error")
        return redirect(url_for("repayment_history"))

    cursor = connection.cursor()
    try:
        cursor.execute("DELETE FROM repayment WHERE repayment_id = %s", (repayment_id,))
        connection.commit()

        user_id = session.get("user_id")
        add_audit_log(user_id, "DELETE", "repayment", repayment_id, f"Repayment deleted: ID {repayment_id}")

        flash("Repayment deleted successfully.", "success")
    except Exception as e:
        connection.rollback()
        flash(f"Failed to delete repayment: {str(e)}", "error")
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("repayment_history"))


@app.route("/credit/report", methods=["GET", "POST"])
@login_required
def credit_report():
    if request.method == "POST":
        borrower_id = request.form.get("borrower_id", "").strip()
        total_loans = request.form.get("total_loans", "").strip()
        active_loans = request.form.get("active_loans", "").strip()
        closed_loans = request.form.get("closed_loans", "").strip()
        default_count = request.form.get("default_count", "").strip()
        total_outstanding = request.form.get("total_outstanding", "").strip()
        credit_score = request.form.get("credit_score", "").strip()
        report_date = request.form.get("report_date", "").strip()

        if not borrower_id or not total_loans or not active_loans or not closed_loans or default_count == "" or not total_outstanding or not credit_score or not report_date:
            flash("Please fill all required credit report fields.", "error")
            return redirect(url_for("credit_report"))

        connection = get_connection()
        if not connection:
            flash("Database connection failed.", "error")
            return redirect(url_for("credit_report"))

        cursor = connection.cursor()
        try:
            cursor.execute("SELECT borrower_id FROM borrower WHERE borrower_id = %s", (borrower_id,))
            borrower_exists = cursor.fetchone()

            if not borrower_exists:
                flash("Invalid borrower ID.", "error")
                return redirect(url_for("credit_report"))

            cursor.execute("""
                INSERT INTO credit_report
                (borrower_id, total_loans, active_loans, closed_loans, default_count, total_outstanding, credit_score, report_date)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                borrower_id,
                total_loans,
                active_loans,
                closed_loans,
                default_count,
                total_outstanding,
                credit_score,
                report_date
            ))
            connection.commit()

            report_id = cursor.lastrowid
            user_id = session.get("user_id")
            add_audit_log(user_id, "INSERT", "credit_report", report_id, f"Credit report created for borrower ID {borrower_id}")

            flash("Credit report added successfully.", "success")
            return redirect(url_for("credit_report"))

        except Exception as e:
            connection.rollback()
            flash(f"Failed to add credit report: {str(e)}", "error")
            return redirect(url_for("credit_report"))
        finally:
            cursor.close()
            connection.close()

    reports = []
    connection = get_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT report_id, borrower_id, total_loans, active_loans, closed_loans, default_count, total_outstanding, credit_score, report_date
                FROM credit_report
                ORDER BY report_id DESC
            """)
            reports = cursor.fetchall()
        finally:
            cursor.close()
            connection.close()

    return render_template("credit/credit_report.html", reports=reports)


@app.route("/credit/inquiry", methods=["GET", "POST"])
@login_required
def credit_inquiry():
    if request.method == "POST":
        bank_id = request.form.get("bank_id", "").strip()
        borrower_id = request.form.get("borrower_id", "").strip()
        user_id_form = request.form.get("user_id", "").strip()
        purpose = request.form.get("purpose", "").strip()

        if not bank_id or not borrower_id or not user_id_form or not purpose:
            flash("Please fill all required credit inquiry fields.", "error")
            return redirect(url_for("credit_inquiry"))

        connection = get_connection()
        if not connection:
            flash("Database connection failed.", "error")
            return redirect(url_for("credit_inquiry"))

        cursor = connection.cursor()
        try:
            cursor.execute("SELECT bank_id FROM bank WHERE bank_id = %s", (bank_id,))
            bank_exists = cursor.fetchone()

            cursor.execute("SELECT borrower_id FROM borrower WHERE borrower_id = %s", (borrower_id,))
            borrower_exists = cursor.fetchone()

            cursor.execute("SELECT user_id FROM bank_user WHERE user_id = %s", (user_id_form,))
            user_exists = cursor.fetchone()

            if not bank_exists:
                flash("Invalid bank ID.", "error")
                return redirect(url_for("credit_inquiry"))

            if not borrower_exists:
                flash("Invalid borrower ID.", "error")
                return redirect(url_for("credit_inquiry"))

            if not user_exists:
                flash("Invalid user ID.", "error")
                return redirect(url_for("credit_inquiry"))

            cursor.execute("""
                INSERT INTO credit_inquiry
                (bank_id, borrower_id, user_id, purpose)
                VALUES (%s, %s, %s, %s)
            """, (
                bank_id,
                borrower_id,
                user_id_form,
                purpose
            ))
            connection.commit()

            inquiry_id = cursor.lastrowid
            session_user_id = session.get("user_id")
            add_audit_log(session_user_id, "INSERT", "credit_inquiry", inquiry_id, f"Credit inquiry created for borrower ID {borrower_id}")

            flash("Credit inquiry submitted successfully.", "success")
            return redirect(url_for("credit_inquiry"))

        except Exception as e:
            connection.rollback()
            flash(f"Failed to add credit inquiry: {str(e)}", "error")
            return redirect(url_for("credit_inquiry"))
        finally:
            cursor.close()
            connection.close()

    inquiries = []
    connection = get_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT inquiry_id, bank_id, borrower_id, user_id, inquiry_date, purpose
                FROM credit_inquiry
                ORDER BY inquiry_id DESC
            """)
            inquiries = cursor.fetchall()
        finally:
            cursor.close()
            connection.close()

    return render_template("credit/credit_inquiry.html", inquiries=inquiries)


@app.route("/credit/consent", methods=["GET", "POST"])
@login_required
def consent_management():
    if request.method == "POST":
        borrower_id = request.form.get("borrower_id", "").strip()
        bank_id = request.form.get("bank_id", "").strip()
        consent_given_date = request.form.get("consent_given_date", "").strip()
        consent_expiry_date = request.form.get("consent_expiry_date", "").strip()
        consent_status = request.form.get("consent_status", "").strip()

        if not borrower_id or not bank_id or not consent_given_date or not consent_expiry_date or not consent_status:
            flash("Please fill all required consent fields.", "error")
            return redirect(url_for("consent_management"))

        connection = get_connection()
        if not connection:
            flash("Database connection failed.", "error")
            return redirect(url_for("consent_management"))

        cursor = connection.cursor()
        try:
            cursor.execute("SELECT borrower_id FROM borrower WHERE borrower_id = %s", (borrower_id,))
            borrower_exists = cursor.fetchone()

            cursor.execute("SELECT bank_id FROM bank WHERE bank_id = %s", (bank_id,))
            bank_exists = cursor.fetchone()

            if not borrower_exists:
                flash("Invalid borrower ID.", "error")
                return redirect(url_for("consent_management"))

            if not bank_exists:
                flash("Invalid bank ID.", "error")
                return redirect(url_for("consent_management"))

            cursor.execute("""
                INSERT INTO consent
                (borrower_id, bank_id, consent_given_date, consent_expiry_date, consent_status)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                borrower_id,
                bank_id,
                consent_given_date,
                consent_expiry_date,
                consent_status
            ))
            connection.commit()

            consent_id = cursor.lastrowid
            user_id = session.get("user_id")
            add_audit_log(user_id, "INSERT", "consent", consent_id, f"Consent created for borrower ID {borrower_id}")

            flash("Consent record added successfully.", "success")
            return redirect(url_for("consent_management"))

        except Exception as e:
            connection.rollback()
            flash(f"Failed to add consent record: {str(e)}", "error")
            return redirect(url_for("consent_management"))
        finally:
            cursor.close()
            connection.close()

    consents = []
    connection = get_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT consent_id, borrower_id, bank_id, consent_given_date, consent_expiry_date, consent_status
                FROM consent
                ORDER BY consent_id DESC
            """)
            consents = cursor.fetchall()
        finally:
            cursor.close()
            connection.close()

    return render_template("credit/consent_management.html", consents=consents)


@app.route("/dispute/raise", methods=["GET", "POST"])
@login_required
def raise_dispute():
    if request.method == "POST":
        borrower_id = request.form.get("borrower_id")
        loan_id = request.form.get("loan_id")
        bank_id = request.form.get("bank_id")
        dispute_type = request.form.get("dispute_type")
        description = request.form.get("description")
        raised_date = request.form.get("raised_date")

        connection = get_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO dispute
                (borrower_id, loan_id, bank_id, dispute_type, description, raised_date, dispute_status)
                VALUES (%s, %s, %s, %s, %s, %s, 'Open')
                """,
                (borrower_id, loan_id if loan_id else None, bank_id, dispute_type, description, raised_date)
            )
            connection.commit()

            dispute_id = cursor.lastrowid
            add_audit_log(
                session["user_id"],
                "INSERT",
                "dispute",
                dispute_id,
                "Dispute raised"
            )

            flash("Dispute raised successfully.", "success")
            return redirect(url_for("view_disputes"))

        except Exception as e:
            connection.rollback()
            flash(f"Failed to raise dispute: {str(e)}", "error")
            return redirect(url_for("raise_dispute"))

        finally:
            cursor.close()
            connection.close()

    return render_template("dispute/raise_dispute.html")

@app.route("/disputes")
@login_required
def view_disputes():
    disputes = []
    status = request.args.get("status", "").strip()

    connection = get_connection()
    if not connection:
        flash("Database connection failed.", "error")
        return render_template("dispute/view_disputes.html", disputes=disputes, status=status)

    cursor = connection.cursor(dictionary=True)
    try:
        if status:
            cursor.execute("""
                SELECT dispute_id, borrower_id, loan_id, bank_id, dispute_type, description, raised_date, dispute_status, resolved_date
                FROM dispute
                WHERE dispute_status = %s
                ORDER BY dispute_id DESC
            """, (status,))
        else:
            cursor.execute("""
                SELECT dispute_id, borrower_id, loan_id, bank_id, dispute_type, description, raised_date, dispute_status, resolved_date
                FROM dispute
                ORDER BY dispute_id DESC
            """)
        disputes = cursor.fetchall()
    finally:
        cursor.close()
        connection.close()

    return render_template("dispute/view_disputes.html", disputes=disputes, status=status)


@app.route("/dispute/details/<int:dispute_id>")
@login_required
def dispute_details(dispute_id):
    connection = get_connection()
    if not connection:
        flash("Database connection failed.", "error")
        return redirect(url_for("view_disputes"))

    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT dispute_id, borrower_id, loan_id, bank_id, dispute_type, description, raised_date, dispute_status, resolved_date
            FROM dispute
            WHERE dispute_id = %s
        """, (dispute_id,))
        dispute = cursor.fetchone()
    finally:
        cursor.close()
        connection.close()

    if not dispute:
        flash("Dispute not found.", "error")
        return redirect(url_for("view_disputes"))

    return render_template("dispute/dispute_details.html", dispute=dispute)


@app.route("/dispute/update/<int:dispute_id>", methods=["POST"])
@role_required("Admin", "Manager")
def update_dispute_status(dispute_id):
    dispute_status = request.form.get("dispute_status")
    resolved_date = request.form.get("resolved_date")

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            UPDATE dispute
            SET dispute_status = %s, resolved_date = %s
            WHERE dispute_id = %s
            """,
            (dispute_status, resolved_date if resolved_date else None, dispute_id)
        )
        connection.commit()

        add_audit_log(
            session["user_id"],
            "UPDATE",
            "dispute",
            dispute_id,
            f"Dispute status updated to {dispute_status}"
        )

        flash("Dispute status updated successfully.", "success")
    except Exception as e:
        connection.rollback()
        flash(f"Failed to update dispute: {str(e)}", "error")
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("dispute_details", dispute_id=dispute_id))

@app.route("/dispute/delete/<int:dispute_id>", methods=["POST"])
@role_required("Admin")
def delete_dispute(dispute_id):
    connection = get_connection()
    if not connection:
        flash("Database connection failed.", "error")
        return redirect(url_for("view_disputes"))

    cursor = connection.cursor()
    try:
        cursor.execute("DELETE FROM dispute WHERE dispute_id = %s", (dispute_id,))
        connection.commit()

        user_id = session.get("user_id")
        add_audit_log(user_id, "DELETE", "dispute", dispute_id, f"Dispute deleted: ID {dispute_id}")

        flash("Dispute deleted successfully.", "success")
    except Exception as e:
        connection.rollback()
        flash(f"Failed to delete dispute: {str(e)}", "error")
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("view_disputes"))


@app.route("/admin/audit-logs")
@role_required("Admin")
def audit_logs():
    logs = []
    connection = get_connection()
    if not connection:
        flash("Database connection failed.", "error")
        return render_template("admin/audit_logs.html", logs=logs)

    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT log_id, user_id, action_type, table_name, record_id, action_timestamp, description
            FROM audit_log
            ORDER BY log_id DESC
        """)
        logs = cursor.fetchall()
    finally:
        cursor.close()
        connection.close()

    return render_template("admin/audit_logs.html", logs=logs)


@app.route("/admin/bank-users")
@role_required("Admin")
def bank_users():
    users = []
    connection = get_connection()
    if not connection:
        flash("Database connection failed.", "error")
        return render_template("admin/bank_users.html", users=users)

    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT user_id, bank_id, full_name, designation, email, username, role, status
            FROM bank_user
            ORDER BY user_id DESC
        """)
        users = cursor.fetchall()
    finally:
        cursor.close()
        connection.close()

    return render_template("admin/bank_users.html", users=users)
@app.route("/bank/add", methods=["GET", "POST"])
def add_bank():
    if request.method == "POST":
        bank_name = request.form.get("bank_name")
        branch_name = request.form.get("branch_name")
        ifsc_code = request.form.get("ifsc_code")
        bank_email = request.form.get("bank_email")
        phone_number = request.form.get("phone_number")
        address = request.form.get("address")
        city = request.form.get("city")
        state = request.form.get("state")
        pincode = request.form.get("pincode")
        status = request.form.get("status")

        connection = get_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO bank
                (bank_name, branch_name, ifsc_code, bank_email, phone_number, address, city, state, pincode, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (bank_name, branch_name, ifsc_code, bank_email, phone_number, address, city, state, pincode, status)
            )
            connection.commit()

            # log only after successful insert
            bank_id = cursor.lastrowid
            if session.get("user_id"):
                add_audit_log(
                    session["user_id"],
                    "INSERT",
                    "bank",
                    bank_id,
                    f"Bank '{bank_name}' added"
                )

            flash("Bank added successfully.", "success")
            return redirect(url_for("register"))

        except Exception as e:
            connection.rollback()
            flash(f"Failed to add bank: {str(e)}", "error")
            return redirect(url_for("add_bank"))

        finally:
            cursor.close()
            connection.close()

    return render_template("bank/add_bank.html")

if __name__ == "__main__":
    app.run(debug=True)