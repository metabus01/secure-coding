"""
Tiny Second-hand Shopping Platform (Secure Coding version)
- WhiteHat School / Secure Coding assignment
- 기능: 회원/상품/채팅(전체·1:1)/신고·자동차단/송금/검색/관리자
- 보안: 비밀번호 해시, CSRF, 입력검증, XSS 방어, 로그인 잠금,
        세션 쿠키 플래그, 보안 헤더, 접근제어/소유자 검증, 에러 처리
"""
import os
import re
import time
import sqlite3
import uuid
from functools import wraps
from datetime import datetime, timezone

import bleach
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g, abort, jsonify, send_from_directory
)
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, send, emit, join_room
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

# ----------------------------------------------------------------------------
# 앱 설정
# ----------------------------------------------------------------------------
app = Flask(__name__)

# [보안] SECRET_KEY 하드코딩 제거 -> 환경변수 우선, 없으면 랜덤 생성
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(32).hex()

# [보안] 세션 쿠키 플래그
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,          # JS에서 쿠키 접근 차단(XSS 완화)
    SESSION_COOKIE_SAMESITE='Lax',         # CSRF 완화
    # 운영(HTTPS) 환경에서는 True 로 설정. 로컬 http 개발은 env 로 제어.
    SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '0') == '1',
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,    # 요청 본문 크기 제한(2MB)
)

DATABASE = 'market.db'
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# [보안] 허용 확장자 화이트리스트 + 파일 시그니처(매직바이트) 검증
ALLOWED_EXT = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
MAGIC_SIGNATURES = {
    b'\xff\xd8\xff': 'jpg',            # JPEG
    b'\x89PNG\r\n\x1a\n': 'png',       # PNG
    b'GIF87a': 'gif',
    b'GIF89a': 'gif',
}
MAX_IMAGE_BYTES = 2 * 1024 * 1024   # 2MB

# [보안] CSRF 보호 (모든 POST 폼에 csrf_token 필요)
csrf = CSRFProtect(app)

# SocketIO: 개발환경 CORS 허용은 로컬 테스트용. 운영시 도메인 제한 권장.
socketio = SocketIO(app, cors_allowed_origins="*")

# 정책 상수
REPORT_BLOCK_THRESHOLD = 3     # 상품: 신고 N회 이상 -> 자동 차단
REPORT_DORMANT_THRESHOLD = 5   # 유저: 신고 N회 이상 -> 휴면 전환
LOGIN_MAX_FAIL = 5             # 로그인 실패 허용 횟수
LOGIN_LOCK_SECONDS = 300       # 잠금 시간(초)
CHAT_MIN_INTERVAL = 0.5        # 채팅 최소 전송 간격(초, 스팸 방지)
TOPUP_MAX_ONCE = 500_000       # 1회 충전 한도
TOPUP_MAX_BALANCE = 5_000_000  # 보유 잔액 상한

# 로그인 실패/채팅 rate-limit 추적(메모리). 운영은 Redis 등 권장.
_login_fail = {}   # username -> (fail_count, first_fail_ts)
_chat_last = {}    # user_id -> last_ts


# ----------------------------------------------------------------------------
# DB 유틸
# ----------------------------------------------------------------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT DEFAULT '',
                balance INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active',   -- active / dormant
                is_admin INTEGER NOT NULL DEFAULT 0,
                report_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT ''
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price INTEGER NOT NULL,
                seller_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',    -- active / blocked / sold
                buyer_id TEXT DEFAULT NULL,
                image TEXT DEFAULT NULL,
                report_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (seller_id) REFERENCES user(id)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_type TEXT NOT NULL,   -- user / product
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT ''
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS transfer (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                product_id TEXT DEFAULT NULL,
                created_at TEXT NOT NULL DEFAULT ''
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS message (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT ''
            )
        """)
        db.commit()

        # 최초 실행 시 관리자 계정 자동 생성 (env로 비밀번호 지정 가능)
        admin_pw = os.environ.get('ADMIN_PASSWORD', 'admin1234!')
        c.execute("SELECT id FROM user WHERE username = 'admin'")
        if c.fetchone() is None:
            c.execute(
                "INSERT INTO user (id, username, password, is_admin, balance, created_at) "
                "VALUES (?, ?, ?, 1, 1000000, ?)",
                (str(uuid.uuid4()), 'admin',
                 generate_password_hash(admin_pw), now())
            )
            db.commit()


def now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


# ----------------------------------------------------------------------------
# 입력 검증 / sanitize
# ----------------------------------------------------------------------------
USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,20}$')


def valid_username(u):
    return bool(u) and bool(USERNAME_RE.match(u))


def valid_password(p):
    # 길이 8~64, 최소 문자+숫자 조합
    return bool(p) and 8 <= len(p) <= 64 and re.search(r'[A-Za-z]', p) and re.search(r'\d', p)


def clean_text(s, max_len):
    """길이 제한 + HTML 태그 전면 제거(XSS 방어). 저장 전 정규화."""
    if s is None:
        return ''
    s = s.strip()[:max_len]
    return bleach.clean(s, tags=[], attributes={}, strip=True)


def save_product_image(file_storage):
    """업로드 이미지 검증 후 저장. 성공 시 저장 파일명, 실패 시 (None, 오류메시지)."""
    if not file_storage or not file_storage.filename:
        return None, None                      # 이미지 미첨부는 허용

    # [보안] 확장자 화이트리스트 (블랙리스트 방식은 우회 가능)
    name = secure_filename(file_storage.filename)
    if '.' not in name:
        return None, '확장자가 없는 파일입니다.'
    ext = name.rsplit('.', 1)[1].lower()
    if ext not in ALLOWED_EXT:
        return None, '허용되지 않는 이미지 형식입니다. (jpg/png/gif/webp)'

    # [보안] 크기 제한 (DoS 방지)
    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)
    if size == 0:
        return None, '빈 파일입니다.'
    if size > MAX_IMAGE_BYTES:
        return None, '이미지 크기는 2MB 이하여야 합니다.'

    # [보안] 파일 시그니처 검증 (확장자만 바꾼 위장 파일/웹셸 차단)
    head = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    if ext == 'webp':
        ok = head[:4] == b'RIFF' and head[8:12] == b'WEBP'
    else:
        ok = any(head.startswith(sig) for sig in MAGIC_SIGNATURES)
    if not ok:
        return None, '이미지 파일이 아닙니다.'

    # [보안] 사용자 파일명을 사용하지 않고 UUID로 재생성 (경로조작·덮어쓰기 방지)
    new_name = f"{uuid.uuid4().hex}.{ext}"
    file_storage.save(os.path.join(UPLOAD_FOLDER, new_name))
    return new_name, None


def delete_product_image(filename):
    """상품 삭제 시 업로드 파일도 정리."""
    if not filename:
        return
    path = os.path.join(UPLOAD_FOLDER, os.path.basename(filename))
    if os.path.isfile(path):
        try:
            os.remove(path)
        except OSError:
            pass


# ----------------------------------------------------------------------------
# 접근 제어 데코레이터
# ----------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        user = current_user()
        if user is None:
            session.clear()
            return redirect(url_for('login'))
        if user['status'] == 'dormant':
            session.clear()
            flash('휴면 처리된 계정입니다. 관리자에게 문의하세요.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user()['is_admin']:
            abort(403)
        return f(*args, **kwargs)
    return wrapper


def current_user():
    if 'user_id' not in session:
        return None
    db = get_db()
    c = db.cursor()
    c.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    return c.fetchone()


# ----------------------------------------------------------------------------
# 보안 헤더
# ----------------------------------------------------------------------------
@app.after_request
def set_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    # SocketIO 클라이언트(cdn) 허용 위해 script-src에 cdn 포함
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.socket.io 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:"
    )
    return resp


# ----------------------------------------------------------------------------
# 에러 핸들러 (스택트레이스/내부정보 노출 방지)
# ----------------------------------------------------------------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, msg='접근 권한이 없습니다.'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, msg='페이지를 찾을 수 없습니다.'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', code=500, msg='서버 오류가 발생했습니다.'), 500


# ----------------------------------------------------------------------------
# 기본 / 인증
# ----------------------------------------------------------------------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        # [보안] 서버측 입력 검증
        if not valid_username(username):
            flash('아이디는 영문/숫자/밑줄 3~20자여야 합니다.')
            return redirect(url_for('register'))
        if not valid_password(password):
            flash('비밀번호는 8자 이상이며 영문과 숫자를 포함해야 합니다.')
            return redirect(url_for('register'))

        db = get_db()
        c = db.cursor()
        c.execute("SELECT id FROM user WHERE username = ?", (username,))
        if c.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        # [보안] 비밀번호 해시 저장
        c.execute(
            "INSERT INTO user (id, username, password, created_at) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), username, generate_password_hash(password), now())
        )
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        # [보안] 로그인 실패 잠금(무차별 대입 방어)
        fail = _login_fail.get(username)
        if fail and fail[0] >= LOGIN_MAX_FAIL:
            if time.time() - fail[1] < LOGIN_LOCK_SECONDS:
                flash('로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요.')
                return redirect(url_for('login'))
            else:
                _login_fail.pop(username, None)  # 잠금 해제

        db = get_db()
        c = db.cursor()
        c.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = c.fetchone()

        # [보안] 해시 비교
        if user and check_password_hash(user['password'], password):
            if user['status'] == 'dormant':
                flash('휴면 처리된 계정입니다. 관리자에게 문의하세요.')
                return redirect(url_for('login'))
            _login_fail.pop(username, None)
            session.clear()
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))

        # 실패 카운트 증가
        cnt = (fail[0] + 1) if fail else 1
        _login_fail[username] = (cnt, time.time() if not fail else fail[1])
        # [보안] 아이디/비번 구분 없는 동일 메시지(사용자 열거 방지)
        flash('아이디 또는 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))


# ----------------------------------------------------------------------------
# 대시보드 / 검색
# ----------------------------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    c = db.cursor()
    c.execute("SELECT * FROM product WHERE status = 'active' ORDER BY created_at DESC")
    products = c.fetchall()
    return render_template('dashboard.html', products=products, user=current_user())


@app.route('/search')
@login_required
def search():
    q = (request.args.get('q') or '').strip()[:50]
    db = get_db()
    c = db.cursor()
    products, users = [], []
    if q:
        # [보안] LIKE 파라미터 바인딩 (SQLi 방어)
        like = f"%{q}%"
        c.execute(
            "SELECT * FROM product WHERE status='active' AND (title LIKE ? OR description LIKE ?)",
            (like, like)
        )
        products = c.fetchall()
        c.execute(
            "SELECT id, username, bio FROM user WHERE status='active' AND username LIKE ?",
            (like,)
        )
        users = c.fetchall()
    return render_template('search.html', q=q, products=products, users=users)


# ----------------------------------------------------------------------------
# 유저: 조회 / 프로필 / 마이페이지(비번 변경)
# ----------------------------------------------------------------------------
@app.route('/user/<user_id>')
@login_required
def view_user(user_id):
    db = get_db()
    c = db.cursor()
    c.execute("SELECT id, username, bio, status FROM user WHERE id = ?", (user_id,))
    target = c.fetchone()
    if not target:
        abort(404)
    c.execute("SELECT * FROM product WHERE seller_id = ? AND status='active'", (user_id,))
    products = c.fetchall()
    return render_template('user.html', target=target, products=products)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    c = db.cursor()
    user = current_user()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'bio':
            bio = clean_text(request.form.get('bio', ''), 500)
            c.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, user['id']))
            db.commit()
            flash('소개글이 업데이트되었습니다.')
        elif action == 'password':
            # [보안] 비밀번호 변경 시 현재 비밀번호 재인증
            cur_pw = request.form.get('current_password') or ''
            new_pw = request.form.get('new_password') or ''
            if not check_password_hash(user['password'], cur_pw):
                flash('현재 비밀번호가 올바르지 않습니다.')
                return redirect(url_for('profile'))
            if not valid_password(new_pw):
                flash('새 비밀번호는 8자 이상이며 영문과 숫자를 포함해야 합니다.')
                return redirect(url_for('profile'))
            c.execute("UPDATE user SET password = ? WHERE id = ?",
                      (generate_password_hash(new_pw), user['id']))
            db.commit()
            flash('비밀번호가 변경되었습니다.')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)


# ----------------------------------------------------------------------------
# 송금
# ----------------------------------------------------------------------------

@app.route('/topup', methods=['GET', 'POST'])
@login_required
def topup():
    """모의 결제(mock payment) 기반 잔액 충전.
    실제 PG 연동 대신 시뮬레이션하되, 한도·검증·기록은 실제와 동일하게 처리."""
    db = get_db()
    c = db.cursor()
    user = current_user()
    if request.method == 'POST':
        amount_raw = (request.form.get('amount') or '').strip()

        # [보안] 금액 형식·범위 검증 (음수/문자/과다 충전 차단)
        if not amount_raw.isdigit():
            flash('금액은 양의 정수여야 합니다.')
            return redirect(url_for('topup'))
        amount = int(amount_raw)
        if amount <= 0 or amount > TOPUP_MAX_ONCE:
            flash(f'1회 충전 한도는 {TOPUP_MAX_ONCE}원입니다.')
            return redirect(url_for('topup'))
        if user['balance'] + amount > TOPUP_MAX_BALANCE:
            flash(f'보유 잔액 상한({TOPUP_MAX_BALANCE}원)을 초과합니다.')
            return redirect(url_for('topup'))

        # [무결성] 충전과 기록을 단일 트랜잭션으로 처리
        try:
            c.execute("BEGIN")
            c.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, user['id']))
            c.execute(
                "INSERT INTO transfer (id, sender_id, receiver_id, amount, product_id, created_at) "
                "VALUES (?, ?, ?, ?, NULL, ?)",
                (str(uuid.uuid4()), 'SYSTEM', user['id'], amount, now())
            )
            db.commit()
            flash(f'{amount}원이 충전되었습니다.')
        except Exception:
            db.rollback()
            flash('충전 처리 중 오류가 발생했습니다.')
        return redirect(url_for('topup'))
    return render_template('topup.html', user=user,
                           max_once=TOPUP_MAX_ONCE, max_balance=TOPUP_MAX_BALANCE)


@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    db = get_db()
    c = db.cursor()
    user = current_user()
    if request.method == 'POST':
        to_username = (request.form.get('to_username') or '').strip()
        amount_raw = (request.form.get('amount') or '').strip()

        # [보안] 금액 검증(양의 정수, 범위)
        if not amount_raw.isdigit():
            flash('금액은 양의 정수여야 합니다.')
            return redirect(url_for('transfer'))
        amount = int(amount_raw)
        if amount <= 0 or amount > 100_000_000:
            flash('올바른 금액 범위가 아닙니다.')
            return redirect(url_for('transfer'))

        c.execute("SELECT * FROM user WHERE username = ? AND status='active'", (to_username,))
        receiver = c.fetchone()
        if not receiver:
            flash('받는 사용자를 찾을 수 없습니다.')
            return redirect(url_for('transfer'))
        if receiver['id'] == user['id']:
            flash('본인에게는 송금할 수 없습니다.')
            return redirect(url_for('transfer'))
        if user['balance'] < amount:
            flash('잔액이 부족합니다.')
            return redirect(url_for('transfer'))

        # [보안/무결성] 원자적 트랜잭션 처리 + 잔액 재확인
        try:
            c.execute("BEGIN")
            c.execute("SELECT balance FROM user WHERE id = ?", (user['id'],))
            bal = c.fetchone()['balance']
            if bal < amount:
                db.rollback()
                flash('잔액이 부족합니다.')
                return redirect(url_for('transfer'))
            c.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, user['id']))
            c.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver['id']))
            c.execute(
                "INSERT INTO transfer (id, sender_id, receiver_id, amount, product_id, created_at) "
                "VALUES (?, ?, ?, ?, NULL, ?)",
                (str(uuid.uuid4()), user['id'], receiver['id'], amount, now())
            )
            db.commit()
            flash(f'{to_username} 님에게 {amount}원 송금 완료.')
        except Exception:
            db.rollback()
            flash('송금 처리 중 오류가 발생했습니다.')
        return redirect(url_for('transfer'))

    c.execute(
        "SELECT * FROM transfer WHERE sender_id = ? OR receiver_id = ? ORDER BY created_at DESC LIMIT 20",
        (user['id'], user['id'])
    )
    history = c.fetchall()
    return render_template('transfer.html', user=user, history=history)


# ----------------------------------------------------------------------------
# 상품: 등록 / 내 상품 관리 / 수정 / 삭제 / 상세
# ----------------------------------------------------------------------------
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    """[보안] basename 처리로 경로 조작(../) 차단, 지정 폴더에서만 서빙."""
    safe = os.path.basename(filename)
    return send_from_directory(UPLOAD_FOLDER, safe)


@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        title = clean_text(request.form.get('title', ''), 100)
        description = clean_text(request.form.get('description', ''), 2000)
        price_raw = (request.form.get('price') or '').strip()

        if not title or not description:
            flash('상품명과 설명은 필수입니다.')
            return redirect(url_for('new_product'))
        if not price_raw.isdigit() or int(price_raw) > 1_000_000_000:
            flash('가격은 0 이상의 정수여야 합니다.')
            return redirect(url_for('new_product'))

        image_name, img_err = save_product_image(request.files.get('image'))
        if img_err:
            flash(img_err)
            return redirect(url_for('new_product'))

        db = get_db()
        c = db.cursor()
        c.execute(
            "INSERT INTO product (id, title, description, price, seller_id, image, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), title, description, int(price_raw),
             session['user_id'], image_name, now())
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')


@app.route('/my/products')
@login_required
def my_products():
    db = get_db()
    c = db.cursor()
    c.execute("SELECT * FROM product WHERE seller_id = ? ORDER BY created_at DESC",
              (session['user_id'],))
    return render_template('my_products.html', products=c.fetchall())


def get_owned_product(product_id):
    """상품 소유자 검증 후 반환. 아니면 None."""
    db = get_db()
    c = db.cursor()
    c.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    p = c.fetchone()
    if not p or p['seller_id'] != session['user_id']:
        return None
    return p


@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    p = get_owned_product(product_id)
    if not p:                      # [보안] 소유자 아님 -> 차단
        abort(403)
    db = get_db()
    c = db.cursor()
    if request.method == 'POST':
        title = clean_text(request.form.get('title', ''), 100)
        description = clean_text(request.form.get('description', ''), 2000)
        price_raw = (request.form.get('price') or '').strip()
        if not title or not description or not price_raw.isdigit():
            flash('입력값을 확인하세요.')
            return redirect(url_for('edit_product', product_id=product_id))
        image_name, img_err = save_product_image(request.files.get('image'))
        if img_err:
            flash(img_err)
            return redirect(url_for('edit_product', product_id=product_id))
        if image_name:
            delete_product_image(p['image'])     # 기존 이미지 정리
            c.execute("UPDATE product SET image=? WHERE id=?", (image_name, product_id))
        c.execute("UPDATE product SET title=?, description=?, price=? WHERE id=?",
                  (title, description, int(price_raw), product_id))
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('my_products'))
    return render_template('edit_product.html', product=p)


@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    p = get_owned_product(product_id)
    if not p:                      # [보안] 소유자 검증
        abort(403)
    db = get_db()
    c = db.cursor()
    c.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    delete_product_image(p['image'])
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('my_products'))



@app.route('/product/<product_id>/buy', methods=['POST'])
@login_required
def buy_product(product_id):
    """상품 구매: 잔액 검증 후 구매자->판매자 원자적 결제 처리."""
    db = get_db()
    c = db.cursor()
    buyer = current_user()

    c.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = c.fetchone()
    if not product:
        abort(404)
    # [보안] 차단/판매완료 상품 구매 차단
    if product['status'] != 'active':
        flash('구매할 수 없는 상품입니다.')
        return redirect(url_for('view_product', product_id=product_id))
    # [보안] 본인 상품 구매 방지
    if product['seller_id'] == buyer['id']:
        flash('본인이 등록한 상품은 구매할 수 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    c.execute("SELECT * FROM user WHERE id = ? AND status='active'", (product['seller_id'],))
    seller = c.fetchone()
    if not seller:
        flash('판매자 계정을 이용할 수 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    price = product['price']
    if buyer['balance'] < price:
        flash('잔액이 부족합니다.')
        return redirect(url_for('view_product', product_id=product_id))

    # [보안/무결성] 상태·잔액 재확인 후 단일 트랜잭션으로 결제
    try:
        c.execute("BEGIN")
        c.execute("SELECT status FROM product WHERE id = ?", (product_id,))
        if c.fetchone()['status'] != 'active':      # 동시 구매(race) 방지
            db.rollback()
            flash('이미 판매된 상품입니다.')
            return redirect(url_for('view_product', product_id=product_id))
        c.execute("SELECT balance FROM user WHERE id = ?", (buyer['id'],))
        if c.fetchone()['balance'] < price:
            db.rollback()
            flash('잔액이 부족합니다.')
            return redirect(url_for('view_product', product_id=product_id))

        c.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (price, buyer['id']))
        c.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (price, seller['id']))
        c.execute("UPDATE product SET status='sold', buyer_id=? WHERE id=?",
                  (buyer['id'], product_id))
        c.execute(
            "INSERT INTO transfer (id, sender_id, receiver_id, amount, product_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), buyer['id'], seller['id'], price, product_id, now())
        )
        db.commit()
        flash(f"'{product['title']}' 구매가 완료되었습니다.")
    except Exception:
        db.rollback()
        flash('구매 처리 중 오류가 발생했습니다.')
    return redirect(url_for('view_product', product_id=product_id))


@app.route('/my/purchases')
@login_required
def my_purchases():
    db = get_db()
    c = db.cursor()
    c.execute("SELECT * FROM product WHERE buyer_id = ? ORDER BY created_at DESC",
              (session['user_id'],))
    return render_template('my_purchases.html', products=c.fetchall())


@app.route('/product/<product_id>')
@login_required
def view_product(product_id):
    db = get_db()
    c = db.cursor()
    c.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = c.fetchone()
    if not product or product['status'] == 'blocked':
        abort(404)
    buyer = current_user()
    c.execute("SELECT id, username FROM user WHERE id = ?", (product['seller_id'],))
    seller = c.fetchone()
    return render_template('view_product.html', product=product, seller=seller, user=buyer)


# ----------------------------------------------------------------------------
# 신고 + 자동 차단/휴면
# ----------------------------------------------------------------------------
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    db = get_db()
    c = db.cursor()
    if request.method == 'POST':
        target_type = request.form.get('target_type')
        target_id = (request.form.get('target_id') or '').strip()
        reason = clean_text(request.form.get('reason', ''), 500)

        if target_type not in ('user', 'product') or not target_id or not reason:
            flash('신고 정보를 올바르게 입력하세요.')
            return redirect(url_for('report'))

        # 대상 존재 확인
        table = 'user' if target_type == 'user' else 'product'
        c.execute(f"SELECT id, seller_id FROM {table} WHERE id = ?", (target_id,)) \
            if target_type == 'product' else \
            c.execute("SELECT id FROM user WHERE id = ?", (target_id,))
        target = c.fetchone()
        if not target:
            flash('신고 대상을 찾을 수 없습니다.')
            return redirect(url_for('report'))

        # [보안] 자기 자신 신고 방지
        if target_type == 'user' and target_id == session['user_id']:
            flash('본인은 신고할 수 없습니다.')
            return redirect(url_for('report'))

        # [보안] 중복 신고 방지(동일 대상 1회)
        c.execute(
            "SELECT id FROM report WHERE reporter_id=? AND target_type=? AND target_id=?",
            (session['user_id'], target_type, target_id)
        )
        if c.fetchone():
            flash('이미 신고한 대상입니다.')
            return redirect(url_for('report'))

        c.execute(
            "INSERT INTO report (id, reporter_id, target_type, target_id, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), session['user_id'], target_type, target_id, reason, now())
        )
        # 신고 카운트 증가 + 임계치 도달 시 자동 조치
        if target_type == 'product':
            c.execute("UPDATE product SET report_count = report_count + 1 WHERE id = ?", (target_id,))
            c.execute("SELECT report_count FROM product WHERE id = ?", (target_id,))
            if c.fetchone()['report_count'] >= REPORT_BLOCK_THRESHOLD:
                c.execute("UPDATE product SET status='blocked' WHERE id = ?", (target_id,))
        else:
            c.execute("UPDATE user SET report_count = report_count + 1 WHERE id = ?", (target_id,))
            c.execute("SELECT report_count FROM user WHERE id = ?", (target_id,))
            if c.fetchone()['report_count'] >= REPORT_DORMANT_THRESHOLD:
                c.execute("UPDATE user SET status='dormant' WHERE id = ?", (target_id,))
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    prefill = request.args.get('target_id', '')
    ptype = request.args.get('target_type', 'product')
    return render_template('report.html', prefill=prefill, ptype=ptype)


# ----------------------------------------------------------------------------
# 관리자
# ----------------------------------------------------------------------------
@app.route('/admin')
@admin_required
def admin():
    db = get_db()
    c = db.cursor()
    c.execute("SELECT id, username, status, is_admin, report_count, balance FROM user ORDER BY created_at DESC")
    users = c.fetchall()
    c.execute("SELECT * FROM product ORDER BY created_at DESC")
    products = c.fetchall()
    c.execute("SELECT * FROM report ORDER BY created_at DESC LIMIT 50")
    reports = c.fetchall()
    return render_template('admin.html', users=users, products=products, reports=reports)


@app.route('/admin/product/<product_id>/<action>', methods=['POST'])
@admin_required
def admin_product(product_id, action):
    db = get_db()
    c = db.cursor()
    if action == 'block':
        c.execute("UPDATE product SET status='blocked' WHERE id=?", (product_id,))
    elif action == 'unblock':
        c.execute("UPDATE product SET status='active', report_count=0 WHERE id=?", (product_id,))
    elif action == 'delete':
        c.execute("DELETE FROM product WHERE id=?", (product_id,))
    else:
        abort(400)
    db.commit()
    flash('처리되었습니다.')
    return redirect(url_for('admin'))


@app.route('/admin/user/<user_id>/<action>', methods=['POST'])
@admin_required
def admin_user(user_id, action):
    db = get_db()
    c = db.cursor()
    if user_id == session['user_id']:
        flash('본인 계정에는 적용할 수 없습니다.')
        return redirect(url_for('admin'))
    if action == 'dormant':
        c.execute("UPDATE user SET status='dormant' WHERE id=?", (user_id,))
    elif action == 'activate':
        c.execute("UPDATE user SET status='active', report_count=0 WHERE id=?", (user_id,))
    else:
        abort(400)
    db.commit()
    flash('처리되었습니다.')
    return redirect(url_for('admin'))



@app.route('/admin/user/<user_id>/grant', methods=['POST'])
@admin_required
def admin_grant(user_id):
    db = get_db()
    c = db.cursor()
    amount_raw = (request.form.get('amount') or '').strip()
    if not amount_raw.isdigit() or int(amount_raw) <= 0 or int(amount_raw) > TOPUP_MAX_ONCE:
        flash('올바른 금액이 아닙니다.')
        return redirect(url_for('admin'))
    c.execute("SELECT id FROM user WHERE id = ?", (user_id,))
    if not c.fetchone():
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('admin'))
    c.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (int(amount_raw), user_id))
    c.execute(
        "INSERT INTO transfer (id, sender_id, receiver_id, amount, product_id, created_at) "
        "VALUES (?, ?, ?, ?, NULL, ?)",
        (str(uuid.uuid4()), 'ADMIN', user_id, int(amount_raw), now())
    )
    db.commit()
    flash('잔액이 지급되었습니다.')
    return redirect(url_for('admin'))


# ----------------------------------------------------------------------------
# 1:1 채팅 (DB 저장)
# ----------------------------------------------------------------------------
@app.route('/chat/<user_id>')
@login_required
def private_chat(user_id):
    db = get_db()
    c = db.cursor()
    c.execute("SELECT id, username FROM user WHERE id = ? AND status='active'", (user_id,))
    target = c.fetchone()
    if not target or user_id == session['user_id']:
        abort(404)
    me = session['user_id']
    c.execute(
        "SELECT * FROM message WHERE (sender_id=? AND receiver_id=?) "
        "OR (sender_id=? AND receiver_id=?) ORDER BY created_at",
        (me, user_id, user_id, me)
    )
    messages = c.fetchall()
    room = '_'.join(sorted([me, user_id]))   # 두 유저 고유 방
    return render_template('private_chat.html', target=target, messages=messages,
                           room=room, me=me, user=current_user())


# ----------------------------------------------------------------------------
# SocketIO 이벤트
# ----------------------------------------------------------------------------
@socketio.on('send_message')
def handle_global_message(data):
    # [보안] 인증 확인
    if 'user_id' not in session:
        return
    uid = session['user_id']
    # [보안] rate limit (스팸 방지)
    if time.time() - _chat_last.get(uid, 0) < CHAT_MIN_INTERVAL:
        return
    _chat_last[uid] = time.time()

    msg = clean_text((data or {}).get('message', ''), 300)   # [보안] 길이/XSS
    if not msg:
        return
    with app.app_context():
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        u = db.execute("SELECT username FROM user WHERE id=?", (uid,)).fetchone()
        db.close()
    username = u['username'] if u else 'unknown'
    send({'username': username, 'message': msg, 'message_id': str(uuid.uuid4())},
         broadcast=True)


@socketio.on('join_private')
def handle_join(data):
    if 'user_id' not in session:
        return
    room = (data or {}).get('room', '')
    # [보안] 방 이름에 본인 id가 포함될 때만 입장 허용
    if session['user_id'] in room.split('_'):
        join_room(room)


@socketio.on('private_message')
def handle_private_message(data):
    if 'user_id' not in session:
        return
    uid = session['user_id']
    room = (data or {}).get('room', '')
    to_id = (data or {}).get('to', '')
    if uid not in room.split('_') or to_id not in room.split('_'):
        return
    if time.time() - _chat_last.get(uid, 0) < CHAT_MIN_INTERVAL:
        return
    _chat_last[uid] = time.time()

    msg = clean_text((data or {}).get('message', ''), 300)
    if not msg:
        return
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    u = db.execute("SELECT username FROM user WHERE id=?", (uid,)).fetchone()
    db.execute(
        "INSERT INTO message (id, sender_id, receiver_id, content, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), uid, to_id, msg, now())
    )
    db.commit()
    db.close()
    emit('private_message',
         {'username': u['username'] if u else 'unknown', 'message': msg},
         room=room)


if __name__ == '__main__':
    init_db()
    # [보안] debug=False (운영). 로컬 디버깅은 FLASK_DEBUG=1 로 제어
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    # 포트는 PORT 환경변수로 변경 가능 (macOS AirPlay가 5000 점유 시 유용)
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=debug,
                 allow_unsafe_werkzeug=True)
