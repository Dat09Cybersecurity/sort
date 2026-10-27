"""
Kênh liên lạc an toàn: DH + Chữ ký số + mini-PKI + AEAD + Ví dụ số nhỏ
Chạy: pip install flask pycryptodome && python app.py
"""
import os, json, time, hashlib, hmac, base64, statistics
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, jsonify
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pss, DSS, eddsa
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

app = Flask(__name__)
STORE = {'CA': None, 'Alice': None, 'Bob': None, 'certs': {}, 'crl': []}


# ============================================================
# KHÓA
# ============================================================
def gen_keypair(alg, bits=2048):
    alg = alg.upper()
    if alg == 'RSA':
        k = RSA.generate(int(bits))
        return {'alg':'RSA','private_pem':k.export_key().decode(),
                'public_pem':k.publickey().export_key().decode()}
    if alg == 'ECDSA':
        k = ECC.generate(curve='P-256')
        return {'alg':'ECDSA','private_pem':k.export_key(format='PEM'),
                'public_pem':k.public_key().export_key(format='PEM')}
    if alg == 'ED25519':
        k = ECC.generate(curve='Ed25519')
        return {'alg':'ED25519','private_pem':k.export_key(format='PEM'),
                'public_pem':k.public_key().export_key(format='PEM')}
    raise ValueError(alg)


def fingerprint(pub_pem):
    return hashlib.sha256(pub_pem.encode()).digest()[:16].hex()


# ============================================================
# BĂM / HMAC
# ============================================================
def hash_all(data):
    return {'sha256':hashlib.sha256(data).hexdigest(),
            'sha1':hashlib.sha1(data).hexdigest(),
            'md5':hashlib.md5(data).hexdigest()}


def avalanche(t1, t2):
    h1 = hashlib.sha256(t1.encode()).digest()
    h2 = hashlib.sha256(t2.encode()).digest()
    return sum(bin(a^b).count('1') for a,b in zip(h1,h2))


# ============================================================
# KÝ / VERIFY
# ============================================================
def sign_data(priv_pem, alg, data):
    t0 = time.perf_counter(); alg = alg.upper()
    if alg == 'RSA':
        sig = pss.new(RSA.import_key(priv_pem)).sign(SHA256.new(data))
    elif alg == 'ECDSA':
        sig = DSS.new(ECC.import_key(priv_pem),'fips-186-3').sign(SHA256.new(data))
    elif alg == 'ED25519':
        sig = eddsa.new(ECC.import_key(priv_pem),'rfc8032').sign(data)
    else: raise ValueError(alg)
    return sig, (time.perf_counter()-t0)*1000


def verify_sig(pub_pem, alg, data, sig):
    t0 = time.perf_counter()
    try:
        alg = alg.upper()
        if alg == 'RSA':
            pss.new(RSA.import_key(pub_pem)).verify(SHA256.new(data), sig)
        elif alg == 'ECDSA':
            DSS.new(ECC.import_key(pub_pem),'fips-186-3').verify(SHA256.new(data), sig)
        elif alg == 'ED25519':
            eddsa.new(ECC.import_key(pub_pem),'rfc8032').verify(data, sig)
        else: return False, f"Thuật toán lạ: {alg}", 0
        return True, "Hợp lệ", (time.perf_counter()-t0)*1000
    except (ValueError, TypeError) as e:
        return False, f"Chữ ký không hợp lệ ({e.__class__.__name__})", (time.perf_counter()-t0)*1000


# ============================================================
# MINI-PKI
# ============================================================
def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',',':')).encode()


def issue_cert(ca_priv, ca_alg, subject, pub_pem, serial, days=365):
    now = datetime.now(timezone.utc)
    body = {'subject':subject,'public_key':pub_pem,
            'not_before':now.isoformat(),
            'not_after':(now+timedelta(days=days)).isoformat(),
            'serial':serial,'issuer':'MiniRootCA'}
    sig,_ = sign_data(ca_priv, ca_alg, canonical(body))
    cert = dict(body)
    cert['signature'] = base64.b64encode(sig).decode()
    cert['sig_alg'] = ca_alg
    return cert


def verify_cert(cert, ca_pub, ca_alg, expected_subject, crl):
    errs = []
    body = {k:cert[k] for k in ('subject','public_key','not_before',
                                 'not_after','serial','issuer')}
    try:
        sig = base64.b64decode(cert['signature'])
        ok,reason,_ = verify_sig(ca_pub, ca_alg, canonical(body), sig)
        if not ok: errs.append(f"Chữ ký CA sai: {reason}")
    except Exception as e:
        errs.append(f"Không đọc được chữ ký: {e}")
    now = datetime.now(timezone.utc)
    try:
        if now < datetime.fromisoformat(cert['not_before']):
            errs.append("Chứng thư chưa có hiệu lực")
        if now > datetime.fromisoformat(cert['not_after']):
            errs.append("Chứng thư đã hết hạn")
    except Exception: errs.append("Thời gian không hợp lệ")
    if cert.get('subject') != expected_subject:
        errs.append(f"Tên chủ thể không khớp (có '{cert.get('subject')}', mong đợi '{expected_subject}')")
    if cert.get('serial') in crl:
        errs.append(f"Chứng thư đã bị thu hồi (serial={cert.get('serial')})")
    return {'ok':len(errs)==0, 'errors':errs}


# ============================================================
# DH / HKDF
# ============================================================
def dh_small(p=23, g=5, a=6, b=15):
    A,B = pow(g,a,p), pow(g,b,p)
    Ka,Kb = pow(B,a,p), pow(A,b,p)
    return {'p':p,'g':g,'a':a,'b':b,'A':A,'B':B,
            'K_Alice':Ka,'K_Bob':Kb,'match':Ka==Kb}


def derive_key(shared):
    return HKDF(shared, 32, b'', SHA256, 1)


# ============================================================
# AEAD
# ============================================================
def aes_enc(key, pt, aad):
    n = get_random_bytes(12)
    c = AES.new(key, AES.MODE_GCM, nonce=n); c.update(aad)
    ct,tag = c.encrypt_and_digest(pt); return n,ct,tag

def aes_dec(key, n, ct, tag, aad):
    try:
        c = AES.new(key, AES.MODE_GCM, nonce=n); c.update(aad)
        return True, c.decrypt_and_verify(ct, tag), "OK"
    except (ValueError, KeyError):
        return False, None, "Thẻ xác thực không hợp lệ"

def cha_enc(key, pt, aad):
    n = get_random_bytes(12)
    c = ChaCha20_Poly1305.new(key=key, nonce=n); c.update(aad)
    ct,tag = c.encrypt_and_digest(pt); return n,ct,tag

def cha_dec(key, n, ct, tag, aad):
    try:
        c = ChaCha20_Poly1305.new(key=key, nonce=n); c.update(aad)
        return True, c.decrypt_and_verify(ct, tag), "OK"
    except (ValueError, KeyError):
        return False, None, "Thẻ xác thực không hợp lệ"


# ============================================================
# MITM
# ============================================================
def mitm_plain(p=23, g=5, a=6, b=15, e=9):
    A,B,E = pow(g,a,p), pow(g,b,p), pow(g,e,p)
    K1,K2 = pow(E,a,p), pow(E,b,p)
    log = [
        f"[Setup] p={p}, g={g}, a(Alice)={a}, b(Bob)={b}, e(Eve)={e}",
        f"[Alice] A = g^a mod p = {A}",
        f"[Bob]   B = g^b mod p = {B}",
        f"[Eve]   E = g^e mod p = {E}   (chặn A, B; gửi E cho cả 2)",
        f"[Alice] K_Alice = E^a mod p = {K1}",
        f"[Eve]   K1 = A^e mod p = {pow(A,e,p)}  -> biết khóa Alice-Eve",
        f"[Eve]   K2 = B^e mod p = {pow(B,e,p)}  -> biết khóa Eve-Bob",
        f"[Bob]   K_Bob = E^b mod p = {K2}",
        f"",
        f"=> K_Alice = {K1}  !=  K_Bob = {K2}",
        f"=> Eve đọc/giả mạo được MỌI tin giữa Alice và Bob!",
    ]
    return {'K1':K1,'K2':K2,'log':log}


def mitm_auth(p=23, g=5):
    log = [
        f"[Setup] p={p}, g={g}",
        "[Alice] Ký A bằng khóa dài hạn => gửi (A, sig_A, cert_Alice)",
        "[Bob]   Ký B bằng khóa dài hạn => gửi (B, sig_B, cert_Bob)",
        "[Eve]   Chặn A, gửi E cho Bob (kèm sig giả)",
        "[Bob]   Verify sig bằng public key trong cert_Alice -> SAI",
        "[Bob]   Phát hiện MITM => TỪ CHỐI",
        "[Eve]   Nếu dùng cert Eve: verify OK, subject='Eve' != 'Alice' => TỪ CHỐI",
        "",
        "KẾT LUẬN: MITM THẤT BẠI (nhờ chữ ký + tên chủ thể)",
    ]
    return {'blocked':True,'log':log}


# ============================================================
# BENCHMARK
# ============================================================
def bench_sign(alg, n=20, bits=2048):
    data = b"benchmark"
    kg,sg,vf,ks,ss = [],[],[],[],[]
    for _ in range(n):
        t0=time.perf_counter(); kp=gen_keypair(alg,bits); kg.append(time.perf_counter()-t0)
        t0=time.perf_counter(); sig,_=sign_data(kp['private_pem'],alg,data); sg.append(time.perf_counter()-t0)
        t0=time.perf_counter(); verify_sig(kp['public_pem'],alg,data,sig); vf.append(time.perf_counter()-t0)
        ks.append(len(kp['public_pem'])); ss.append(len(sig))
    return {'alg':alg,'bits':bits if alg=='RSA' else '-',
            'keygen_ms':statistics.mean(kg)*1000,
            'sign_ms':statistics.mean(sg)*1000,
            'verify_ms':statistics.mean(vf)*1000,
            'key_size':statistics.mean(ks),
            'sig_size':statistics.mean(ss)}


def bench_aead(n=20, size_mb=1):
    data = os.urandom(int(size_mb*1024*1024))
    key = get_random_bytes(32); aad = b"hdr"
    at,ct_t = [],[]
    for _ in range(n):
        t0=time.perf_counter()
        nn,cc,tt=aes_enc(key,data,aad); aes_dec(key,nn,cc,tt,aad)
        at.append(time.perf_counter()-t0)
        t0=time.perf_counter()
        nn,cc,tt=cha_enc(key,data,aad); cha_dec(key,nn,cc,tt,aad)
        ct_t.append(time.perf_counter()-t0)
    return {'aes_gcm_ms':statistics.mean(at)*1000,
            'chacha_ms':statistics.mean(ct_t)*1000,
            'size_mb':size_mb}


# ============================================================
# VÍ DỤ SỐ NHỎ (TOY)
# ============================================================
def rsa_toy(n=1247, e=59, d=299, m=20):
    s = pow(m, d, n)
    m_check = pow(s, e, n)
    return {'n':n,'e':e,'d':d,'m':m,'s':s,'m_check':m_check,'ok':m==m_check}


def rsa_forgery(n=1247, e=59, d=299, m1=5, m2=7):
    s1 = pow(m1,d,n); s2 = pow(m2,d,n)
    target = (m1*m2) % n
    sig_forged = (s1*s2) % n
    m_rec = pow(sig_forged, e, n)
    return {'m1':m1,'m2':m2,'target':target,
            'sig1':s1,'sig2':s2,'sig_forged':sig_forged,
            'm_recovered':m_rec,'ok':m_rec==target}


def elgamal_toy(p=23, g=5, x=6, m=10, k=7):
    y = pow(g,x,p)
    r = pow(g,k,p)
    # k^{-1} mod (p-1)
    try: k_inv = pow(k, -1, p-1)
    except ValueError:
        return {'error': f'k={k} không nguyên tố cùng nhau với p-1={p-1}'}
    s = ((m - x*r) * k_inv) % (p-1)
    left = pow(g,m,p)
    right = (pow(y,r,p) * pow(r,s,p)) % p
    return {'p':p,'g':g,'x':x,'m':m,'k':k,'y':y,'r':r,'s':s,
            'left':left,'right':right,'ok':left==right}


def _ec_add(P,Q,a,p):
    if P is None: return Q
    if Q is None: return P
    x1,y1 = P; x2,y2 = Q
    if x1==x2 and (y1+y2)%p==0: return None
    if P==Q:
        m = (3*x1*x1+a)*pow(2*y1,-1,p) % p
    else:
        m = (y2-y1)*pow(x2-x1,-1,p) % p
    x3 = (m*m-x1-x2)%p
    y3 = (m*(x1-x3)-y1)%p
    return (x3,y3)


def _ec_mul(k,P,a,p):
    R = None
    for bit in bin(k)[2:]:
        R = _ec_add(R,R,a,p)
        if bit=='1': R = _ec_add(R,P,a,p)
    return R


def ecdsa_toy(p=17, a=3, b=5, Gx=5, Gy=3, n=23, d=7, h=10, k=5):
    G = (Gx,Gy)
    try:
        Q = _ec_mul(d,G,a,p)
        R = _ec_mul(k,G,a,p)
        if R is None: return {'error':'k*G = điểm vô cực'}
        r = R[0] % n
        try: k_inv = pow(k,-1,n)
        except ValueError: return {'error':f'k={k} không khả nghịch mod n={n}'}
        s = (k_inv * (h + d*r)) % n
        try: s_inv = pow(s,-1,n)
        except ValueError: return {'error':f's={s} không khả nghịch mod n={n}'}
        u1 = (h*s_inv)%n; u2 = (r*s_inv)%n
        X = _ec_add(_ec_mul(u1,G,a,p), _ec_mul(u2,Q,a,p), a, p)
        on_curve = lambda P: P and (P[1]**2 - (P[0]**3+a*P[0]+b))%p==0
        return {'p':p,'a':a,'b':b,'G':G,'n':n,'d':d,'h':h,'k':k,
                'Q':Q,'r':r,'s':s,'X':X,
                'ok': X is not None and (X[0]%n)==r and on_curve(X)}
    except Exception as e:
        return {'error':str(e)}


def blom_toy(p=17, D=None, r_U=12, r_V=7):
    if D is None: D = [[8,7],[7,2]]
    def poly_for(r_id):
        coeffs = []
        for j in range(len(D)):
            c = sum(D[i][j]*pow(r_id,i,p) for i in range(len(D))) % p
            coeffs.append(c)
        return coeffs
    cU = poly_for(r_U); cV = poly_for(r_V)
    KU = sum(cU[j]*pow(r_V,j,p) for j in range(len(cU))) % p
    KV = sum(cV[j]*pow(r_U,j,p) for j in range(len(cV))) % p
    return {'p':p,'D':D,'r_U':r_U,'r_V':r_V,
            'gU_coeffs':cU,'gV_coeffs':cV,
            'K_U':KU,'K_V':KV,'ok':KU==KV}


# ============================================================
# ROUTES
# ============================================================
@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/genkey', methods=['POST'])
def api_genkey():
    d = request.json
    kp = gen_keypair(d['alg'], d.get('bits', 2048))
    kp['fingerprint'] = fingerprint(kp['public_pem'])
    STORE[d['entity']] = kp
    return jsonify({'entity':d['entity'],'alg':kp['alg'],
                    'public_pem':kp['public_pem'],'fingerprint':kp['fingerprint']})

@app.route('/api/hash', methods=['POST'])
def api_hash():
    t = request.json.get('text','')
    r = hash_all(t.encode())
    if t:
        t2 = (t[:1] + ('b' if t[1:2]!='b' else 'c') + t[2:]) if len(t)>1 else t+'b'
        r['avalanche_bits'] = avalanche(t, t2)
        r['avalanche_pair'] = [t, t2]
    return jsonify(r)

@app.route('/api/hmac', methods=['POST'])
def api_hmac():
    d = request.json
    k,m = d.get('key','').encode(), d.get('msg','').encode()
    tag = hmac.new(k,m,hashlib.sha256).hexdigest()
    good = hmac.compare_digest(tag, hmac.new(k,m,hashlib.sha256).hexdigest())
    bad  = hmac.compare_digest(tag, hmac.new(k,m+b'x',hashlib.sha256).hexdigest())
    return jsonify({'tag':tag,'valid':good,'invalid_demo':bad})

@app.route('/api/sign', methods=['POST'])
def api_sign():
    d = request.json
    kp = STORE.get(d['entity'])
    if not kp: return jsonify({'error':'Chưa sinh khóa'}),400
    sig,ms = sign_data(kp['private_pem'], kp['alg'], d.get('msg','').encode())
    return jsonify({'signature_b64':base64.b64encode(sig).decode(),
                    'sig_size':len(sig),'sign_ms':ms})

@app.route('/api/verify', methods=['POST'])
def api_verify():
    d = request.json
    kp = STORE.get(d['entity'])
    if not kp: return jsonify({'error':'Chưa sinh khóa'}),400
    sig = base64.b64decode(d['signature_b64'])
    ok,reason,ms = verify_sig(kp['public_pem'], kp['alg'], d.get('msg','').encode(), sig)
    return jsonify({'ok':ok,'reason':reason,'verify_ms':ms})

@app.route('/api/issue_cert', methods=['POST'])
def api_issue_cert():
    d = request.json
    ca = STORE.get('CA'); subj = STORE.get(d['subject'])
    if not ca or not subj: return jsonify({'error':'Cần sinh khóa CA và subject'}),400
    serial = f"{d['subject']}-{int(time.time())}"
    cert = issue_cert(ca['private_pem'], ca['alg'], d['subject'],
                      subj['public_pem'], serial, d.get('days',365))
    STORE['certs'][d['subject']] = cert
    return jsonify(cert)

@app.route('/api/verify_cert', methods=['POST'])
def api_verify_cert():
    d = request.json
    ca = STORE.get('CA')
    if not ca: return jsonify({'error':'Chưa có CA'}),400
    return jsonify(verify_cert(d['cert'], ca['public_pem'], ca['alg'],
                                d['subject'], STORE['crl']))

@app.route('/api/revoke', methods=['POST'])
def api_revoke():
    STORE['crl'].append(request.json['serial'])
    return jsonify({'crl':STORE['crl']})

@app.route('/api/dh_small', methods=['POST'])
def api_dh_small():
    d = request.json or {}
    try:
        return jsonify(dh_small(int(d.get('p',23)), int(d.get('g',5)),
                                 int(d.get('a',6)), int(d.get('b',15))))
    except Exception as e:
        return jsonify({'error':str(e)})

@app.route('/api/ecdh_demo', methods=['POST'])
def api_ecdh_demo():
    A = ECC.generate(curve='P-256'); B = ECC.generate(curve='P-256')
    P = B.pointQ * A.d
    shared = int(P.x).to_bytes(32,'big')
    key = derive_key(shared)
    msg = b"Hello Bob (ECDH P-256 demo)"
    aad = b"Alice->Bob#1"
    n,ct,tag = aes_enc(key, msg, aad)
    return jsonify({'session_key_hash':hashlib.sha256(key).hexdigest()[:32],
                    'nonce_b64':base64.b64encode(n).decode(),
                    'ct_b64':base64.b64encode(ct).decode(),
                    'tag_b64':base64.b64encode(tag).decode(),
                    'aad':aad.decode()})

@app.route('/api/aead', methods=['POST'])
def api_aead():
    d = request.json
    key = base64.b64decode(d['key_b64'])
    pt = base64.b64decode(d['plaintext_b64'])
    aad = d.get('aad','').encode()
    fn = aes_enc if d.get('alg','AES')=='AES' else cha_enc
    n,ct,tag = fn(key,pt,aad)
    return jsonify({'nonce_b64':base64.b64encode(n).decode(),
                    'ct_b64':base64.b64encode(ct).decode(),
                    'tag_b64':base64.b64encode(tag).decode()})

@app.route('/api/aead_decrypt', methods=['POST'])
def api_aead_decrypt():
    d = request.json
    try:
        key = base64.b64decode(d['key_b64'])
        n = base64.b64decode(d['nonce_b64'])
        ct = base64.b64decode(d['ct_b64'])
        tag = base64.b64decode(d['tag_b64'])
    except Exception as e:
        return jsonify({'ok':False,'reason':f'Lỗi base64: {e}'})
    aad = d.get('aad','').encode()
    fn = aes_dec if d.get('alg','AES')=='AES' else cha_dec
    ok,pt,reason = fn(key,n,ct,tag,aad)
    return jsonify({'ok':ok,'reason':reason,
                    'plaintext_b64':base64.b64encode(pt).decode() if ok else None})

@app.route('/api/mitm_plain', methods=['POST'])
def api_mitm_plain():
    d = request.json or {}
    return jsonify(mitm_plain(int(d.get('p',23)), int(d.get('g',5)),
                              int(d.get('a',6)), int(d.get('b',15)),
                              int(d.get('e',9))))

@app.route('/api/mitm_auth', methods=['POST'])
def api_mitm_auth():
    d = request.json or {}
    return jsonify(mitm_auth(int(d.get('p',23)), int(d.get('g',5))))

@app.route('/api/benchmark_sign', methods=['POST'])
def api_bench_sign():
    d = request.json or {}
    n = int(d.get('n', 20))
    bits = int(d.get('bits', 2048))
    out = [bench_sign('RSA', n, bits),
           bench_sign('ECDSA', n),
           bench_sign('ED25519', n)]
    if d.get('rsa3072'):
        out.insert(1, bench_sign('RSA', n, 3072))
    return jsonify(out)

@app.route('/api/benchmark_aead', methods=['POST'])
def api_bench_aead():
    d = request.json or {}
    return jsonify(bench_aead(int(d.get('n',20)), int(d.get('size_mb',1))))

# --- TOY ---
@app.route('/api/rsa_toy', methods=['POST'])
def api_rsa_toy():
    d = request.json or {}
    try:
        return jsonify(rsa_toy(int(d.get('n',1247)), int(d.get('e',59)),
                                int(d.get('d',299)), int(d.get('m',20))))
    except Exception as e: return jsonify({'error':str(e)})

@app.route('/api/rsa_forgery', methods=['POST'])
def api_rsa_forgery():
    d = request.json or {}
    try:
        return jsonify(rsa_forgery(int(d.get('n',1247)), int(d.get('e',59)),
                                    int(d.get('d',299)),
                                    int(d.get('m1',5)), int(d.get('m2',7))))
    except Exception as e: return jsonify({'error':str(e)})

@app.route('/api/elgamal_toy', methods=['POST'])
def api_elgamal_toy():
    d = request.json or {}
    try:
        return jsonify(elgamal_toy(int(d.get('p',23)), int(d.get('g',5)),
                                    int(d.get('x',6)), int(d.get('m',10)),
                                    int(d.get('k',7))))
    except Exception as e: return jsonify({'error':str(e)})

@app.route('/api/ecdsa_toy', methods=['POST'])
def api_ecdsa_toy():
    d = request.json or {}
    try:
        return jsonify(ecdsa_toy(int(d.get('p',17)), int(d.get('a',3)),
                                  int(d.get('b',5)),
                                  int(d.get('Gx',5)), int(d.get('Gy',3)),
                                  int(d.get('n',23)), int(d.get('d',7)),
                                  int(d.get('h',10)), int(d.get('k',5))))
    except Exception as e: return jsonify({'error':str(e)})

@app.route('/api/blom_toy', methods=['POST'])
def api_blom_toy():
    d = request.json or {}
    try:
        D = d.get('D')
        if D is not None:
            D = [[int(x) for x in row] for row in D]
        return jsonify(blom_toy(int(d.get('p',17)), D,
                                int(d.get('r_U',12)), int(d.get('r_V',7))))
    except Exception as e: return jsonify({'error':str(e)})


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)