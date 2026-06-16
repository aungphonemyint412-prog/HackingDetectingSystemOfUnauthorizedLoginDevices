import pymysql

DB = dict(host='thomas.proxy.rlwy.net', port=29978, user='root',
          password='ZBpoilVhllsEVbTKIeOiaBzCMjxEVcoe', database='railway')

conn = pymysql.connect(**DB)
cur  = conn.cursor()

print('=' * 72)
print('  RAILWAY MySQL  |  database: railway')
print('=' * 72)

# users
print('\nTABLE: users')
print('-' * 72)
cur.execute('SELECT id, username, email, email_verified, created_at FROM users')
rows = cur.fetchall()
print(f"  {'id':<4}  {'username':<28}  {'email':<30}  ver  created_at")
print(f"  {'-'*4}  {'-'*28}  {'-'*30}  ---  -------------------")
for r in rows:
    print(f"  {r[0]:<4}  {r[1]:<28}  {r[2]:<30}  {r[3]:<3}  {r[4]}")

# login_history
print('\nTABLE: login_history')
print('-' * 72)
cur.execute('SELECT id, user_id, ip_address, login_status, login_time, is_suspicious FROM login_history')
rows = cur.fetchall()
print(f"  {'id':<4}  {'user':<5}  {'ip':<16}  {'status':<9}  {'login_time':<20}  susp")
print(f"  {'-'*4}  {'-'*5}  {'-'*16}  {'-'*9}  {'-'*20}  ----")
for r in rows:
    print(f"  {r[0]:<4}  {r[1]:<5}  {str(r[2]):<16}  {str(r[3]):<9}  {str(r[4]):<20}  {r[5]}")

# otp_codes
print('\nTABLE: otp_codes')
print('-' * 72)
cur.execute('SELECT id, user_id, code, is_used, expires_at, created_at FROM otp_codes')
rows = cur.fetchall()
print(f"  {'id':<4}  {'user':<5}  {'code':<5}  used  {'expires_at':<20}  created_at")
print(f"  {'-'*4}  {'-'*5}  {'-'*5}  ----  {'-'*20}  -------------------")
for r in rows:
    print(f"  {r[0]:<4}  {r[1]:<5}  {r[2]:<5}  {r[3]:<4}  {str(r[4]):<20}  {r[5]}")

print('\n' + '=' * 72)
conn.close()
