import discord
from discord.ext import commands
import os
import json
import requests
import asyncio
import threading
import traceback
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

TOKENS_FILE = "member_tokens.json"


def sanitize_env_value(raw_value):
    value = (raw_value or "").strip()
    if len(value) >= 2 and ((value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'")):
        value = value[1:-1].strip()
    return value


def sanitize_token(raw_token):
    token = sanitize_env_value(raw_token)
    if token.lower().startswith("bot "):
        token = token[4:].strip()
    return token


def parse_int_env(name, default="0"):
    raw_value = os.getenv(name, default)
    cleaned = sanitize_env_value(raw_value)
    if not cleaned:
        return 0, None
    try:
        return int(cleaned), None
    except ValueError:
        return 0, f"{name} must be an integer, got {raw_value!r}"


def parse_bool_env(name, default="false"):
    return sanitize_env_value(os.getenv(name, default)).lower() in {"1", "true", "yes", "on"}


def env_presence(name):
    value = sanitize_env_value(os.getenv(name, ""))
    if not value:
        return "missing"
    return f"set(len={len(value)})"


# --- 設定項目 ---
CLIENT_ID = sanitize_env_value(os.getenv("DISCORD_CLIENT_ID", ""))
CLIENT_SECRET = sanitize_env_value(os.getenv("DISCORD_CLIENT_SECRET", ""))
REDIRECT_URI = sanitize_env_value(os.getenv("DISCORD_REDIRECT_URI", ""))
BOT_TOKEN = sanitize_token(os.getenv("DISCORD_BOT_TOKEN", ""))
VERIFIED_ROLE_ID, VERIFIED_ROLE_ID_ERROR = parse_int_env("VERIFIED_ROLE_ID")
PORT, PORT_ERROR = parse_int_env("PORT", "8000")
ENABLE_MEMBERS_INTENT = parse_bool_env("ENABLE_MEMBERS_INTENT", "true")
ENABLE_MESSAGE_CONTENT_INTENT = parse_bool_env("ENABLE_MESSAGE_CONTENT_INTENT", "false")

if PORT <= 0:
    PORT = 8000


def log_startup_env():
    print(
        "Env summary: "
        f"DISCORD_BOT_TOKEN={env_presence('DISCORD_BOT_TOKEN')}, "
        f"DISCORD_CLIENT_ID={env_presence('DISCORD_CLIENT_ID')}, "
        f"DISCORD_CLIENT_SECRET={env_presence('DISCORD_CLIENT_SECRET')}, "
        f"DISCORD_REDIRECT_URI={env_presence('DISCORD_REDIRECT_URI')}, "
        f"VERIFIED_ROLE_ID={env_presence('VERIFIED_ROLE_ID')}, "
        f"PORT={env_presence('PORT')}"
    )

# --- データ管理 ---
def load_tokens():
    try:
        with open(TOKENS_FILE, "r") as f: return json.load(f)
    except: return {}

def save_token(user_id, access_token, email=None):
    tokens = load_tokens()
    tokens[str(user_id)] = {
        "access_token": access_token,
        "email": email
    }
    with open(TOKENS_FILE, "w") as f: json.dump(tokens, f, indent=4)

# --- Discord Bot本体 ---
intents = discord.Intents.default()
intents.members = ENABLE_MEMBERS_INTENT
intents.message_content = ENABLE_MESSAGE_CONTENT_INTENT
bot = commands.Bot(command_prefix='.', intents=intents)

class VerifyView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
        # 認証リンク（identify, email, guilds.joinを含める）
        url = f"https://discord.com/api/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope=identify+email+guilds.join"
        self.add_item(discord.ui.Button(label="認証する", url=url, emoji="✅", style=discord.ButtonStyle.link))

@bot.event
async def on_ready():
    print(f"✅ Bot Logged in as {bot.user}")

@bot.command()
@commands.has_permissions(administrator=True)
async def setup_verify(ctx):
    """認証パネルを設置するコマンド"""
    embed = discord.Embed(
        title="✅ 認証パネル",
        description="👤 **認証をしてサーバーを楽しみましょう！！！** 👤\n\n🛡️ **認証後に <@&{VERIFIED_ROLE_ID}> が付与されます**\n\n下のボタンを押して認証を開始してください。\n認証後、自動的にロールが付与されます。".format(VERIFIED_ROLE_ID=VERIFIED_ROLE_ID),
        color=0x2b2d31
    )
    # 画像のURL（必要に応じて変更してください）
    embed.set_thumbnail(url="https://ui-avatars.com/api/?name=Auth&background=3b82f6&color=fff")
    await ctx.send(embed=embed, view=VerifyView())

@bot.command()
@commands.has_permissions(administrator=True)
async def join(ctx, target_guild_id: int):
    """保存されたトークンを使ってメンバーをターゲットサーバーへ追加"""
    tokens = load_tokens()
    await ctx.send(f"🔄 {len(tokens)}人の移行を開始します...")
    
    success = 0
    for user_id, access_token in tokens.items():
        token_data = access_token if isinstance(access_token, str) else access_token.get("access_token", "")
        url = f"https://discord.com/api/v10/guilds/{target_guild_id}/members/{user_id}"
        headers = {"Authorization": f"Bot {BOT_TOKEN}", "Content-Type": "application/json"}
        payload = {"access_token": token_data}
        
        r = requests.put(url, headers=headers, json=payload)
        if r.status_code in [201, 204]:
            success += 1
            print(f"  ✅ {user_id} を追加しました")
        else:
            print(f"  ❌ {user_id} 失敗: {r.status_code} {r.text}")
        await asyncio.sleep(1) # レート制限対策

    await ctx.send(f"✅ 移行完了: {success}人が参加しました。")

# --- Webサーバー (Flask) ---
app = Flask(__name__)
CORS(app)


@app.route('/')
def health_check():
    return jsonify({'status': 'ok'}), 200

def exchange_code_for_token(code):
    """認証コードをアクセストークンに交換し、ユーザー情報を取得する共通処理"""
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.post('https://discord.com/api/oauth2/token', data=data, headers=headers)
    token_json = r.json()
    
    access_token = token_json.get('access_token')
    if not access_token:
        print(f"❌ トークン交換失敗: {token_json}")
        return None
    
    # ユーザー情報の取得（ID + email）
    user_r = requests.get('https://discord.com/api/v10/users/@me', headers={'Authorization': f'Bearer {access_token}'})
    user_data = user_r.json()
    user_id = user_data.get('id')
    email = user_data.get('email')
    username = user_data.get('username', 'Unknown')
    
    if user_id and access_token:
        save_token(user_id, access_token, email)
        asyncio.run_coroutine_threadsafe(give_role(user_id), bot.loop)
        print(f"✅ 認証完了: {username} ({user_id}) | Email: {email}")
        return {'user_id': user_id, 'username': username, 'email': email}
    
    return None

@app.route('/callback')
def callback():
    """直接リダイレクト用（localhost使用時）"""
    code = request.args.get('code')
    if not code: return "無効なリクエストです", 400
    
    result = exchange_code_for_token(code)
    if result:
        try:
            with open("DiscordWebAuth/index.html", "r", encoding="utf-8") as f:
                return f.read(), 200
        except:
            return "<h1>認証に成功しました！</h1>Discordに戻ってください。", 200
    
    return "<h1>認証に失敗しました</h1>トークンの取得ができませんでした。", 500

@app.route('/api/exchange-code', methods=['POST'])
def api_exchange_code():
    """Cloudflare Pages等の外部サイトからコードを受け取るAPI"""
    body = request.get_json()
    code = body.get('code') if body else None
    if not code:
        return jsonify({'success': False, 'message': 'Code required'}), 400
    
    result = exchange_code_for_token(code)
    if result:
        return jsonify({'success': True, 'user': result})
    
    return jsonify({'success': False, 'message': 'Token exchange failed'}), 500

async def give_role(user_id):
    """特定のサーバーでロールを付与する"""
    for guild in bot.guilds:
        try:
            # キャッシュではなくAPIから取得（確実に見つかる）
            member = guild.get_member(int(user_id))
            if not member:
                member = await guild.fetch_member(int(user_id))
            if member:
                role = guild.get_role(VERIFIED_ROLE_ID)
                if role:
                    await member.add_roles(role, reason="Web認証完了")
                    print(f"👑 {member.name} にロールを付与しました ({guild.name})")
                else:
                    print(f"⚠️ ロールID {VERIFIED_ROLE_ID} が見つかりません ({guild.name})")
        except discord.NotFound:
            pass  # このサーバーにはいないメンバー
        except Exception as e:
            print(f"❌ ロール付与エラー: {e}")

def run_web():
    try:
        from waitress import serve
        print(f"Web API listening on 0.0.0.0:{PORT} via waitress")
        serve(app, host='0.0.0.0', port=PORT)
    except Exception as e:
        print(f"waitress unavailable, falling back to Flask dev server: {e}")
        app.run(host='0.0.0.0', port=PORT, use_reloader=False)


def validate_config():
    missing = []
    invalid = []
    if not BOT_TOKEN:
        missing.append("DISCORD_BOT_TOKEN")
    if not CLIENT_ID:
        missing.append("DISCORD_CLIENT_ID")
    if not CLIENT_SECRET:
        missing.append("DISCORD_CLIENT_SECRET")
    if not REDIRECT_URI:
        missing.append("DISCORD_REDIRECT_URI")
    if VERIFIED_ROLE_ID_ERROR:
        invalid.append(VERIFIED_ROLE_ID_ERROR)
    if VERIFIED_ROLE_ID <= 0:
        missing.append("VERIFIED_ROLE_ID")
    if PORT_ERROR:
        invalid.append(PORT_ERROR)
    if invalid:
        raise RuntimeError("Invalid environment variables: " + "; ".join(invalid))
    if missing:
        raise RuntimeError("Missing required environment variables: " + ", ".join(missing))


def main():
    try:
        log_startup_env()
        validate_config()
        threading.Thread(target=run_web, daemon=True).start()
        print(f"Starting bot with intents: members={intents.members}, message_content={intents.message_content}")
        bot.run(BOT_TOKEN)
    except Exception as e:
        print(f"Startup failure: {e}")
        traceback.print_exc()
        raise


if __name__ == "__main__":
    main()

    main()
