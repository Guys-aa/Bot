import discord
from discord.ext import commands
import os
import json
import secrets
import requests
import asyncio
import threading
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

# --- 設定項目 ---
VERIFIED_ROLE_ID = 1452162563478388756  # 認証後に付与するロールID

TOKENS_FILE = "member_tokens.json"

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
intents.members = True
intents.message_content = True
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
    app.run(host='0.0.0.0', port=8000)

# スレッドでWebサーバーを起動
threading.Thread(target=run_web, daemon=True).start()

if __name__ == "__main__":
    bot.run(BOT_TOKEN)
