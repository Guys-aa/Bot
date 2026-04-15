import discord
from discord.ext import commands
import os
import json
import time
import hmac
import base64
import hashlib
import requests
import asyncio
import threading
import traceback
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from urllib.parse import urlencode

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


def get_env_value(*names, default=""):
    for name in names:
        raw_value = os.getenv(name)
        cleaned = sanitize_env_value(raw_value)
        if cleaned:
            return cleaned, name
    return sanitize_env_value(default), None


def parse_int_env(names, default="0"):
    raw_value, source_name = get_env_value(*names, default=default)
    cleaned = sanitize_env_value(raw_value)
    if not cleaned:
        return 0, None, source_name
    try:
        return int(cleaned), None, source_name
    except ValueError:
        label = "/".join(names)
        return 0, f"{label} must be an integer, got {raw_value!r}", source_name


def parse_bool_env(names, default="false"):
    raw_value, _ = get_env_value(*names, default=default)
    return sanitize_env_value(raw_value).lower() in {"1", "true", "yes", "on"}


def env_presence(*names):
    value, source_name = get_env_value(*names)
    if not value:
        return "missing"
    return f"set(len={len(value)}, source={source_name})"


# --- 設定項目 ---
CLIENT_ID, CLIENT_ID_SOURCE = get_env_value("DISCORD_CLIENT_ID", "CLIENT_ID")
CLIENT_SECRET, CLIENT_SECRET_SOURCE = get_env_value("DISCORD_CLIENT_SECRET", "CLIENT_SECRET")
REDIRECT_URI, REDIRECT_URI_SOURCE = get_env_value("DISCORD_REDIRECT_URI", "REDIRECT_URI")
BOT_TOKEN_RAW, BOT_TOKEN_SOURCE = get_env_value("DISCORD_BOT_TOKEN", "BOT_TOKEN", "TOKEN")
BOT_TOKEN = sanitize_token(BOT_TOKEN_RAW)
VERIFIED_ROLE_ID, VERIFIED_ROLE_ID_ERROR, VERIFIED_ROLE_ID_SOURCE = parse_int_env(("VERIFIED_ROLE_ID", "ROLE_ID"))
GUILD_ID, GUILD_ID_ERROR, GUILD_ID_SOURCE = parse_int_env(("GUILD_ID", "TARGET_GUILD_ID"))
PORT, PORT_ERROR, PORT_SOURCE = parse_int_env(("PORT",), "8000")
ENABLE_MEMBERS_INTENT = parse_bool_env(("ENABLE_MEMBERS_INTENT", "MEMBERS_INTENT"), "true")
ENABLE_MESSAGE_CONTENT_INTENT = parse_bool_env(("ENABLE_MESSAGE_CONTENT_INTENT", "MESSAGE_CONTENT_INTENT"), "true")

if PORT <= 0:
    PORT = 8000


def log_startup_env():
    print(
        "Env summary: "
        f"BOT_TOKEN={env_presence('DISCORD_BOT_TOKEN', 'BOT_TOKEN', 'TOKEN')}, "
        f"CLIENT_ID={env_presence('DISCORD_CLIENT_ID', 'CLIENT_ID')}, "
        f"CLIENT_SECRET={env_presence('DISCORD_CLIENT_SECRET', 'CLIENT_SECRET')}, "
        f"REDIRECT_URI={env_presence('DISCORD_REDIRECT_URI', 'REDIRECT_URI')}, "
        f"VERIFIED_ROLE_ID={env_presence('VERIFIED_ROLE_ID', 'ROLE_ID')}, "
        f"GUILD_ID={env_presence('GUILD_ID', 'TARGET_GUILD_ID')}, "
        f"PORT={env_presence('PORT')}"
    )


def get_state_secret():
    secret = CLIENT_SECRET or BOT_TOKEN
    return secret.encode("utf-8", errors="ignore")


def build_oauth_state(guild_id, role_id):
    payload = {
        "guild_id": int(guild_id),
        "role_id": int(role_id),
        "ts": int(time.time()),
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode("ascii").rstrip("=")
    signature = hmac.new(get_state_secret(), payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{signature}"


def parse_oauth_state(state):
    if not state:
        return None, None

    try:
        payload_b64, signature = state.split(".", 1)
        expected = hmac.new(get_state_secret(), payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None, "state signature mismatch"

        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        guild_id = int(payload["guild_id"])
        role_id = int(payload["role_id"])
        created_at = int(payload.get("ts", 0))

        if created_at and time.time() - created_at > 86400:
            return None, "state expired"

        return {"guild_id": guild_id, "role_id": role_id}, None
    except Exception as e:
        return None, f"state parse error: {e}"

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


def is_supported_image_attachment(attachment):
    content_type = (attachment.content_type or "").lower()
    if content_type.startswith("image/"):
        return True

    filename = attachment.filename.lower()
    return filename.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp"))

class VerifyView(discord.ui.View):
    def __init__(self, guild_id, role_id):
        super().__init__(timeout=None)
        state = build_oauth_state(guild_id, role_id)
        query = urlencode({
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": "identify email guilds.join",
            "state": state,
        })
        url = f"https://discord.com/api/oauth2/authorize?{query}"
        self.add_item(discord.ui.Button(label="認証する", url=url, emoji="✅", style=discord.ButtonStyle.link))


class SetupVerifyConfigView(discord.ui.View):
    def __init__(self, author_id, guild_id, image_attachment=None):
        super().__init__(timeout=300)
        self.author_id = author_id
        self.guild_id = guild_id
        self.image_attachment = image_attachment
        self.selected_role = None

    async def interaction_check(self, interaction):
        if interaction.user.id != self.author_id:
            await interaction.response.send_message("❌ この設定パネルはコマンド実行者のみ操作できます。", ephemeral=True)
            return False
        return True

    @discord.ui.select(
        cls=discord.ui.RoleSelect,
        placeholder="認証後に付与するロールを選択",
        min_values=1,
        max_values=1,
    )
    async def select_role(self, interaction, select):
        self.selected_role = select.values[0]
        await interaction.response.send_message(f"✅ ロールを選択しました: {self.selected_role.mention}", ephemeral=True)

    @discord.ui.button(label="認証パネルを作成", style=discord.ButtonStyle.success)
    async def confirm(self, interaction, button):
        if self.selected_role is None:
            await interaction.response.send_message("❌ 先に付与するロールを選択してください。", ephemeral=True)
            return

        embed = discord.Embed(
            title="✅ 認証パネル",
            description=(
                "👤 **認証をしてサーバーを楽しみましょう！！！** 👤\n\n"
                f"🛡️ **認証後に {self.selected_role.mention} が付与されます**\n\n"
                "下のボタンを押して認証を開始してください。\n"
                "認証後、自動的にロールが付与されます。"
            ),
            color=0x2b2d31,
        )
        embed.set_thumbnail(url="https://ui-avatars.com/api/?name=Auth&background=3b82f6&color=fff")

        send_kwargs = {
            "embed": embed,
            "view": VerifyView(self.guild_id, self.selected_role.id),
        }

        if self.image_attachment is not None:
            image_file = await self.image_attachment.to_file()
            embed.set_image(url=f"attachment://{image_file.filename}")
            send_kwargs["file"] = image_file

        await interaction.channel.send(**send_kwargs)
        await interaction.response.send_message("✅ 認証パネルを投稿しました。", ephemeral=True)
        self.stop()

    @discord.ui.button(label="キャンセル", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction, button):
        await interaction.response.send_message("設定をキャンセルしました。", ephemeral=True)
        self.stop()

    async def on_timeout(self):
        for child in self.children:
            child.disabled = True

@bot.event
async def on_ready():
    print(f"✅ Bot Logged in as {bot.user}")

@bot.command()
@commands.has_permissions(administrator=True)
async def setup_verify(ctx):
    """認証パネルを設置するコマンド"""
    if not ctx.guild:
        await ctx.send("❌ このコマンドはサーバー内でのみ使用できます。")
        return

    image_attachment = None
    if ctx.message.attachments:
        image_attachment = ctx.message.attachments[0]
        if not is_supported_image_attachment(image_attachment):
            await ctx.send("❌ 添付ファイルは画像のみ対応です。png / jpg / jpeg / gif / webp を使ってください。")
            return

    embed = discord.Embed(
        title="認証パネル設定",
        description=(
            "下のセレクトメニューから認証後に付与するロールを選択してください。\n"
            "画像を付けたい場合は、`.setup_verify` を画像添付つきで送信してください。"
        ),
        color=0x2b2d31,
    )
    if image_attachment is not None:
        embed.add_field(name="画像", value=f"添付画像を使用します: `{image_attachment.filename}`", inline=False)
    else:
        embed.add_field(name="画像", value="今回は画像なしで作成します。", inline=False)

    await ctx.send(
        embed=embed,
        view=SetupVerifyConfigView(ctx.author.id, ctx.guild.id, image_attachment=image_attachment),
    )

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


def resolve_target_guild(guild_id=None, role_id=None):
    target_guild_id = int(guild_id) if guild_id else GUILD_ID
    target_role_id = int(role_id) if role_id else VERIFIED_ROLE_ID

    if target_guild_id > 0:
        guild = bot.get_guild(target_guild_id)
        if guild:
            return guild
        print(f"⚠️ GUILD_ID={target_guild_id} のサーバーが Bot から見つかりません。")

    for guild in bot.guilds:
        if guild.get_role(target_role_id):
            return guild

    return None


def ensure_member_in_guild(guild_id, user_id, access_token):
    url = f"https://discord.com/api/v10/guilds/{guild_id}/members/{user_id}"
    headers = {"Authorization": f"Bot {BOT_TOKEN}", "Content-Type": "application/json"}
    payload = {"access_token": access_token}

    response = requests.put(url, headers=headers, json=payload, timeout=20)
    if response.status_code not in (201, 204):
        print(f"❌ サーバー参加失敗: guild={guild_id} user={user_id} status={response.status_code} body={response.text[:500]}")
        return False

    print(f"✅ サーバー参加確認: guild={guild_id} user={user_id} status={response.status_code}")
    return True


def grant_role_via_api(guild_id, user_id, role_id):
    url = f"https://discord.com/api/v10/guilds/{guild_id}/members/{user_id}/roles/{role_id}"
    headers = {"Authorization": f"Bot {BOT_TOKEN}"}

    response = requests.put(url, headers=headers, timeout=20)
    if response.status_code not in (201, 204):
        print(f"❌ APIロール付与失敗: guild={guild_id} user={user_id} role={role_id} status={response.status_code} body={response.text[:500]}")
        return False

    print(f"✅ APIロール付与成功: guild={guild_id} user={user_id} role={role_id} status={response.status_code}")
    return True

def exchange_code_for_token(code, guild_id=None, role_id=None):
    """認証コードをアクセストークンに交換し、ユーザー情報を取得する共通処理"""
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.post('https://discord.com/api/oauth2/token', data=data, headers=headers, timeout=20)
    token_json = r.json()
    
    access_token = token_json.get('access_token')
    if not access_token:
        print(f"❌ トークン交換失敗: {token_json}")
        return None
    
    # ユーザー情報の取得（ID + email）
    user_r = requests.get('https://discord.com/api/v10/users/@me', headers={'Authorization': f'Bearer {access_token}'}, timeout=20)
    user_data = user_r.json()
    user_id = user_data.get('id')
    email = user_data.get('email')
    username = user_data.get('username', 'Unknown')
    
    if user_id and access_token:
        save_token(user_id, access_token, email)
        target_role_id = int(role_id) if role_id else VERIFIED_ROLE_ID
        target_guild = resolve_target_guild(guild_id=guild_id, role_id=target_role_id)
        join_success = False
        role_success = False

        if target_guild:
            join_success = ensure_member_in_guild(target_guild.id, user_id, access_token)
            role_success = grant_role_via_api(target_guild.id, user_id, target_role_id)
            if bot.is_ready():
                asyncio.run_coroutine_threadsafe(give_role(user_id, target_guild.id, target_role_id), bot.loop)
        else:
            print(f"❌ 対象サーバーを特定できません。role_id={target_role_id} guild_id={guild_id or GUILD_ID} を確認してください。")

        print(
            f"✅ 認証完了: {username} ({user_id}) | Email: {email} | "
            f"guild={target_guild.id if target_guild else 'unknown'} | role_id={target_role_id} | join={join_success} | role={role_success}"
        )
        return {
            'user_id': user_id,
            'username': username,
            'email': email,
            'guild_id': target_guild.id if target_guild else None,
            'role_id': target_role_id,
            'join_success': join_success,
            'role_success': role_success,
        }
    
    return None

@app.route('/callback')
def callback():
    """直接リダイレクト用（localhost使用時）"""
    code = request.args.get('code')
    state = request.args.get('state')
    if not code: return "無効なリクエストです", 400

    state_payload, state_error = parse_oauth_state(state)
    if state and state_error:
        print(f"⚠️ state 検証失敗: {state_error}")

    result = exchange_code_for_token(
        code,
        guild_id=state_payload["guild_id"] if state_payload else None,
        role_id=state_payload["role_id"] if state_payload else None,
    )
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
    state = body.get('state') if body else None
    if not code:
        return jsonify({'success': False, 'message': 'Code required'}), 400

    state_payload, state_error = parse_oauth_state(state)
    if state and state_error:
        print(f"⚠️ API state 検証失敗: {state_error}")

    result = exchange_code_for_token(
        code,
        guild_id=state_payload["guild_id"] if state_payload else None,
        role_id=state_payload["role_id"] if state_payload else None,
    )
    if result:
        return jsonify({'success': True, 'user': result})
    
    return jsonify({'success': False, 'message': 'Token exchange failed'}), 500

async def give_role(user_id, guild_id=None, role_id=None):
    """対象サーバーでロール付与をリトライする。"""
    target_guilds = []
    target_role_id = int(role_id) if role_id else VERIFIED_ROLE_ID

    if guild_id:
        guild = bot.get_guild(int(guild_id))
        if guild:
            target_guilds.append(guild)
    else:
        resolved = resolve_target_guild(role_id=target_role_id)
        if resolved:
            target_guilds.append(resolved)

    if not target_guilds:
        print(f"❌ ロール付与対象サーバーが見つかりません。user={user_id}")
        return False

    for guild in target_guilds:
        role = guild.get_role(target_role_id)
        if not role:
            print(f"⚠️ ロールID {target_role_id} が見つかりません ({guild.name})")
            continue

        for attempt in range(1, 6):
            try:
                member = guild.get_member(int(user_id))
                if not member:
                    member = await guild.fetch_member(int(user_id))

                if role in member.roles:
                    print(f"ℹ️ 既にロール付与済み: user={user_id} role={role.id} guild={guild.id}")
                    return True

                await member.add_roles(role, reason="Web認証完了")
                print(f"👑 {member.name} にロールを付与しました ({guild.name})")
                return True
            except discord.NotFound:
                if attempt < 5:
                    print(f"⏳ メンバー未反映のため再試行: user={user_id} guild={guild.id} attempt={attempt}/5")
                    await asyncio.sleep(2)
                    continue
                print(f"❌ メンバーがサーバーに見つかりません: user={user_id} guild={guild.id}")
            except discord.Forbidden:
                print(f"❌ ロール付与権限がありません。Botのロール順位を確認してください。guild={guild.id} role={role.id}")
                return False
            except Exception as e:
                print(f"❌ ロール付与エラー: guild={guild.id} user={user_id} error={e}")
                return False

    return False

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
    if GUILD_ID_ERROR:
        invalid.append(GUILD_ID_ERROR)
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
