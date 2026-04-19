import hmac
import hashlib
import base64
import os
from pathlib import Path
from urllib.parse import urlparse

class PasswordCore:
    def __init__(self, secret_path=None):
        self.secret_path = secret_path or Path.home() / ".genpass_secret"

    def get_or_create_secret(self, initial_secret=None):
        """获取密钥（不存在时允许GUI层传入初始值创建）"""
        if not self.secret_path.exists():
            if initial_secret is None:
                raise FileNotFoundError(f"未找到密钥文件 {self.secret_path}")
            self.write_secret(initial_secret)
        self.enforce_permissions()
        with open(self.secret_path, "r", encoding="utf-8") as f:
            return f.readline().strip()

    def write_secret(self, secret):
        """写入密钥并锁定权限"""
        with open(self.secret_path, "w", encoding="utf-8") as f:
            f.write(secret)
        self.enforce_permissions()

    def enforce_permissions(self):
        """强制密钥文件权限为600"""
        if os.name == "posix" and self.secret_path.exists():
            self.secret_path.chmod(0o600)

    @staticmethod
    def extract_host(url):
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return urlparse(url).netloc.split(":")[0].lower()

    @staticmethod
    def generate_password(site_id, username, secret, length=None):
        """核心派生：支持长度约束，无长度时回退原版（全输出）"""
        if length is None:
            length = 32
            # return PasswordCore._original_generate(site_id, username, secret)
        return PasswordCore._fixed_length_generate(site_id, username, secret, max_len=length)

    @staticmethod
    def _original_generate(site_id, username, secret):
        """原版全长度密码（约44位）"""
        msg = f"{site_id}:{username}:{secret}".encode("utf-8")
        digest = hashlib.sha256(msg).digest()
        return (
            base64.b64encode(digest)
            .decode("utf-8")
            .replace("=", "!")
            .replace("+", "@")
            .replace("/", "#")
        )

    @staticmethod
    def _fixed_length_generate(site_id, username, secret, max_len):
        """固定长度密码（保证大写/小写/数字/特殊各至少1个）"""
        # 字符池（Base64 派生集，避开易混淆字符）
        upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"  # 去 I,O
        lower = "abcdefghijkmnopqrstuvwxyz"  # 去 l
        digit = "23456789"                   # 去 0,1
        special = "@!#$%&*+-=?"              # 常见允许符号

        # 用 HMAC(secret+长度, 站点+用户) 做种子流（确保长度变化序列不同）
        key = f"{secret}{max_len}".encode("utf-8")
        msg = f"{site_id}:{username}".encode("utf-8")
        h = hmac.new(key, msg, hashlib.sha256)
        seed = h.digest()
        # 循环扩展种子流（2倍长度备用）
        stream = bytearray()
        for i in range(max_len * 2):
            idx = i % len(seed)
            stream.append(seed[idx] ^ (i & 0xFF))  # 简单扰乱

        chars = []
        types = [upper, lower, digit, special]
        used_types = set()

        for i in range(max_len):
            # 前4位强制各类型一次，后面按种子轮询
            if i < len(types):
                t = i % len(types)
            else:
                t = stream[i] % len(types)
            pool = types[t]
            c = pool[stream[len(chars)] % len(pool)]
            chars.append(c)
            used_types.add(t)

        # 补齐未出现的类型（防止某类缺失）
        for t in range(len(types)):
            if t not in used_types:
                # 找一个可替换的位置（跳过前4位以外的特殊位？按需调整）
                pos = (t + 3) % min(max_len, 12)
                pool = types[t]
                chars[pos] = pool[stream[max_len + t] % len(pool)]

        return "".join(chars)[:max_len]