import tkinter as tk
from tkinter import ttk, messagebox
from core import PasswordCore

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("确定性密码生成器")
        self.root.geometry("670x375")
        
        # 实例化核心引擎
        self.core = PasswordCore()
        
        # 先检查密钥，不存在则进入首次设置
        try:
            self.core.get_or_create_secret()
            self.build_main_ui()
        except FileNotFoundError:
            self.build_first_run_ui()

    def build_first_run_ui(self):
        self.clear_window()
        self.root.title("首次设置 - 密码生成器")
        frame = ttk.Frame(self.root, padding="40 30")
        frame.grid(sticky="nsew")

        ttk.Label(frame, text="🎉 欢迎首次使用", font=("Arial", 14, "bold"))\
            .grid(row=0, column=0, pady=(0, 10))
        ttk.Label(frame, text="请设置主密钥（Master Secret）\n将加密保存至本地，作为所有密码的派生根密钥", justify="left")\
            .grid(row=1, column=0, pady=(0, 15), sticky="w")

        ttk.Label(frame, text="输入主密钥：").grid(row=2, column=0, sticky="w", pady=5)
        self.secret_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.secret_var, show="*", width=45)\
            .grid(row=2, column=0, pady=5)

        ttk.Label(frame, text="确认主密钥：").grid(row=3, column=0, sticky="w", pady=5)
        self.confirm_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.confirm_var, show="*", width=45)\
            .grid(row=3, column=0, pady=5)

        ttk.Button(frame, text="💾 保存并进入", command=self.handle_first_save, width=38)\
            .grid(row=4, column=0, pady=20)

    def handle_first_save(self):
        s1, s2 = self.secret_var.get().strip(), self.confirm_var.get().strip()
        if len(s1) < 12:
            messagebox.showerror("错误", "主密钥至少12位")
            return
        if s1 != s2:
            messagebox.showerror("错误", "两次输入不一致")
            return
        self.core.write_secret(s1)
        messagebox.showinfo("成功", "主密钥已保存，请勿泄露！")
        self.build_main_ui()

    def build_main_ui(self):
        self.clear_window()
        self.root.title("密码生成器")
        frame = ttk.Frame(self.root, padding="25 22")
        frame.grid(sticky="nsew")

        # ✅ 修正：将密码长度加入字段数组，统一管理行号
        fields = [
            ("网站 URL：",    "url_var",      55, None, ""),
            ("用户名：",      "user_var",     55, None, ""),
            ("站点标识：",    "siteid_var",   37, "（选填，不填则用URL域名）", ""),
            ("覆盖密钥：",    "customsec_var",39, "（选填，临时替换主密钥）", "*"),
            ("密码长度：",    "length_var",   18, "（选填，默认输出32位）", "")
        ]

        row_index = len(fields)

        for i, (label, var_name, width, hint, show_char) in enumerate(fields):
            setattr(self, var_name, tk.StringVar())
            ttk.Label(frame, text=label).grid(row=i, column=0, pady=7, sticky="w")
            kwargs = {"show": show_char} if show_char else {}
            entry = ttk.Entry(frame, textvariable=getattr(self, var_name), width=width, **kwargs)
            entry.grid(row=i, column=1, pady=7, padx=(11, 0), sticky="ew")
            if hint:
                ttk.Label(frame, text=hint, foreground="#666", font=("", 9))\
                    .grid(row=i, column=2, sticky="w")

        
        ttk.Button(frame, text="🚀 生成密码", command=self.do_generate, width=20)\
            .grid(row=row_index, column=0, columnspan=3, sticky="w", pady=23)

        row_index+=1

        self.result_var = tk.StringVar(value="待生成")
        ttk.Entry(frame, textvariable=self.result_var, state="readonly", 
                 font=("Courier New", 11), width=53).grid(row=row_index, column=0, columnspan=2, pady=10, sticky="ew")
        ttk.Button(frame, text="📋 复制", command=self.do_copy, width=12)\
            .grid(row=row_index, column=2, padx=(59, 60))

        # 状态栏在第7行
        row_index+=1
        self.status_var = tk.StringVar(value=f"✅ 已加载密钥：{self.core.secret_path}")
        ttk.Label(frame, textvariable=self.status_var, foreground="#006400", font=("", 9))\
            .grid(row=row_index, column=0, columnspan=3, sticky="w", pady=3)

        frame.columnconfigure(1, weight=1)

    def do_generate(self):
        url = self.url_var.get().strip()
        user = self.user_var.get().strip()
        site_id = self.siteid_var.get().strip()
        len_val = self.length_var.get().strip()

        if (not url) and (not site_id):
            messagebox.showerror("错误", '站点标识和url必须至少有一个')
            return

        if not user:
            messagebox.showerror("错误", "用户名必填")
            return

        if len(len_val)>0:
            if not len_val.isdigit():
                messagebox.showerror("错误", "密码长度必须为数字")
                return
            elif int(len_val)>128 or int(len_val)<8:
                messagebox.showerror("错误", "密码长度必须在8~128之间")
                return               

        try:
            secret = self.customsec_var.get().strip() or self.core.get_or_create_secret()
            host = self.core.extract_host(url)
            site_id = site_id or host
            len_val = int(self.length_var.get().strip()) if self.length_var.get().strip() else None
            pwd = self.core.generate_password(site_id, user, secret, length=len_val)

            self.result_var.set(pwd)
            tip = f"⚠️ 使用自定义站点标识'{site_id}'" if self.siteid_var.get().strip() \
                  else f"✅ 使用域名标识：{site_id}"
            self.status_var.set(tip)
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def do_copy(self):
        pwd = self.result_var.get()
        if pwd and pwd != "待生成":
            self.root.clipboard_clear()
            self.root.clipboard_append(pwd)
            self.status_var.set("✅ 已复制到剪贴板")

    def clear_window(self):
        for w in self.root.winfo_children():
            w.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()