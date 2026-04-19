import argparse
from core import PasswordCore

def main():
    parser = argparse.ArgumentParser(
        description="基于「站点标识+用户名+本地密钥」生成稳定强密码",
        epilog="密钥文件默认：~/.genpass_secret（需 chmod 600）"
    )
    parser.add_argument("-u", "--url",  help="站点URL（提取域名）")
    parser.add_argument("-n", "--username",  help="用户名")
    parser.add_argument("-s", "--site-id",  help="站点标识（空则用URL域名）")
    parser.add_argument("--raw-secret",      help="临时覆盖密钥（非生产用）")
    parser.add_argument("--init-secret",     help="首次写入密钥（一次性操作）")
    parser.add_argument("--secret-file",     help="指定自定义密钥文件路径")
    parser.add_argument("-l", "--length", type=int, help="指定密码长度（默认全输出）")
    
    args = parser.parse_args()

    # 实例化核心类，支持自定义密钥路径
    core = PasswordCore(secret_path=args.secret_file)

    # 优先处理初始化请求
    if args.init_secret:
        core.write_secret(args.init_secret)
        print("主密钥已写入并锁定权限")
        return
    else :
        if (not args.site_id) and (not args.url):
            print('站点标识和url必须至少有一个')
            return

        if not args.username:
            print("必须输入用户名")
            return



    # 正常生成流程
    secret = args.raw_secret or core.get_or_create_secret()
    site_id = args.site_id
    if args.url:
        host= core.extract_host(args.url)
    
    site_id= site_id or host

    if args.site_id and args.url:
        print(f"已指定site-id='{site_id}'， host='{host}'未参与计算")

    pwd = core.generate_password(site_id, args.username, secret, length=args.length)
    print(f"站点标识: {site_id}\n最终密码: {pwd}")

if __name__ == "__main__":
    main()