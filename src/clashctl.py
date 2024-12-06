#!/usr/bin/env python3

import argparse
import atexit
import os
import shutil
import subprocess
import sys
import re
import tempfile
from collections import ChainMap
from collections.abc import MutableMapping

from pathlib import Path

import yaml
import requests
import dbus


class SystemdStatusManager:

    def __init__(self, service_name_template):
        self.bus = dbus.SystemBus()
        self.systemd = self.bus.get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1')
        self.manager = dbus.Interface(self.systemd, 'org.freedesktop.systemd1.Manager')

        self.service_name = service_name_template

    def get_status(self, device_name):
        try:
            service_name = self.get_service_name(device_name)
            service_path = self.manager.GetUnit(service_name)
            service = self.bus.get_object('org.freedesktop.systemd1', service_path)
            properties = dbus.Interface(service, 'org.freedesktop.DBus.Properties')
            active_state = properties.Get('org.freedesktop.systemd1.Unit', 'ActiveState')
            sub_state = properties.Get('org.freedesktop.systemd1.Unit', 'SubState')
            print(f"Service {service_name}: ActiveState={active_state}, SubState={sub_state}")
            return active_state, sub_state
        except dbus.exceptions.DBusException as e:
            print(f"Error: {e}")
            return None, None

    def get_service_name(self, device_name):
        return self.service_name.replace('{device_name}', device_name)

    def start(self, device_name):
        return self.manager.StartUnit(self.get_service_name(device_name), "replace")

    def stop(self, device_name):
        return self.manager.StopUnit(self.get_service_name(device_name), "replace")

    def restart(self, device_name):
        return self.manager.RestartUnit(self.get_service_name(device_name), "replace")

    def reload(self, device_name):
        return self.manager.ReloadUnit(self.get_service_name(device_name), "replace")


class ClashControl:

    systemd_service = "clash@{device_name}.service"
    systemd_service_file = "/etc/systemd/system/clash@.service"
    systemd_content = """[Unit]
Description=Clash
After=vyos-router.service

[Service]
WorkingDirectory=/config/clash/run/%i
Type=simple
LimitNPROC=500
LimitNOFILE=1000000
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_TIME CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_TIME CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE
Restart=always
ExecStartPre=/bin/sh -c 'sleep 5 && [ -x /config/clash/config/%i/scripts/pre-up ] && /config/clash/config/%i/scripts/pre-up || exit 0'
ExecStart=/config/clash/bin/clashd -d /config/clash/run/%i
ExecStartPost=/bin/sh -c 'sleep 5 && [ -x /config/clash/config/%i/scripts/post-up ] && /config/clash/config/%i/scripts/post-up || exit 0'
ExecStopPost=/bin/sh -c 'sleep 3 && [ -x /config/clash/config/%i/scripts/post-down ] && /config/clash/config/%i/scripts/post-down || exit 0'
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
"""
    clash_binary_repo_id = 'MetaCubeX/mihomo'
    clash_binary_repo_tag = 'latest'

    clash_root = '/config/clash'

    bin_dir = clash_root + '/bin'
    clash_local_binary = bin_dir + '/clashd'
    clash_binary_symbol = 'Meta'

    config_dir = clash_root + '/config'

    subscription_download_file = '00-clash_download.yaml'
    subscription_file = 'config.yaml'

    dashboard_repo_ids = [
        "MetaCubeX/metacubexd",
        "haishanh/yacd",
        "ayanamist/clash-dashboard",
    ]

    ui_dir = clash_root + '/ui'
    run_dir = clash_root + '/run'

    clash_directories = [
        bin_dir,
        ui_dir,
        config_dir,
        run_dir,
    ]

    def __init__(self):
        self.systemd_manager = SystemdStatusManager(self.systemd_service)
        self.ensure_dir()
        self.ensure_systemd_file()

    def ensure_dir(self):
        for dirname in self.clash_directories:
            os.makedirs(dirname, exist_ok=True)

    def ensure_systemd_file(self, reload_systemd=False):
        if not os.path.exists(self.systemd_service_file):
            with open(self.systemd_service_file, "w") as f:
                f.write(self.systemd_content)

            if reload_systemd:
                subprocess.run(['systemctl', 'daemon-reload'], check=True)
            else:
                print("Please run systemctl daemon-reload ")

    @staticmethod
    def get_default_file_suffix_by_mimetype(mime_type):
        if mime_type == 'application/gzip':
            return '.gz'
        else:
            return None

    @staticmethod
    def get_assets_from_github(repo, tag='release', name_pattern=None):
        resp = requests.get(f'https://api.github.com/repos/{repo}/releases/{tag}')

        if resp.status_code != 200:
            raise Exception(f'Failed to Request Github API {repo}/{tag}: {resp.status_code}')

        j = resp.json()

        assets = []
        release_name = None
        if 'assets' in j:
            for item in j['assets']:
                if name_pattern is None or re.search(name_pattern, item['name']):
                    assets.append(item)
        if 'name' in j:
            release_name = j['name']

        return release_name, assets

    @staticmethod
    def download_github_asset(asset):
        if 'browser_download_url' not in asset:
            raise Exception(f'Invalid github asset: missing browser_download_url')

        if 'size' not in asset:
            raise Exception(f'Invalid github asset: missing size')

        # 发起下载请求
        with requests.get(asset['browser_download_url'],  stream=True) as response:
            response.raise_for_status()
            # 验证内容长度
            content_length = int(response.headers.get("Content-Length", 0))
            if content_length != asset['size']:
                raise ValueError(f"Expected size {asset['size']}, but got {content_length}")

            file_suffix = ClashControl.get_default_file_suffix_by_mimetype(asset['content_type'])

            # 创建临时文件
            with tempfile.NamedTemporaryFile(delete=False, suffix=file_suffix) as temp_file:
                temp_file_path = temp_file.name

                atexit.register(lambda: os.remove(temp_file_path) if os.path.exists(temp_file_path) else None)

                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:  # 忽略空块
                        temp_file.write(chunk)
                temp_file.flush()

                actual_size = os.path.getsize(temp_file_path)
                if actual_size != asset['size']:
                    os.remove(temp_file_path)
                    raise ValueError(f"Expected size {asset['size']}, but downloaded file size is {actual_size}")

        return temp_file_path

    @staticmethod
    def github_download(repo, tag, name_pattern, target_file_path=None):
        release_name, assets = ClashControl.get_assets_from_github(repo, tag, name_pattern)
        temp_file_path = ClashControl.download_github_asset(assets[0])

        if target_file_path:
            shutil.move(temp_file_path, target_file_path)
            return target_file_path

    @staticmethod
    def get_arch():
        uname = os.uname()
        if uname.sysname != 'Linux':
            raise Exception(f'Unsupported system: {uname.sysname}')

        return uname.machine

    def check_clash_update(self):
        release_name, _ = self.get_assets_from_github(self.clash_binary_repo_id, self.clash_binary_repo_tag)
        print(release_name)

    def install_clash(self):
        cpu_arch = self.get_arch()
        if cpu_arch == 'arm64' or cpu_arch == 'aarch64':
            binary_suffix = r'linux\-arm64\-.*\.gz$'
        elif cpu_arch == 'x86_64':
            binary_suffix = r'linux\-amd64\-go120\-.*\.gz$'
        else:
            raise Exception(f'Unsupported architecture: {cpu_arch}')

        release_name, assets = self.get_assets_from_github(self.clash_binary_repo_id, self.clash_binary_repo_tag, binary_suffix)

        if release_name is None:
            raise Exception('Unable to find release for clash')

        if len(assets) == 0:
            raise Exception('No assets found for clash')

        gz_temp_file_path = self.download_github_asset(assets[0])

        tmp_file_path = gz_temp_file_path.rstrip('.gz')
        atexit.register(lambda: os.remove(tmp_file_path) if os.path.exists(tmp_file_path) else None)

        try:
            # 解压 gz 文件
            subprocess.run(["gunzip", "-f", gz_temp_file_path], check=True)

            # 设置执行权限
            subprocess.run(["chmod", "+x", tmp_file_path], check=True)

            # 执行文件并检查是否包含 "Meta"
            result = subprocess.run(
                [tmp_file_path, "-v"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                capture_output=True,
                text=True
            )

            if result.stdout.find(self.clash_binary_symbol) > -1:
                # 移动文件到目标路径
                subprocess.run(["sudo", "mv", tmp_file_path, self.clash_local_binary], check=True)
                print(f"File moved to {self.clash_local_binary}")
            else:
                print(f"Symbol not found in downloaded binary")
        except subprocess.CalledProcessError as e:
            print(f"命令执行失败: {e}")
        except Exception as e:
            print(f"处理文件时出错: {e}")
        finally:
            pass


    def install_ui(self):
        for repo_id in self.dashboard_repo_ids:
            dashboard_url = f'https://github.com/{repo_id}/archive/refs/heads/gh-pages.tar.gz'

            name = os.path.basename(repo_id)
            with requests.get(dashboard_url, allow_redirects=True) as response:
                response.raise_for_status()

                with tempfile.NamedTemporaryFile() as temp_file:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:  # 忽略空块
                            temp_file.write(chunk)

                    temp_file.flush()

                    os.makedirs(f"{self.ui_dir}/{name}", exist_ok=True)
                    subprocess.run(
                        ['tar', '--strip-components=1', '-xv', '-C', f"{self.ui_dir}/{name}", '-f', temp_file.name],
                        check=True)

    def install_all(self):
        self.ensure_dir()
        self.install_clash()
        self.install_ui()
        self.ensure_systemd_file(True)

    def require_binary(self):
        if os.path.exists(self.clash_local_binary) and os.access(self.clash_local_binary, os.X_OK):
            return True
        else:
            raise Exception(f'{self.clash_local_binary} does not exist or permission incorrect')

    def download_subscription(self, device_name):
        self.require_binary()

        # /config/clash/config/utun0.yaml for subscription configs
        # /config/clash/config/utun0/ for clash configs
        dev_config_root = os.path.join(self.config_dir, device_name)
        os.makedirs(dev_config_root, exist_ok=True)
        # parse yaml
        config = self.config_load(device_name)
        if 'subscription' not in config:
            raise Exception('No subscription found')

        resp = requests.get(config['subscription'])
        if resp.status_code != 200:
            raise Exception('Subscription download failed')

        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(resp.content)
            temp_file.flush()

            result = subprocess.run(
                [self.clash_local_binary, '-d', os.path.join(self.config_dir, device_name), '-f', temp_file.name, '-t'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode != 0:
                raise Exception('Unable to verify subscription: Command execution failed')

            if result.stdout.find('Initial configuration complete') > -1 and \
                    result.stdout.find('test is successful') > -1:
                shutil.copy(temp_file.name, os.path.join(dev_config_root, self.subscription_download_file))
            else:
                raise Exception('Unable to verify subscription: Verification failed')

    def deep_merge(self, source, destination):
        """
        深度合并两个字典
        """
        for key, value in source.items():
            if isinstance(value, MutableMapping):
                # 如果值是字典，递归合并
                node = destination.setdefault(key, {})
                self.deep_merge(value, node)
            elif isinstance(value, list):
                # 如果值是列表，追加到目标列表中
                if key in destination:
                    destination[key].extend(value)
                else:
                    destination[key] = value
            else:
                # 否则直接覆盖
                destination[key] = value
        return destination

    def load_yaml_files(self, directory):
        # 获取目录下所有的 YAML 文件
        yaml_files = Path(directory).glob('*.yaml')

        # 根据文件名排序
        yaml_files = sorted(yaml_files)

        # 加载所有 YAML 文件的内容
        merged_config = {}
        for file in yaml_files:
            with open(file, 'r') as f:
                config = yaml.safe_load(f)
                if config is None:
                    config = {}
                merged_config = self.deep_merge(config, merged_config)

        return merged_config

    def generate_config(self, device_name):
        os.makedirs(os.path.join(self.run_dir, device_name), exist_ok=True)

        with open(os.path.join(self.run_dir, device_name, self.subscription_file), 'w') as f:
            yaml.dump(self.load_yaml_files(os.path.join(self.config_dir, device_name)), f, default_flow_style=False)

    def config_exists(self, device_name):
        return os.path.exists(os.path.join(self.config_dir, f'{device_name}.yaml'))

    def config_load(self, device_name):
        return yaml.safe_load(open(os.path.join(self.config_dir, f'{device_name}.yaml')))

    def print_version(self):
        self.require_binary()

        try:
            # 执行命令并捕获输出
            result = subprocess.run([self.clash_local_binary, '-v'], capture_output=True, text=True)
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Error executing command: {e}")

    def start_service(self, device_name):
        os.makedirs(os.path.join(self.run_dir, device_name), exist_ok=True)
        return self.systemd_manager.start(device_name)

    def stop_service(self, device_name):
        return self.systemd_manager.stop(device_name)

    def restart_service(self, device_name):
        return self.systemd_manager.restart(device_name)

    def reload_service(self, device_name):
        return self.systemd_manager.reload(device_name)

    def service_status(self, device_name):
        return self.systemd_manager.get_status(device_name)


def main():
    parser = argparse.ArgumentParser(
        description="Clashctl for VyOS by sskaje",
        epilog="DEV is the device name (e.g., utun0).",
        # usage="python %(prog)s COMMAND [args] [options]"
    )

    subparsers = parser.add_subparsers(dest="command", metavar='COMMAND')

    # Command: start
    parser_start = subparsers.add_parser("start", help="Start an instance (Requires DEVICE)")
    parser_start.add_argument("device", metavar='DEVICE', help="UTUN interface")

    # Command: stop
    parser_stop = subparsers.add_parser("stop", help="Stop an instance (Requires DEVICE)")
    parser_stop.add_argument("device", metavar='DEVICE', help="UTUN interface")

    # Command: restart
    parser_restart = subparsers.add_parser("restart", help="Restart an instance (Requires DEVICE)")
    parser_restart.add_argument("device", metavar='DEVICE', help="UTUN interface")

    # Command: purge_cache
    parser_purge_cache = subparsers.add_parser("purge_cache", help="Remove cache.db and restart (Requires DEVICE)")
    parser_purge_cache.add_argument("device", metavar='DEVICE', help="UTUN interface")

    # Command: status
    parser_status = subparsers.add_parser("status", help="Show instance status (Requires DEVICE)")
    parser_status.add_argument("device", metavar='DEVICE', help="UTUN interface")

    # Command: rehash
    parser_rehash = subparsers.add_parser("rehash", help="Download config and restart to reload (Requires DEVICE)")
    parser_rehash.add_argument("device", metavar='DEVICE', help="UTUN interface")

    # Command: reload
    parser_reload = subparsers.add_parser("reload", help="Reload config (Requires DEVICE)")
    parser_reload.add_argument("device", metavar='DEVICE', help="UTUN interface")

    # Command: generate_config
    parser_generate_config = subparsers.add_parser("generate_config", help="Generate instance configuration (Requires DEVICE)")
    parser_generate_config.add_argument("device", metavar='DEVICE', help="UTUN interface")

    # Command: install
    subparsers.add_parser("install", help="Install")

    # Command: check_update
    subparsers.add_parser("check_update", help="Check clash binary version")

    # Command: check_version
    subparsers.add_parser("check_version", help="Check clash binary version")

    # Command: update
    subparsers.add_parser("update", help="Update clash binary")

    # Command: update_ui
    subparsers.add_parser("update_ui", help="Download Dashboard UI")

    # Command: show_version
    subparsers.add_parser("show_version", help="Show clash binary version")

    # Command: help
    subparsers.add_parser("help", help="Show this message")

    args = parser.parse_args()

    if args.command == "help":
        parser.print_help()
    elif args.command is None:
        parser.print_usage()
    else:

        ctrl = ClashControl()
        if args.command == "start":
            ctrl.start_service(args.device)
        elif args.command == "stop":
            ctrl.stop_service(args.device)
        elif args.command == "restart":
            ctrl.restart_service(args.device)
        elif args.command == "status":
            ctrl.service_status(args.device)
        elif args.command == "rehash":
            ctrl.download_subscription(args.device)
            ctrl.generate_config(args.device)
            ctrl.reload_service(args.device)
        elif args.command == "generate_config":
            ctrl.download_subscription(args.device)
            ctrl.generate_config(args.device)
        elif args.command == "show_version":
            ctrl.print_version()
        elif args.command == "install":
            ctrl.install_all()
        elif args.command == "check_update":
            ctrl.check_clash_update()
        elif args.command == "update":
            ctrl.install_clash()
        elif args.command == "update_ui":
            ctrl.install_ui()


if __name__ == "__main__":
    main()

