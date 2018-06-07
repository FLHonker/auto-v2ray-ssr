# VPS服务器一键部署SSR

## 以ubunu为例

1. 安装wget
sudo apt install wget

2. 自动化脚本部署（root权限下）
wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ssr.sh && chmod +x ssr.sh && bash ssr.sh

注意：若链接失效，您也也可习性下载[ssr.h](./ssr.h)后运行。