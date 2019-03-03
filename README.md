# VPS服务器一键部署SSR

## 以ubunu为例

## 1. 安装wget

sudo apt install wget

## 2. 自动化脚本部署（root权限下）

wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ssr.sh && chmod +x ssr.sh && bash ssr.sh

注意：若链接失效，您也也可习性下载本目录下的[ssr.h](https://raw.githubusercontent.com/FLHonker/autoVPS-ssr/652dca3ea530082cfe3db9349cb501162f5c7563/ssr.sh)后运行。

## 3. BBR加速

wget --no-check-certificate https://github.com/teddysun/across/raw/master/bbr.sh && chmod +x bbr.sh && bash bbr.sh
