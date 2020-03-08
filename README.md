# VPS服务器一键部署SSR

以ubunu为例

## 1. SSR

```
#（已喝茶） wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ssr.sh && chmod +x ssr.sh && bash ssr.sh
wget -N --no-check-certificate https://raw.githubusercontent.com/kawa11/doubi/master/ssrmu.sh && chmod +x ssrmu.sh && bash ssrmu.sh
```

> 注意：若链接失效，您也也可下载本目录下的[ssr.h](https://raw.githubusercontent.com/FLHonker/autoVPS-ssr/652dca3ea530082cfe3db9349cb501162f5c7563/ssr.sh)后运行。

## 2. V2ray

```
wget -N --no-check-certificate https://raw.githubusercontent.com/FLHonker/auto-v2ray-ssr/master/v2ray_install.sh && chmod +x v2ray_install.sh && sudo bash v2ray_install.sh
```

## 3. Trojan
```
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/johnrosen1/trojan-gfw-script/master/vps.sh)"
```

## 4. BBR加速：

```
wget --no-check-certificate https://github.com/teddysun/across/raw/master/bbr.sh && chmod +x bbr.sh && bash bbr.sh
```
> ssr.sh/v2ray_install.sh/Trojan 脚本中也有安装BBR的多种选项。（推荐）
* BBR-plus版本（CentOS7）参考[https://github.com/cx9208/bbrplus]
