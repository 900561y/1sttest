#!/bin/bash

export LC_ALL=C
#export LANG=C
export LANG=en_US.UTF-8
export LANGUAGE=en_US.UTF-8

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
  sudoCmd="sudo"
else
  sudoCmd=""
fi

uninstall() {
  ${sudoCmd} $(which rm) -rf $1
  printf "File or Folder Deleted: %s\n" $1
}


# fonts color
red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}
green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}
yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}
blue(){
    echo -e "\033[34m\033[01m$1\033[0m"
}
bold(){
    echo -e "\033[1m\033[01m$1\033[0m"
}



osInfo=""
osRelease=""
osReleaseVersion=""
osReleaseVersionNo=""
osReleaseVersionCodeName=""
osSystemPackage=""
osSystemMdPath=""
osSystemShell="bash"


# Detection system release
function getLinuxOSRelease(){
    if [[ -f /etc/redhat-release ]]; then
        osRelease="centos"
        osSystemPackage="yum"
        osSystemMdPath="/usr/lib/systemd/system/"
        osReleaseVersionCodeName=""
    elif cat /etc/issue | grep -Eqi "debian|raspbian"; then
        osRelease="debian"
        osSystemPackage="apt-get"
        osSystemMdPath="/lib/systemd/system/"
        osReleaseVersionCodeName="buster"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
        osRelease="ubuntu"
        osSystemPackage="apt-get"
        osSystemMdPath="/lib/systemd/system/"
        osReleaseVersionCodeName="bionic"
    elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
        osRelease="centos"
        osSystemPackage="yum"
        osSystemMdPath="/usr/lib/systemd/system/"
        osReleaseVersionCodeName=""
    elif cat /proc/version | grep -Eqi "debian|raspbian"; then
        osRelease="debian"
        osSystemPackage="apt-get"
        osSystemMdPath="/lib/systemd/system/"
        osReleaseVersionCodeName="buster"
    elif cat /proc/version | grep -Eqi "ubuntu"; then
        osRelease="ubuntu"
        osSystemPackage="apt-get"
        osSystemMdPath="/lib/systemd/system/"
        osReleaseVersionCodeName="bionic"
    elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
        osRelease="centos"
        osSystemPackage="yum"
        osSystemMdPath="/usr/lib/systemd/system/"
        osReleaseVersionCodeName=""
    fi

    getLinuxOSVersion

    [[ -z $(echo $SHELL|grep zsh) ]] && osSystemShell="bash" || osSystemShell="zsh"

    echo "OS info: ${osInfo}, ${osRelease}, ${osReleaseVersion}, ${osReleaseVersionNo}, ${osReleaseVersionCodeName}, ${osSystemShell}, ${osSystemPackage}, ${osSystemMdPath}"
}

# Detection system version number
getLinuxOSVersion(){
    if [[ -s /etc/redhat-release ]]; then
        osReleaseVersion=$(grep -oE '[0-9.]+' /etc/redhat-release)
    else
        osReleaseVersion=$(grep -oE '[0-9.]+' /etc/issue)
    fi

    # https://unix.stackexchange.com/questions/6345/how-can-i-get-distribution-name-and-version-number-in-a-simple-shell-script

    if [ -f /etc/os-release ]; then
        # freedesktop.org and systemd
        . /etc/os-release
        osInfo=$NAME
        osReleaseVersionNo=$VERSION_ID

        if [ -n $VERSION_CODENAME ]; then
            osReleaseVersionCodeName=$VERSION_CODENAME
        fi
    elif type lsb_release >/dev/null 2>&1; then
        # linuxbase.org
        osInfo=$(lsb_release -si)
        osReleaseVersionNo=$(lsb_release -sr)
    elif [ -f /etc/lsb-release ]; then
        # For some versions of Debian/Ubuntu without lsb_release command
        . /etc/lsb-release
        osInfo=$DISTRIB_ID
        
        osReleaseVersionNo=$DISTRIB_RELEASE
    elif [ -f /etc/debian_version ]; then
        # Older Debian/Ubuntu/etc.
        osInfo=Debian
        osReleaseVersion=$(cat /etc/debian_version)
        osReleaseVersionNo=$(sed 's/\..*//' /etc/debian_version)
    elif [ -f /etc/redhat-release ]; then
        osReleaseVersion=$(grep -oE '[0-9.]+' /etc/redhat-release)
    else
        # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
        osInfo=$(uname -s)
        osReleaseVersionNo=$(uname -r)
    fi
}

osPort80=""
osPort443=""
osSELINUXCheck=""
osSELINUXCheckIsRebootInput=""

function testLinuxPortUsage(){
    $osSystemPackage -y install net-tools socat

    osPort80=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 80`
    osPort443=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 443`

    if [ -n "$osPort80" ]; then
        process80=`netstat -tlpn | awk -F '[: ]+' '$5=="80"{print $9}'`
        red "==========================================================="
        red "It is detected that port 80 is occupied, and the occupied process is: ${process80}, this installation is over"
        red "==========================================================="
        exit 1
    fi

    if [ -n "$osPort443" ]; then
        process443=`netstat -tlpn | awk -F '[: ]+' '$5=="443"{print $9}'`
        red "============================================================="
        red "It is detected that port 443 is occupied, and the occupied process is: ${process443}, this installation is over"
        red "============================================================="
        exit 1
    fi

    osSELINUXCheck=$(grep SELINUX= /etc/selinux/config | grep -v "#")
    if [ "$osSELINUXCheck" == "SELINUX=enforcing" ]; then
        red "======================================================================="
        red "SELinux is detected to be in forced mode. In order to prevent failure to apply for a certificate, please restart the VPS before executing this script"
        red "======================================================================="
        read -p "Do you want to restart now? Please enter [Y/n] :" osSELINUXCheckIsRebootInput
        [ -z "${osSELINUXCheckIsRebootInput}" ] && osSELINUXCheckIsRebootInput="y"

        if [[ $osSELINUXCheckIsRebootInput == [Yy] ]]; then
            sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
            setenforce 0
            echo -e "VPS Restarting..."
            reboot
        fi
        exit
    fi

    if [ "$osSELINUXCheck" == "SELINUX=permissive" ]; then
        red "======================================================================="
        red "SELinux is detected to be in permissive mode. In order to prevent failure to apply for a certificate, please restart the VPS before executing this script"
        red "======================================================================="
        read -p "Do you want to restart now? Please enter [Y/n] :" osSELINUXCheckIsRebootInput
        [ -z "${osSELINUXCheckIsRebootInput}" ] && osSELINUXCheckIsRebootInput="y"

        if [[ $osSELINUXCheckIsRebootInput == [Yy] ]]; then
            sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
            setenforce 0
            echo -e "VPS Restarting..."
            reboot
        fi
        exit
    fi

    if [ "$osRelease" == "centos" ]; then
        if  [ -n "$(grep ' 6\.' /etc/redhat-release)" ] ; then
            red "==============="
            red "The current system is not supported"
            red "==============="
            exit
        fi

        if  [ -n "$(grep ' 5\.' /etc/redhat-release)" ] ; then
            red "==============="
            red "The current system is not supported"
            red "==============="
            exit
        fi

        ${sudoCmd} systemctl stop firewalld
        ${sudoCmd} systemctl disable firewalld

    elif [ "$osRelease" == "ubuntu" ]; then
        if  [ -n "$(grep ' 14\.' /etc/os-release)" ] ;then
            red "==============="
            red "The current system is not supported"
            red "==============="
            exit
        fi
        if  [ -n "$(grep ' 12\.' /etc/os-release)" ] ;then
            red "==============="
            red "The current system is not supported"
            red "==============="
            exit
        fi

        ${sudoCmd} systemctl stop ufw
        ${sudoCmd} systemctl disable ufw
        
    
    elif [ "$osRelease" == "debian" ]; then
        $osSystemPackage update -y

    fi

}


# Edit SSH public key file for password-free login
function editLinuxLoginWithPublicKey(){
    if [ ! -d "${HOME}/ssh" ]; then
        mkdir -p ${HOME}/.ssh
    fi

    vi ${HOME}/.ssh/authorized_keys
}



# Set up SSH root login

function setLinuxRootLogin(){

    read -p "Is root login allowed (ssh key or password login)? Please enter[Y/n]?" osIsRootLoginInput
    osIsRootLoginInput=${osIsRootLoginInput:-Y}

    if [[ $osIsRootLoginInput == [Yy] ]]; then

        if [ "$osRelease" == "centos" ] || [ "$osRelease" == "debian" ] ; then
            ${sudoCmd} sed -i 's/#\?PermitRootLogin \(yes\|no\|Yes\|No\|prohibit-password\)/PermitRootLogin yes/g' /etc/ssh/sshd_config
        fi
        if [ "$osRelease" == "ubuntu" ]; then
            ${sudoCmd} sed -i 's/#\?PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
        fi

        green "Set to allow root login success!"
    fi


    read -p "Do you want to allow root to log in with a password (please set to allow root to log in in the previous step)? Please enter[Y/n]?" osIsRootLoginWithPasswordInput
    osIsRootLoginWithPasswordInput=${osIsRootLoginWithPasswordInput:-Y}

    if [[ $osIsRootLoginWithPasswordInput == [Yy] ]]; then
        sed -i 's/#\?PasswordAuthentication \(yes\|no\)/PasswordAuthentication yes/g' /etc/ssh/sshd_config
        green "Set to allow root to log in successfully with a password!"
    fi


    ${sudoCmd} sed -i 's/#\?TCPKeepAlive yes/TCPKeepAlive yes/g' /etc/ssh/sshd_config
    ${sudoCmd} sed -i 's/#\?ClientAliveCountMax 3/ClientAliveCountMax 30/g' /etc/ssh/sshd_config
    ${sudoCmd} sed -i 's/#\?ClientAliveInterval [0-9]*/ClientAliveInterval 40/g' /etc/ssh/sshd_config

    if [ "$osRelease" == "centos" ] ; then

        ${sudoCmd} service sshd restart
        ${sudoCmd} systemctl restart sshd

        green "The setting is successful, please log in to the vps server with the shell tool software!"
    fi

    if [ "$osRelease" == "ubuntu" ] || [ "$osRelease" == "debian" ] ; then
        
        ${sudoCmd} service ssh restart
        ${sudoCmd} systemctl restart ssh

        green "The setting is successful, please log in to the vps server with the shell tool software!"
    fi

    # /etc/init.d/ssh restart

}

# Modify SSH port number
function changeLinuxSSHPort(){
    green "Modified SSH login port number, do not use commonly used port numbers. For example 20|21|23|25|53|69|80|110|443|123!"
    read -p "Please enter the port number to be modified (must be a pure number and between 1024~65535 or 22):" osSSHLoginPortInput
    osSSHLoginPortInput=${osSSHLoginPortInput:-0}

    if [ $osSSHLoginPortInput -eq 22 -o $osSSHLoginPortInput -gt 1024 -a $osSSHLoginPortInput -lt 65535 ]; then
        sed -i "s/#\?Port [0-9]*/Port $osSSHLoginPortInput/g" /etc/ssh/sshd_config

        if [ "$osRelease" == "centos" ] ; then
            yum -y install policycoreutils-python

            semanage port -a -t ssh_port_t -p tcp $osSSHLoginPortInput
            firewall-cmd --permanent --zone=public --add-port=$osSSHLoginPortInput/tcp 
            firewall-cmd --reload
            ${sudoCmd} service sshd restart
            ${sudoCmd} systemctl restart sshd
        fi

        if [ "$osRelease" == "ubuntu" ] || [ "$osRelease" == "debian" ] ; then
            semanage port -a -t ssh_port_t -p tcp $osSSHLoginPortInput
            sudo ufw allow $osSSHLoginPortInput/tcp

            ${sudoCmd} service ssh restart
            ${sudoCmd} systemctl restart ssh
        fi

        green "The setting is successful, please remember the port number set ${osSSHLoginPortInput}!"
        green "Login server command: ssh -p ${osSSHLoginPortInput} root@111.111.111.your ip !"
    else
        echo "The port number entered is wrong! Range: 22,1025~65534"
    fi
}

function setLinuxDateZone(){

    tempCurrentDateZone=$(date +'%z')

    if [[ ${tempCurrentDateZone} == "+0800" ]]; then
        yellow "The current time zone is already Beijing time  $tempCurrentDateZone | $(date -R) "
    else 
        green " =================================================="
        yellow "The current time zone is: $tempCurrentDateZone | $(date -R) "
        yellow "Whether to set the time zone to Beijing time +0800区, So that the cron timing restart script runs according to Beijing time."
        green " =================================================="
        # read 默认值 https://stackoverflow.com/questions/2642585/read-a-variable-in-bash-with-a-default-value

        read -p "Is it set to Beijing time +0800 time zone? Please enter[Y/n]?" osTimezoneInput
        osTimezoneInput=${osTimezoneInput:-Y}

        if [[ $osTimezoneInput == [Yy] ]]; then
            if [[ -f /etc/localtime ]] && [[ -f /usr/share/zoneinfo/Asia/Shanghai ]];  then
                mv /etc/localtime /etc/localtime.bak
                cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

                yellow "Set successfully! The current time zone has been set to $(date -R)"
                green " =================================================="
            fi
        fi

    fi
}



# Software Installation



function installBBR(){
    wget -O tcp_old.sh -N --no-check-certificate "https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp_old.sh && ./tcp_old.sh
}

function installBBR2(){
    
    if [[ -f ./tcp.sh ]];  then
        mv ./tcp.sh ./tcp_old.sh
    fi    
    wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
}


function installPackage(){
    if [ "$osRelease" == "centos" ]; then
       
        # rpm -Uvh http://nginx.org/packages/centos/7/noarch/RPMS/nginx-release-centos-7-0.el7.ngx.noarch.rpm

        cat > "/etc/yum.repos.d/nginx.repo" <<-EOF
[nginx]
name=nginx repo
baseurl=https://nginx.org/packages/centos/$osReleaseVersionNo/\$basearch/
gpgcheck=0
enabled=1

EOF

        $osSystemPackage update -y

        ${sudoCmd}  $osSystemPackage install -y epel-release

        $osSystemPackage install -y curl wget git unzip zip tar
        $osSystemPackage install -y xz jq redhat-lsb-core 
        $osSystemPackage install -y iputils-ping

    elif [ "$osRelease" == "ubuntu" ]; then
        
        # https://joshtronic.com/2018/12/17/how-to-install-the-latest-nginx-on-debian-and-ubuntu/
        # https://www.nginx.com/resources/wiki/start/topics/tutorials/install/
        
        $osSystemPackage install -y gnupg2
        wget -O - https://nginx.org/keys/nginx_signing.key | ${sudoCmd} apt-key add -

        cat > "/etc/apt/sources.list.d/nginx.list" <<-EOF
deb https://nginx.org/packages/ubuntu/ $osReleaseVersionCodeName nginx
deb-src https://nginx.org/packages/ubuntu/ $osReleaseVersionCodeName nginx
EOF

        $osSystemPackage update -y
        ${sudoCmd} $osSystemPackage install -y software-properties-common
        $osSystemPackage install -y curl wget git unzip zip tar
        $osSystemPackage install -y xz-utils jq lsb-core lsb-release
        $osSystemPackage install -y iputils-ping


    elif [ "$osRelease" == "debian" ]; then
        # ${sudoCmd} add-apt-repository ppa:nginx/stable -y

        $osSystemPackage install -y gnupg2
        wget -O - https://nginx.org/keys/nginx_signing.key | ${sudoCmd} apt-key add -
        # curl -L https://nginx.org/keys/nginx_signing.key | ${sudoCmd} apt-key add -

        cat > "/etc/apt/sources.list.d/nginx.list" <<-EOF 
deb http://nginx.org/packages/debian/ $osReleaseVersionCodeName nginx
deb-src http://nginx.org/packages/debian/ $osReleaseVersionCodeName nginx
EOF
        
        $osSystemPackage update -y
        $osSystemPackage install -y curl wget git unzip zip tar
        $osSystemPackage install -y xz-utils jq lsb-core lsb-release
        $osSystemPackage install -y iputils-ping
    fi
}


function installSoftEditor(){
    # Install the micro editor
    if [[ ! -f "${HOME}/bin/micro" ]] ;  then
        mkdir -p ${HOME}/bin
        cd ${HOME}/bin
        curl https://getmic.ro | bash

        cp ${HOME}/bin/micro /usr/local/bin

        green " =================================================="
        yellow " The micro editor is installed successfully!"
        green " =================================================="
    fi

    if [ "$osRelease" == "centos" ]; then   
        $osSystemPackage install -y xz  vim-minimal vim-enhanced vim-common
    else
        $osSystemPackage install -y vim-gui-common vim-runtime vim 
    fi

    # Set vim Chinese garbled
    if [[ ! -d "${HOME}/.vimrc" ]] ;  then
        cat > "${HOME}/.vimrc" <<-EOF
set fileencodings=utf-8,gb2312,gb18030,gbk,ucs-bom,cp936,latin1
set enc=utf8
set fencs=utf8,gbk,gb2312,gb18030

syntax on
colorscheme elflord

if has('mouse')
  se mouse+=a
  set number
endif

EOF
    fi
}

function installSoftOhMyZsh(){

    green " =================================================="
    yellow "Ready to install ZSH"
    green " =================================================="

    if [ "$osRelease" == "centos" ]; then

        ${sudoCmd} $osSystemPackage install zsh -y
        $osSystemPackage install util-linux-user -y

    elif [ "$osRelease" == "ubuntu" ]; then

        ${sudoCmd} $osSystemPackage install zsh -y

    elif [ "$osRelease" == "debian" ]; then

        ${sudoCmd} $osSystemPackage install zsh -y
    fi

    green " =================================================="
    yellow " ZSH installation is successful, ready to install oh-my-zsh"
    green " =================================================="

    # installation oh-my-zsh
    if [[ ! -d "${HOME}/.oh-my-zsh" ]] ;  then
        curl -Lo ${HOME}/ohmyzsh_install.sh https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh
        chmod +x ${HOME}/ohmyzsh_install.sh
        sh ${HOME}/ohmyzsh_install.sh --unattended
    fi

    if [[ ! -d "${HOME}/.oh-my-zsh/custom/plugins/zsh-autosuggestions" ]] ;  then
        git clone "https://github.com/zsh-users/zsh-autosuggestions" "${HOME}/.oh-my-zsh/custom/plugins/zsh-autosuggestions"

        # Configure zshrc file
        zshConfig=${HOME}/.zshrc
        zshTheme="maran"
        sed -i 's/ZSH_THEME=.*/ZSH_THEME="'"${zshTheme}"'"/' $zshConfig
        sed -i 's/plugins=(git)/plugins=(git cp history z rsync colorize nvm zsh-autosuggestions)/' $zshConfig

        zshAutosuggestionsConfig=${HOME}/.oh-my-zsh/custom/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh
        sed -i "s/ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=8'/ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=1'/" $zshAutosuggestionsConfig


        # Actually change the default shell to zsh
        zsh=$(which zsh)

        if ! chsh -s "$zsh"; then
            error "chsh command unsuccessful. Change your default shell manually."
        else
            export SHELL="$zsh"
            green "===== Shell successfully changed to '$zsh'."
        fi


        echo 'alias lla="ls -ahl"' >> ${HOME}/.zshrc
        echo 'alias mi="micro"' >> ${HOME}/.zshrc

        green " =================================================="
        yellow " oh-my-zsh is successfully installed, please use the exit command to exit the server and log in again!"
        green " =================================================="

    fi

}



# Network speed test

function vps_netflix(){
    # bash <(curl -sSL https://raw.githubusercontent.com/Netflixxp/NF/main/nf.sh)
    # bash <(curl -sSL "https://github.com/CoiaPrant/Netflix_Unlock_Information/raw/main/netflix.sh")
	# wget -N --no-check-certificate https://github.com/CoiaPrant/Netflix_Unlock_Information/raw/main/netflix.sh && chmod +x netflix.sh && ./netflix.sh

	wget -O netflix.sh -N --no-check-certificate https://github.com/CoiaPrant/MediaUnlock_Test/raw/main/check.sh && chmod +x netflix.sh && ./netflix.sh

    # wget -N -O nf https://github.com/sjlleo/netflix-verify/releases/download/2.01/nf_2.01_linux_amd64 && chmod +x nf && clear && ./nf
}


function vps_superspeed(){
	bash <(curl -Lso- https://git.io/superspeed)
	#wget -N --no-check-certificate https://raw.githubusercontent.com/ernisn/superspeed/master/superspeed.sh && chmod +x superspeed.sh && ./superspeed.sh
}

function vps_bench(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/teddysun/across/master/bench.sh && chmod +x bench.sh && bash bench.sh
}

function vps_zbench(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/FunctionClub/ZBench/master/ZBench-CN.sh && chmod +x ZBench-CN.sh && bash ZBench-CN.sh
}

function vps_testrace(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/nanqinlang-script/testrace/master/testrace.sh && chmod +x testrace.sh && ./testrace.sh
}

function vps_LemonBench(){
    wget -O LemonBench.sh -N --no-check-certificate https://ilemonra.in/LemonBenchIntl && chmod +x LemonBench.sh && ./LemonBench.sh fast
}





versionWgcf="2.2.2"
downloadFilenameWgcf="wgcf_${versionWgcf}_linux_amd64"
configWgcfBinPath="/usr/local/bin"
configWgcfConfigFilePath="${HOME}/wireguard"
configWgcfAccountFilePath="$configWgcfConfigFilePath/wgcf-account.toml"
configWgcfProfileFilePath="$configWgcfConfigFilePath/wgcf-profile.conf"

function installWireguard(){

    getTrojanAndV2rayVersion "wgcf"
    green " =================================================="
    green "    start installation Wireguard with Cloudflare Warp command line tool Wgcf ${versionWgcf} !"
    red "    Need to install first BBR script install original version BBR, can't install bbr plus"
    red "    Centos 7 recommended 4.11 kernel, Use the first BBR script of this script to install the original BBR"
    red "    Debian or Ubuntu Can also be used The new BBR installation script in this script installs the original BBR, Kernel is above 5.4"
    red "    Installing the kernel is risky, causing the VPS to fail to start, please use it with caution"
    green " =================================================="

    green "The current Linux kernel devel kernel version is: $(ls /usr/src/kernels)"
    green "The current Linux kernel version is: $(uname -r)"
    echo ""
    green "To install Wireguard, you need to ensure that the versions of kernel, kernel-devel, and kernel-headers are consistent"

	read -p "Do you want to continue? Please confirm that the linux kernel has been installed correctly and press Enter to continue the operation by default, please enter[Y/n]?" isContinueInput
	isContinueInput=${isContinueInput:-Y}

	if [[ $isContinueInput == [Yy] ]]; then
		echo ""
	else 
        green " Please use the first item of this script to install the BBR script to install the original version of BBR, and change the linux kernel to 4.11!"
		exit
	fi

    mkdir -p ${configWgcfConfigFilePath}
    mkdir -p ${configWgcfBinPath}
    cd ${configWgcfConfigFilePath}

    # https://github.com/ViRb3/wgcf/releases/download/v2.2.2/wgcf_2.2.2_linux_amd64
    wget -O ${configWgcfPath}/wgcf --no-check-certificate "https://github.com/ViRb3/wgcf/releases/download/v${versionWgcf}/${downloadFilenameWgcf}"
    ${sudoCmd} chmod +x ${configWgcfPath}/wgcf

    if [[ -f ${configWgcfPath}/wgcf ]]; then

        green " Cloudflare Warp 命令行工具 Wgcf ${versionWgcf} 下载成功!"

        # ${configWgcfPath}/wgcf register --config "${configWgcfAccountFilePath}"
        # ${configWgcfPath}/wgcf generate --config "${configWgcfProfileFilePath}"

        ${configWgcfPath}/wgcf register 
        ${configWgcfPath}/wgcf generate 

        sed -i '/AllowedIPs = 0\.0\.0\.0/d' ${configWgcfProfileFilePath}
        sed -i 's/engage\.cloudflareclient\.com/162\.159\.192\.1/g'  ${configWgcfProfileFilePath}

    else
        ren "  Wgcf ${versionWgcf} 下载失败!"
        exit
    fi

    green "  Start installing Wireguard!"
    bash <(curl -sSL https://raw.githubusercontent.com/jinwyp/one_click_script/master/wireguard.sh)
    # wget -O wireguard.sh -N --no-check-certificate "https://raw.githubusercontent.com/teddysun/across/master/wireguard.sh" && chmod 755 wireguard.sh && ./wireguard.sh -r


    echo "nameserver 8.8.8.8" >>  /etc/resolv.conf
    echo "nameserver 8.8.4.4" >>  /etc/resolv.conf
    echo "nameserver 1.1.1.1" >>  /etc/resolv.conf
    echo "nameserver 9.9.9.9" >>  /etc/resolv.conf
    echo "nameserver 9.9.9.10" >>  /etc/resolv.conf
    echo "nameserver 8.8.8.8" >>  /etc/resolv.conf


    cp ${configWgcfProfileFilePath} /etc/wireguard/wgcf.conf 

    echo 
    green " =================================================="
    
    ${sudoCmd} wg-quick up wgcf

    echo 
    green "  Verify whether Wireguard starts normally. Check whether CLOUDFLARE's ipv6 access is used!"
    isWireguardIpv6Working=$(curl -6 ip.p3terx.com | grep CLOUDFLARENET )
    echo
    echo "curl -6 ip.p3terx.com"
    curl -6 ip.p3terx.com 
    echo
    ${sudoCmd} wg-quick down wgcf


	if [[ -n "$isWireguardIpv6Working" ]]; then	
		green " Wireguard starts normally! "
        echo
	else 
		green " ================================================== "
		red " Wireguard uses curl -6 ip.p3terx.com to detect IPV6 access failure using CLOUDFLARENET"
        red " Please check if the linux kernel is installed correctly, uninstall and reinstall"
        red " The installation will continue to run, or the installation may be successful, but IPV6 is not used"
		green " ================================================== "
		
	fi


    ${sudoCmd} systemctl daemon-reload

    # Enable daemon
    ${sudoCmd} systemctl start wg-quick@wgcf

    # Set boot up
    ${sudoCmd} systemctl enable wg-quick@wgcf


    green " ================================================== "
    green "  Wireguard with Cloudflare Warp Command line tool Wgcf ${versionWgcf} Successful installation !"
    green "  Wireguard Stop: systemctl stop wg-quick@wgcf  Start: systemctl start wg-quick@wgcf  Restart: systemctl restart wg-quick@wgcf"
    green "  Wireguard view log: journalctl -n 50 -u wg-quick@wgcf Check running status: systemctl status wg-quick@wgcf"
    
    green "  Use this script to install v2ray or xray, you can choose whether to lift the google verification code and Netflix restrictions!"
    green "  For v2ray or xray installed by other scripts, please replace the v2ray or xray configuration file yourself!"
    green " ================================================== "
    
}


function removeWireguard(){
    green " ================================================== "
    red " Prepare to uninstall the installed Wireguard and Cloudflare Warp command line tool Wgcf "
    green " ================================================== "

    if [ -f "${configWgcfBinPath}/wgcf" ]; then
        ${sudoCmd} systemctl stop wg-quick@wgcf.service
        ${sudoCmd} systemctl disable wg-quick@wgcf.service
    else 
        red " The system does not have Wireguard and Wgcf installed, exit to uninstall"
        exit
    fi

    $osSystemPackage -y remove wireguard-dkms
    $osSystemPackage -y remove wireguard-tools

    rm -rf ${configWgcfConfigFilePath}

    rm -f ${osSystemMdPath}wg-quick@wgcf.service

    rm -f /usr/bin/wg
    rm -f /usr/bin/wg-quick
    rm -f /usr/share/man/man8/wg.8
    rm -f /usr/share/man/man8/wg-quick.8

    [ -d "/etc/wireguard" ] && ("rm -rf /etc/wireguard")

    modprobe -r wireguard

    green " ================================================== "
    green "  Wireguard and Cloudflare Warp command line tool Wgcf are uninstalled!"
    green " ================================================== "

  
}







configNetworkRealIp=""
configNetworkLocalIp=""
configSSLDomain=""

configSSLCertPath="${HOME}/website/cert"
configWebsitePath="${HOME}/website/html"
configTrojanWindowsCliPrefixPath=$(cat /dev/urandom | head -1 | md5sum | head -c 20)
configWebsiteDownloadPath="${configWebsitePath}/download/${configTrojanWindowsCliPrefixPath}"
configDownloadTempPath="${HOME}/temp"



versionTrojan="1.16.0"
downloadFilenameTrojan="trojan-${versionTrojan}-linux-amd64.tar.xz"

versionTrojanGo="0.8.2"
downloadFilenameTrojanGo="trojan-go-linux-amd64.zip"

versionV2ray="4.33.0"
downloadFilenameV2ray="v2ray-linux-64.zip"

versionXray="1.1.1"
downloadFilenameXray="Xray-linux-64.zip"

versionTrojanWeb="2.8.7"
downloadFilenameTrojanWeb="trojan"

promptInfoTrojanName=""
isTrojanGo="no"
isTrojanGoSupportWebsocket="false"
configTrojanGoWebSocketPath=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
configTrojanPasswordPrefixInput="jin"

configTrojanPath="${HOME}/trojan"
configTrojanGoPath="${HOME}/trojan-go"
configTrojanWebPath="${HOME}/trojan-web"
configTrojanLogFile="${HOME}/trojan-access.log"
configTrojanGoLogFile="${HOME}/trojan-go-access.log"

configTrojanBasePath=${configTrojanPath}
configTrojanBaseVersion=${versionTrojan}

configTrojanWebNginxPath=$(cat /dev/urandom | head -1 | md5sum | head -c 5)
configTrojanWebPort="$(($RANDOM + 10000))"


isInstallNginx="true"
isNginxWithSSL="no"
nginxConfigPath="/etc/nginx/nginx.conf"
nginxAccessLogFilePath="${HOME}/nginx-access.log"
nginxErrorLogFilePath="${HOME}/nginx-error.log"

promptInfoXrayInstall="V2ray"
promptInfoXrayVersion=""
promptInfoXrayName="v2ray"
isXray="no"

configV2rayWebSocketPath=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
configV2rayPort="$(($RANDOM + 10000))"
configV2rayVmessTCPPort="$(($RANDOM + 10000))"
configV2rayPortShowInfo=$configV2rayPort
configV2rayIsTlsShowInfo="none"
configV2rayTrojanPort="$(($RANDOM + 10000))"

configV2rayPath="${HOME}/v2ray"
configV2rayAccessLogFilePath="${HOME}/v2ray-access.log"
configV2rayErrorLogFilePath="${HOME}/v2ray-error.log"
configV2rayProtocol="vmess"
configV2rayVlessMode=""
configReadme=${HOME}/trojan_v2ray_readme.txt


function downloadAndUnzip(){
    if [ -z $1 ]; then
        green " ================================================== "
        green "     The download file address is empty!"
        green " ================================================== "
        exit
    fi
    if [ -z $2 ]; then
        green " ================================================== "
        green "     The destination path address is empty!"
        green " ================================================== "
        exit
    fi
    if [ -z $3 ]; then
        green " ================================================== "
        green "     The file name of the downloaded file is empty!"
        green " ================================================== "
        exit
    fi

    mkdir -p ${configDownloadTempPath}

    if [[ $3 == *"tar.xz"* ]]; then
        green "===== Download and unzip the tar file: $3 "
        wget -O ${configDownloadTempPath}/$3 $1
        tar xf ${configDownloadTempPath}/$3 -C ${configDownloadTempPath}
        mv ${configDownloadTempPath}/trojan/* $2
        rm -rf ${configDownloadTempPath}/trojan
    else
        green "===== Download and unzip the zip file:  $3 "
        wget -O ${configDownloadTempPath}/$3 $1
        unzip -d $2 ${configDownloadTempPath}/$3
    fi

}

function getGithubLatestReleaseVersion(){
    # https://github.com/p4gefau1t/trojan-go/issues/63
    wget --no-check-certificate -qO- https://api.github.com/repos/$1/tags | grep 'name' | cut -d\" -f4 | head -1 | cut -b 2-
}

function getTrojanAndV2rayVersion(){
    # https://github.com/trojan-gfw/trojan/releases/download/v1.16.0/trojan-1.16.0-linux-amd64.tar.xz
    # https://github.com/p4gefau1t/trojan-go/releases/download/v0.8.1/trojan-go-linux-amd64.zip

    echo ""

    if [[ $1 == "trojan" ]] ; then
        versionTrojan=$(getGithubLatestReleaseVersion "trojan-gfw/trojan")
        downloadFilenameTrojan="trojan-${versionTrojan}-linux-amd64.tar.xz"
        echo "versionTrojan: ${versionTrojan}"
    fi

    if [[ $1 == "trojan-go" ]] ; then
        versionTrojanGo=$(getGithubLatestReleaseVersion "p4gefau1t/trojan-go")
        downloadFilenameTrojanGo="trojan-go-linux-amd64.zip"
        echo "versionTrojanGo: ${versionTrojanGo}"
    fi

    if [[ $1 == "v2ray" ]] ; then
        versionV2ray=$(getGithubLatestReleaseVersion "v2fly/v2ray-core")
        echo "versionV2ray: ${versionV2ray}"
    fi

    if [[ $1 == "xray" ]] ; then
        versionXray=$(getGithubLatestReleaseVersion "XTLS/Xray-core")
        echo "versionXray: ${versionXray}"
    fi

    if [[ $1 == "trojan-web" ]] ; then
        versionTrojanWeb=$(getGithubLatestReleaseVersion "Jrohy/trojan")
        downloadFilenameTrojanWeb="trojan"
        echo "versionTrojanWeb: ${versionTrojanWeb}"
    fi

    if [[ $1 == "wgcf" ]] ; then
        versionWgcf=$(getGithubLatestReleaseVersion "ViRb3/wgcf")
        downloadFilenameWgcf="wgcf_${versionWgcf}_linux_amd64"
        echo "versionWgcf: ${versionWgcf}"
    fi

}

function stopServiceNginx(){
    serviceNginxStatus=`ps -aux | grep "nginx: worker" | grep -v "grep"`
    if [[ -n "$serviceNginxStatus" ]]; then
        ${sudoCmd} systemctl stop nginx.service
    fi
}

function stopServiceV2ray(){
    if [[ -f "${osSystemMdPath}v2ray.service" ]] || [[ -f "/etc/systemd/system/v2ray.service" ]] || [[ -f "/lib/systemd/system/v2ray.service" ]] ; then
        ${sudoCmd} systemctl stop v2ray.service
    fi
}

function isTrojanGoInstall(){
    if [ "$isTrojanGo" = "yes" ] ; then
        getTrojanAndV2rayVersion "trojan-go"
        configTrojanBaseVersion=${versionTrojanGo}
        configTrojanBasePath="${configTrojanGoPath}"
        promptInfoTrojanName="-go"
    else
        getTrojanAndV2rayVersion "trojan"
        configTrojanBaseVersion=${versionTrojan}
        configTrojanBasePath="${configTrojanPath}"
        promptInfoTrojanName=""
    fi
}


function compareRealIpWithLocalIp(){

    yellow " Check whether the IP pointed by the domain name is correct (default detection, if the IP pointed by the domain name is not the IP of this machine, you cannot continue. If the CDN is turned on, it is inconvenient to turn it off, you can choose No)"
    read -p "Check whether the IP pointed by the domain name is correct? Please enter[Y/n]?" isDomainValidInput
    isDomainValidInput=${isDomainValidInput:-Y}

    if [[ $isDomainValidInput == [Yy] ]]; then
        if [ -n $1 ]; then
            configNetworkRealIp=`ping $1 -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
            # configNetworkLocalIp=`curl ipv4.icanhazip.com`
            configNetworkLocalIp=`curl v4.ident.me`

            green " ================================================== "
            green "     The domain name resolution address is ${configNetworkRealIp}, 本VPS的IP为 ${configNetworkLocalIp}. "
            green " ================================================== "

            if [[ ${configNetworkRealIp} == ${configNetworkLocalIp} ]] ; then
                green " ================================================== "
                green "     The IP resolved by the domain name is normal!"
                green " ================================================== "
                true
            else
                green " ================================================== "
                red "     The domain name resolution address is inconsistent with the VPS IP address!"
                red "     This installation failed, please make sure that the domain name resolution is normal, please check whether the domain name and DNS are valid!"
                green " ================================================== "
                false
            fi
        else
            green " ================================================== "        
            red "     The domain name is entered incorrectly!"
            green " ================================================== "        
            false
        fi
        
    else
        green " ================================================== "
        green "     Do not check whether the domain name resolution is correct!"
        green " ================================================== "
        true
    fi
}

function getHTTPSCertificate(){

    # Apply for https certificate
	mkdir -p ${configSSLCertPath}
	mkdir -p ${configWebsitePath}
	curl https://get.acme.sh | sh

    green "=========================================="

	if [[ $1 == "standalone" ]] ; then
	    green "  Start to re-apply for a certificate acme.sh standalone mode !"
	    ~/.acme.sh/acme.sh  --issue  -d ${configSSLDomain}  --standalone

        ~/.acme.sh/acme.sh  --installcert  -d ${configSSLDomain}   \
        --key-file   ${configSSLCertPath}/private.key \
        --fullchain-file ${configSSLCertPath}/fullchain.cer

	else
	    green "  Start applying for a certificate for the first time acme.sh nginx mode !"
        ~/.acme.sh/acme.sh  --issue  -d ${configSSLDomain}  --webroot ${configWebsitePath}/

        ~/.acme.sh/acme.sh  --installcert  -d ${configSSLDomain}   \
        --key-file   ${configSSLCertPath}/private.key \
        --fullchain-file ${configSSLCertPath}/fullchain.cer \
        --reloadcmd  "systemctl force-reload  nginx.service"
    fi
}



function installWebServerNginx(){

    green " ================================================== "
    yellow "     Start to install the web server nginx !"
    green " ================================================== "

    if test -s ${nginxConfigPath}; then
        green " ================================================== "
        red "     Nginx Already exist, exit the installation!"
        green " ================================================== "
        exit
    fi

    stopServiceV2ray

    ${osSystemPackage} install nginx -y
    ${sudoCmd} systemctl enable nginx.service
    ${sudoCmd} systemctl stop nginx.service

    if [[ -z $1 ]] ; then
        cat > "${nginxConfigPath}" <<-EOF
user  root;
worker_processes  1;
error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;
events {
    worker_connections  1024;
}
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] '
                      '"\$request" \$status \$body_bytes_sent  '
                      '"\$http_referer" "\$http_user_agent" "\$http_x_forwarded_for"';
    access_log  $nginxAccessLogFilePath  main;
    error_log $nginxErrorLogFilePath;
    sendfile        on;
    #tcp_nopush     on;
    keepalive_timeout  120;
    client_max_body_size 20m;
    #gzip  on;

    server {
        listen       80;
        server_name  $configSSLDomain;
        root $configWebsitePath;
        index index.php index.html index.htm;

        location /$configV2rayWebSocketPath {
            proxy_pass http://127.0.0.1:$configV2rayPort;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;

            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }
    }
}
EOF

    elif [[ $1 == "trojan-web" ]] ; then

        cat > "${nginxConfigPath}" <<-EOF
user  root;
worker_processes  1;
error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;
events {
    worker_connections  1024;
}
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] '
                      '"\$request" \$status \$body_bytes_sent  '
                      '"\$http_referer" "\$http_user_agent" "\$http_x_forwarded_for"';
    access_log  $nginxAccessLogFilePath  main;
    error_log $nginxErrorLogFilePath;
    sendfile        on;
    #tcp_nopush     on;
    keepalive_timeout  120;
    client_max_body_size 20m;
    #gzip  on;

    server {
        listen       80;
        server_name  $configSSLDomain;
        root $configWebsitePath;
        index index.php index.html index.htm;

        location /$configV2rayWebSocketPath {
            proxy_pass http://127.0.0.1:$configV2rayPort;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;
        }

        location /$configTrojanWebNginxPath {
            proxy_pass http://127.0.0.1:$configTrojanWebPort/;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Host \$http_host;
        }

        location ~* ^/(js|css|vendor|common|auth|trojan)/ {
            proxy_pass  http://127.0.0.1:$configTrojanWebPort;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;
        }

        # http redirect to https
        if ( \$remote_addr != 127.0.0.1 ){
            rewrite ^/(.*)$ https://$configSSLDomain/\$1 redirect;
        }
    }
}
EOF
    else
        cat > "${nginxConfigPath}" <<-EOF
user  root;
worker_processes  1;
error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;
events {
    worker_connections  1024;
}
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] '
                      '"\$request" \$status \$body_bytes_sent  '
                      '"\$http_referer" "\$http_user_agent" "\$http_x_forwarded_for"';
    access_log  $nginxAccessLogFilePath  main;
    error_log $nginxErrorLogFilePath;
    sendfile        on;
    #tcp_nopush     on;
    keepalive_timeout  120;
    client_max_body_size 20m;
    #gzip  on;

    server {
        listen 443 ssl http2;
        listen [::]:443 http2;
        server_name  $configSSLDomain;

        ssl_certificate       ${configSSLCertPath}/fullchain.cer;
        ssl_certificate_key   ${configSSLCertPath}/private.key;
        ssl_protocols         TLSv1.2 TLSv1.3;
        ssl_ciphers           TLS-AES-256-GCM-SHA384:TLS-CHACHA20-POLY1305-SHA256:TLS-AES-128-GCM-SHA256:TLS-AES-128-CCM-8-SHA256:TLS-AES-128-CCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256;


        # Config for 0-RTT in TLSv1.3
        ssl_early_data on;
        ssl_stapling on;
        ssl_stapling_verify on;
        add_header Strict-Transport-Security "max-age=31536000";
        
        root $configWebsitePath;
        index index.php index.html index.htm;

        location /$configV2rayWebSocketPath {
            proxy_pass http://127.0.0.1:$configV2rayPort;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }
    }

    server {
        listen 80;
        listen [::]:80;
        server_name  $configSSLDomain;
        return 301 https://$configSSLDomain\$request_uri;
    }
}
EOF
    fi



    # Download the fake site and set the fake site
    rm -rf ${configWebsitePath}/*
    mkdir -p ${configWebsiteDownloadPath}

    downloadAndUnzip "https://github.com/jinwyp/one_click_script/raw/master/download/website.zip" "${configWebsitePath}" "website.zip"
    downloadAndUnzip "https://github.com/jinwyp/one_click_script/raw/master/download/trojan_client_all.zip" "${configWebsiteDownloadPath}" "trojan_client_all.zip"
    #downloadAndUnzip "https://github.com/jinwyp/one_click_script/raw/master/download/trojan-qt5.zip" "${configWebsiteDownloadPath}" "trojan-qt5.zip"
    
    downloadAndUnzip "https://github.com/jinwyp/one_click_script/raw/master/download/v2ray_client_all.zip" "${configWebsiteDownloadPath}" "v2ray_client_all.zip"
    #wget -P "${configWebsiteDownloadPath}" "https://github.com/jinwyp/one_click_script/raw/master/download/v2ray-android.zip"

    ${sudoCmd} systemctl start nginx.service

    green " ================================================== "
    green "       The web server nginx is installed successfully!!"
    green "    The fake site is http://${configSSLDomain}"

	if [[ $1 == "trojan-web" ]] ; then
	    yellow "    Trojan-web ${versionTrojanWeb} Visual management panel address  http://${configSSLDomain}/${configTrojanWebNginxPath} "
	    green "    Trojan-web Visual management panel executable file path ${configTrojanWebPath}/trojan-web"
	    green "    Trojan Server-side executable file path /usr/bin/trojan/trojan"
	    green "    Trojan Server-side configuration path /usr/local/etc/trojan/config.json "
	    green "    Trojan-web Stop: systemctl stop trojan-web.service  Start: systemctl start trojan-web.service  Restart: systemctl restart trojan-web.service"
	    green "    Trojan Stop: systemctl stop trojan.service  Start: systemctl start trojan.service  Restart: systemctl restart trojan.service"
	fi

    green "    The static html content of the fake site is placed in the directory ${configWebsitePath}, You can change the content of the website yourself!"
	green "    nginx config path ${nginxConfigPath} "
	green "    nginx access log ${nginxAccessLogFilePath} "
	green "    nginx error log ${nginxErrorLogFilePath} "
	green "    nginx Stop: systemctl stop nginx.service  Start: systemctl start nginx.service  Restart: systemctl restart nginx.service"
    green " ================================================== "

    cat >> ${configReadme} <<-EOF

Webserver nginx install successful! disguised website is ${configSSLDomain}   
The static html content of the fake site is placed in the directory ${configWebsitePath}, You can change the content of the website by yourself.
nginx config path ${nginxConfigPath}, nginx access log ${nginxAccessLogFilePath}, nginx error log ${nginxErrorLogFilePath}
nginx Stop: systemctl stop nginx.service  Start: systemctl start nginx.service  Restart: systemctl restart nginx.service

EOF


	if [[ $1 == "trojan-web" ]] ; then
        cat >> ${configReadme} <<-EOF

Trojan-web installed ${versionTrojanWeb} Visual management panel, access address  ${configSSLDomain}/${configTrojanWebNginxPath}
Trojan-web Stop: systemctl stop trojan-web.service  Start: systemctl start trojan-web.service  Restart: systemctl restart trojan-web.service


EOF
	fi

}

function removeNginx(){

    ${sudoCmd} systemctl stop nginx.service

    green " ================================================== "
    red " Ready to uninstall the installed nginx"
    green " ================================================== "

    if [ "$osRelease" == "centos" ]; then
        yum remove -y nginx
    else
        apt autoremove -y --purge nginx nginx-common nginx-core
        apt-get remove --purge nginx nginx-full nginx-common nginx-core
    fi

    rm -rf ${configSSLCertPath}
    rm -rf ${configWebsitePath}
    rm -f ${nginxAccessLogFilePath}
    rm -f ${nginxErrorLogFilePath}

    rm -f ${configReadme}

    rm -rf "/etc/nginx"
    ${sudoCmd} bash /root/.acme.sh/acme.sh --uninstall
    uninstall /root/.acme.sh
    rm -rf ${configDownloadTempPath}

    green " ================================================== "
    green "  Nginx Uninstallation is complete!"
    green " ================================================== "
}


function installTrojanWholeProcess(){

    stopServiceNginx
    testLinuxPortUsage
    installPackage

    green " ================================================== "
    yellow " Please enter the domain name bound to this VPS, such as www.xxx.com: (Please close CDN and install after this step)"
    if [[ $1 == "repair" ]] ; then
        blue " It must be the same as the domain name used when the previous installation failed"
    fi
    green " ================================================== "

    read configSSLDomain
    if compareRealIpWithLocalIp "${configSSLDomain}" ; then

        if [[ -z $1 ]] ; then
            if [ "$isNginxWithSSL" = "no" ] ; then
                getHTTPSCertificate "standalone"
                installWebServerNginx
            else
                getHTTPSCertificate "standalone"
                installWebServerNginx "v2ray"
            fi

        else
            getHTTPSCertificate "standalone"
        fi

        if test -s ${configSSLCertPath}/fullchain.cer; then
            green " ================================================== "
            green "     The SSL certificate has been detected successfully!"
            green " ================================================== "

            if [ "$isNginxWithSSL" = "no" ] ; then
                installTrojanServer
            else
                installV2ray
            fi
        else
            red "==================================="
            red " The https certificate was not successfully applied, and the installation failed!"
            red " Please check whether the domain name and DNS are valid, please do not apply for the same domain name multiple times in one day!"
            red " Please check whether ports 80 and 443 are open, VPS service providers may need to add additional firewall rules, such as Alibaba Cloud, Google Cloud, etc.!"
            red " Restart the VPS, re-execute the script, and re-select the repair certificate option to apply for the certificate again!"
            red " Can refer to https://www.v2rayssr.com/trojan-2.html"
            red "==================================="
            exit
        fi
    else
        exit
    fi
}




function installTrojanServer(){

    trojanPassword1=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword2=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword3=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword4=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword5=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword6=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword7=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword8=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword9=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword10=$(cat /dev/urandom | head -1 | md5sum | head -c 10)

    isTrojanGoInstall

    if [[ -f "${configTrojanBasePath}/trojan${promptInfoTrojanName}" ]]; then
        green " =================================================="
        green "  Trojan${promptInfoTrojanName} has been installed, exit the installation!"
        green " =================================================="
        exit
    fi


    green " =================================================="
    green " Start installing Trojan${promptInfoTrojanName} Version: ${configTrojanBaseVersion}!"
    yellow " Please enter the prefix of the trojan password? (A number of random passwords and passwords with this prefix will be generated)"
    green " =================================================="

    read configTrojanPasswordPrefixInput
    configTrojanPasswordPrefixInput=${configTrojanPasswordPrefixInput:-jin}

    mkdir -p ${configTrojanBasePath}
    cd ${configTrojanBasePath}
    rm -rf ${configTrojanBasePath}/*

    if [ "$isTrojanGo" = "no" ] ; then
        # https://github.com/trojan-gfw/trojan/releases/download/v1.16.0/trojan-1.16.0-linux-amd64.tar.xz
        downloadAndUnzip "https://github.com/trojan-gfw/trojan/releases/download/v${versionTrojan}/${downloadFilenameTrojan}" "${configTrojanPath}" "${downloadFilenameTrojan}"
    else
        # https://github.com/p4gefau1t/trojan-go/releases/download/v0.8.1/trojan-go-linux-amd64.zip
        downloadAndUnzip "https://github.com/p4gefau1t/trojan-go/releases/download/v${versionTrojanGo}/${downloadFilenameTrojanGo}" "${configTrojanGoPath}" "${downloadFilenameTrojanGo}"
    fi


    if [ "$configV2rayVlessMode" != "trojan" ] ; then
        configV2rayTrojanPort=443
    elif [ "$configV2rayVlessMode" != "vlesstrojan" ] ; then
        configV2rayTrojanPort=443
    fi


    if [ "$isTrojanGo" = "no" ] ; then

        # Add trojan server configuration
	    cat > ${configTrojanBasePath}/server.json <<-EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": $configV2rayTrojanPort,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "${trojanPassword1}",
        "${trojanPassword2}",
        "${trojanPassword3}",
        "${trojanPassword4}",
        "${trojanPassword5}",
        "${trojanPassword6}",
        "${trojanPassword7}",
        "${trojanPassword8}",
        "${trojanPassword9}",
        "${trojanPassword10}",
        "${configTrojanPasswordPrefixInput}202000",
        "${configTrojanPasswordPrefixInput}202010",
        "${configTrojanPasswordPrefixInput}202011",
        "${configTrojanPasswordPrefixInput}202012",
        "${configTrojanPasswordPrefixInput}202013",
        "${configTrojanPasswordPrefixInput}202014",
        "${configTrojanPasswordPrefixInput}202015",
        "${configTrojanPasswordPrefixInput}202016",
        "${configTrojanPasswordPrefixInput}202017",
        "${configTrojanPasswordPrefixInput}202018",
        "${configTrojanPasswordPrefixInput}202019",
        "${configTrojanPasswordPrefixInput}202020",
        "${configTrojanPasswordPrefixInput}202021",
        "${configTrojanPasswordPrefixInput}202022",
        "${configTrojanPasswordPrefixInput}202023",
        "${configTrojanPasswordPrefixInput}202024",
        "${configTrojanPasswordPrefixInput}202025",
        "${configTrojanPasswordPrefixInput}202026",
        "${configTrojanPasswordPrefixInput}202027",
        "${configTrojanPasswordPrefixInput}202028",
        "${configTrojanPasswordPrefixInput}202029",
        "${configTrojanPasswordPrefixInput}202030",
        "${configTrojanPasswordPrefixInput}202031",
        "${configTrojanPasswordPrefixInput}202032",
        "${configTrojanPasswordPrefixInput}202033",
        "${configTrojanPasswordPrefixInput}202034",
        "${configTrojanPasswordPrefixInput}202035",
        "${configTrojanPasswordPrefixInput}202036",
        "${configTrojanPasswordPrefixInput}202037",
        "${configTrojanPasswordPrefixInput}202038",
        "${configTrojanPasswordPrefixInput}202039",
        "${configTrojanPasswordPrefixInput}202040",
        "${configTrojanPasswordPrefixInput}202041",
        "${configTrojanPasswordPrefixInput}202042",
        "${configTrojanPasswordPrefixInput}202043",
        "${configTrojanPasswordPrefixInput}202044",
        "${configTrojanPasswordPrefixInput}202045",
        "${configTrojanPasswordPrefixInput}202046",
        "${configTrojanPasswordPrefixInput}202047",
        "${configTrojanPasswordPrefixInput}202048",
        "${configTrojanPasswordPrefixInput}202049",
        "${configTrojanPasswordPrefixInput}202050",
        "${configTrojanPasswordPrefixInput}202051",
        "${configTrojanPasswordPrefixInput}202052",
        "${configTrojanPasswordPrefixInput}202053",
        "${configTrojanPasswordPrefixInput}202054",
        "${configTrojanPasswordPrefixInput}202055",
        "${configTrojanPasswordPrefixInput}202056",
        "${configTrojanPasswordPrefixInput}202057",
        "${configTrojanPasswordPrefixInput}202058",
        "${configTrojanPasswordPrefixInput}202059",
        "${configTrojanPasswordPrefixInput}202060",
        "${configTrojanPasswordPrefixInput}202061",
        "${configTrojanPasswordPrefixInput}202062",
        "${configTrojanPasswordPrefixInput}202063",
        "${configTrojanPasswordPrefixInput}202064",
        "${configTrojanPasswordPrefixInput}202065",
        "${configTrojanPasswordPrefixInput}202066",
        "${configTrojanPasswordPrefixInput}202067",
        "${configTrojanPasswordPrefixInput}202068",
        "${configTrojanPasswordPrefixInput}202069",
        "${configTrojanPasswordPrefixInput}202070",
        "${configTrojanPasswordPrefixInput}202071",
        "${configTrojanPasswordPrefixInput}202072",
        "${configTrojanPasswordPrefixInput}202073",
        "${configTrojanPasswordPrefixInput}202074",
        "${configTrojanPasswordPrefixInput}202075",
        "${configTrojanPasswordPrefixInput}202076",
        "${configTrojanPasswordPrefixInput}202077",
        "${configTrojanPasswordPrefixInput}202078",
        "${configTrojanPasswordPrefixInput}202079",
        "${configTrojanPasswordPrefixInput}202080",
        "${configTrojanPasswordPrefixInput}202081",
        "${configTrojanPasswordPrefixInput}202082",
        "${configTrojanPasswordPrefixInput}202083",
        "${configTrojanPasswordPrefixInput}202084",
        "${configTrojanPasswordPrefixInput}202085",
        "${configTrojanPasswordPrefixInput}202086",
        "${configTrojanPasswordPrefixInput}202087",
        "${configTrojanPasswordPrefixInput}202088",
        "${configTrojanPasswordPrefixInput}202089",
        "${configTrojanPasswordPrefixInput}202090",
        "${configTrojanPasswordPrefixInput}202091",
        "${configTrojanPasswordPrefixInput}202092",
        "${configTrojanPasswordPrefixInput}202093",
        "${configTrojanPasswordPrefixInput}202094",
        "${configTrojanPasswordPrefixInput}202095",
        "${configTrojanPasswordPrefixInput}202096",
        "${configTrojanPasswordPrefixInput}202097",
        "${configTrojanPasswordPrefixInput}202098",
        "${configTrojanPasswordPrefixInput}202099"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "${configSSLCertPath}/fullchain.cer",
        "key": "${configSSLCertPath}/private.key",
        "key_password": "",
        "cipher_tls13":"TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
	    "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": ""
    }
}
EOF

        rm /etc/systemd/system/trojan.service   
        # Add startup script
        cat > ${osSystemMdPath}trojan.service <<-EOF
[Unit]
Description=trojan
After=network.target

[Service]
Type=simple
PIDFile=${configTrojanPath}/trojan.pid
ExecStart=${configTrojanPath}/trojan -l ${configTrojanLogFile} -c "${configTrojanPath}/server.json"
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
RestartPreventExitStatus=23
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    fi


    if [ "$isTrojanGo" = "yes" ] ; then

        # Add trojan server configuration
	    cat > ${configTrojanBasePath}/server.json <<-EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": $configV2rayTrojanPort,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "${trojanPassword1}",
        "${trojanPassword2}",
        "${trojanPassword3}",
        "${trojanPassword4}",
        "${trojanPassword5}",
        "${trojanPassword6}",
        "${trojanPassword7}",
        "${trojanPassword8}",
        "${trojanPassword9}",
        "${trojanPassword10}",
        "${configTrojanPasswordPrefixInput}202000",
        "${configTrojanPasswordPrefixInput}202010",
        "${configTrojanPasswordPrefixInput}202011",
        "${configTrojanPasswordPrefixInput}202012",
        "${configTrojanPasswordPrefixInput}202013",
        "${configTrojanPasswordPrefixInput}202014",
        "${configTrojanPasswordPrefixInput}202015",
        "${configTrojanPasswordPrefixInput}202016",
        "${configTrojanPasswordPrefixInput}202017",
        "${configTrojanPasswordPrefixInput}202018",
        "${configTrojanPasswordPrefixInput}202019",
        "${configTrojanPasswordPrefixInput}202020",
        "${configTrojanPasswordPrefixInput}202021",
        "${configTrojanPasswordPrefixInput}202022",
        "${configTrojanPasswordPrefixInput}202023",
        "${configTrojanPasswordPrefixInput}202024",
        "${configTrojanPasswordPrefixInput}202025",
        "${configTrojanPasswordPrefixInput}202026",
        "${configTrojanPasswordPrefixInput}202027",
        "${configTrojanPasswordPrefixInput}202028",
        "${configTrojanPasswordPrefixInput}202029",
        "${configTrojanPasswordPrefixInput}202030",
        "${configTrojanPasswordPrefixInput}202031",
        "${configTrojanPasswordPrefixInput}202032",
        "${configTrojanPasswordPrefixInput}202033",
        "${configTrojanPasswordPrefixInput}202034",
        "${configTrojanPasswordPrefixInput}202035",
        "${configTrojanPasswordPrefixInput}202036",
        "${configTrojanPasswordPrefixInput}202037",
        "${configTrojanPasswordPrefixInput}202038",
        "${configTrojanPasswordPrefixInput}202039",
        "${configTrojanPasswordPrefixInput}202040",
        "${configTrojanPasswordPrefixInput}202041",
        "${configTrojanPasswordPrefixInput}202042",
        "${configTrojanPasswordPrefixInput}202043",
        "${configTrojanPasswordPrefixInput}202044",
        "${configTrojanPasswordPrefixInput}202045",
        "${configTrojanPasswordPrefixInput}202046",
        "${configTrojanPasswordPrefixInput}202047",
        "${configTrojanPasswordPrefixInput}202048",
        "${configTrojanPasswordPrefixInput}202049",
        "${configTrojanPasswordPrefixInput}202050",
        "${configTrojanPasswordPrefixInput}202051",
        "${configTrojanPasswordPrefixInput}202052",
        "${configTrojanPasswordPrefixInput}202053",
        "${configTrojanPasswordPrefixInput}202054",
        "${configTrojanPasswordPrefixInput}202055",
        "${configTrojanPasswordPrefixInput}202056",
        "${configTrojanPasswordPrefixInput}202057",
        "${configTrojanPasswordPrefixInput}202058",
        "${configTrojanPasswordPrefixInput}202059",
        "${configTrojanPasswordPrefixInput}202060",
        "${configTrojanPasswordPrefixInput}202061",
        "${configTrojanPasswordPrefixInput}202062",
        "${configTrojanPasswordPrefixInput}202063",
        "${configTrojanPasswordPrefixInput}202064",
        "${configTrojanPasswordPrefixInput}202065",
        "${configTrojanPasswordPrefixInput}202066",
        "${configTrojanPasswordPrefixInput}202067",
        "${configTrojanPasswordPrefixInput}202068",
        "${configTrojanPasswordPrefixInput}202069",
        "${configTrojanPasswordPrefixInput}202070",
        "${configTrojanPasswordPrefixInput}202071",
        "${configTrojanPasswordPrefixInput}202072",
        "${configTrojanPasswordPrefixInput}202073",
        "${configTrojanPasswordPrefixInput}202074",
        "${configTrojanPasswordPrefixInput}202075",
        "${configTrojanPasswordPrefixInput}202076",
        "${configTrojanPasswordPrefixInput}202077",
        "${configTrojanPasswordPrefixInput}202078",
        "${configTrojanPasswordPrefixInput}202079",
        "${configTrojanPasswordPrefixInput}202080",
        "${configTrojanPasswordPrefixInput}202081",
        "${configTrojanPasswordPrefixInput}202082",
        "${configTrojanPasswordPrefixInput}202083",
        "${configTrojanPasswordPrefixInput}202084",
        "${configTrojanPasswordPrefixInput}202085",
        "${configTrojanPasswordPrefixInput}202086",
        "${configTrojanPasswordPrefixInput}202087",
        "${configTrojanPasswordPrefixInput}202088",
        "${configTrojanPasswordPrefixInput}202089",
        "${configTrojanPasswordPrefixInput}202090",
        "${configTrojanPasswordPrefixInput}202091",
        "${configTrojanPasswordPrefixInput}202092",
        "${configTrojanPasswordPrefixInput}202093",
        "${configTrojanPasswordPrefixInput}202094",
        "${configTrojanPasswordPrefixInput}202095",
        "${configTrojanPasswordPrefixInput}202096",
        "${configTrojanPasswordPrefixInput}202097",
        "${configTrojanPasswordPrefixInput}202098",
        "${configTrojanPasswordPrefixInput}202099"
    ],
    "log_level": 1,
    "log_file": "${configTrojanGoLogFile}",
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "${configSSLCertPath}/fullchain.cer",
        "key": "${configSSLCertPath}/private.key",
        "key_password": "",
	    "prefer_server_cipher": false,
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": "",
        "sni": "${configSSLDomain}",
        "fingerprint": "firefox"
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true
    },
    "websocket": {
        "enabled": ${isTrojanGoSupportWebsocket},
        "path": "/${configTrojanGoWebSocketPath}",
        "host": "${configSSLDomain}"
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": ""
    }
}
EOF

        # Add startup script
        cat > ${osSystemMdPath}trojan-go.service <<-EOF
[Unit]
Description=trojan-go
After=network.target

[Service]
Type=simple
PIDFile=${configTrojanGoPath}/trojan-go.pid
ExecStart=${configTrojanGoPath}/trojan-go -config "${configTrojanGoPath}/server.json"
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
    fi

    ${sudoCmd} chmod +x ${osSystemMdPath}trojan${promptInfoTrojanName}.service
    ${sudoCmd} systemctl daemon-reload
    ${sudoCmd} systemctl start trojan${promptInfoTrojanName}.service
    ${sudoCmd} systemctl enable trojan${promptInfoTrojanName}.service



    # Download and make the command line startup file of the trojan windows client
    rm -rf ${configTrojanBasePath}/trojan-win-cli
    rm -rf ${configTrojanBasePath}/trojan-win-cli-temp
    mkdir -p ${configTrojanBasePath}/trojan-win-cli-temp

    downloadAndUnzip "https://github.com/jinwyp/one_click_script/raw/master/download/trojan-win-cli.zip" "${configTrojanBasePath}" "trojan-win-cli.zip"

    if [ "$isTrojanGo" = "no" ] ; then
        downloadAndUnzip "https://github.com/trojan-gfw/trojan/releases/download/v${versionTrojan}/trojan-${versionTrojan}-win.zip" "${configTrojanBasePath}/trojan-win-cli-temp" "trojan-${versionTrojan}-win.zip"
        mv -f ${configTrojanBasePath}/trojan-win-cli-temp/trojan/trojan.exe ${configTrojanBasePath}/trojan-win-cli/
        mv -f ${configTrojanBasePath}/trojan-win-cli-temp/trojan/VC_redist.x64.exe ${configTrojanBasePath}/trojan-win-cli/
    fi

    if [ "$isTrojanGo" = "yes" ] ; then
        downloadAndUnzip "https://github.com/p4gefau1t/trojan-go/releases/download/v${versionTrojanGo}/trojan-go-windows-amd64.zip" "${configTrojanBasePath}/trojan-win-cli-temp" "trojan-go-windows-amd64.zip"
        mv -f ${configTrojanBasePath}/trojan-win-cli-temp/* ${configTrojanBasePath}/trojan-win-cli/
    fi

    rm -rf ${configTrojanBasePath}/trojan-win-cli-temp
    cp ${configSSLCertPath}/fullchain.cer ${configTrojanBasePath}/trojan-win-cli/fullchain.cer

    cat > ${configTrojanBasePath}/trojan-win-cli/config.json <<-EOF
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": 1080,
    "remote_addr": "${configSSLDomain}",
    "remote_port": 443,
    "password": [
        "${trojanPassword1}"
    ],
    "log_level": 1,
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "fullchain.cer",
        "cipher_tls13":"TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
	    "sni": "",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "curves": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    }
}
EOF

    zip -r ${configWebsiteDownloadPath}/trojan-win-cli.zip ${configTrojanBasePath}/trojan-win-cli/




    # Set up cron timing tasks
    # https://stackoverflow.com/questions/610839/how-can-i-programmatically-create-a-new-cron-job

    # (crontab -l 2>/dev/null | grep -v '^[a-zA-Z]'; echo "15 4 * * 0,1,2,3,4,5,6 systemctl restart trojan.service") | sort - | uniq - | crontab -
    (crontab -l ; echo "10 4 * * 0,1,2,3,4,5,6 systemctl restart trojan${promptInfoTrojanName}.service") | sort - | uniq - | crontab -


	green "======================================================================"
	green "    Trojan${promptInfoTrojanName} Version: ${configTrojanBaseVersion} Successful installation !"

    if [[ ${isInstallNginx} == "true" ]]; then
        green "    The fake site is http://${configSSLDomain}"
	    green "    The static html content of the fake site is placed in the directory ${configWebsitePath}, You can change the content of the website yourself!"
    fi

	red "    Trojan Server-side configuration path ${configTrojanBasePath}/server.json "
	red "    Trojan Access log ${configTrojanLogFile} Or run journalctl -n 50 -u trojan${promptInfoTrojanName}.service Check out!"
	green "    Trojan Stop: systemctl stop trojan${promptInfoTrojanName}.service  Start: systemctl start trojan${promptInfoTrojanName}.service  Restart: systemctl restart trojan${promptInfoTrojanName}.service"
	green "    Trojan The server will automatically restart every day to prevent memory leaks. Run crontab -l Command View timing restart command !"
	green "======================================================================"
	blue  "----------------------------------------"
	yellow "Trojan${promptInfoTrojanName} The configuration information is as follows, please copy and save by yourself, and choose one of the passwords!"
	yellow "server address: ${configSSLDomain}  port: $configV2rayTrojanPort"
	yellow "password1: ${trojanPassword1}"
	yellow "password2: ${trojanPassword2}"
	yellow "password3: ${trojanPassword3}"
	yellow "password4: ${trojanPassword4}"
	yellow "password5: ${trojanPassword5}"
	yellow "password6: ${trojanPassword6}"
	yellow "password7: ${trojanPassword7}"
	yellow "password8: ${trojanPassword8}"
	yellow "password9: ${trojanPassword9}"
	yellow "password10: ${trojanPassword10}"
	yellow "The number of passwords you specify the prefix: from ${configTrojanPasswordPrefixInput}202010 To ${configTrojanPasswordPrefixInput}202099 Can be used"

    if [[ ${isTrojanGoSupportWebsocket} == "true" ]]; then
        yellow "Websocket path The path is: /${configTrojanGoWebSocketPath}"
        # yellow "Websocket obfuscation_password The obfuscated password is: ${trojanPasswordWS}"
        yellow "Websocket Double TLS is: true open"
    fi

	blue  "----------------------------------------"
	green "======================================================================"
	green "Please download the corresponding trojan client:"
	yellow "1 Windows client：http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/v2ray-windows.zip"
	#yellow "  Windows 客户端另一个版本下载：http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/trojan-Qt5-windows.zip"
	yellow "  Windows client cmdline：http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/trojan-win-cli.zip"
	yellow "  Windows The client command line version needs to be used with browser plug-ins, such as switchyomega, etc.! "
    yellow "2 MacOS client：http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/trojan-mac.zip"
    #yellow "  MacOS 客户端Trojan-Qt5下载：http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/trojan-Qt5-mac.zip"
    yellow "3 Android client https://github.com/trojan-gfw/igniter/releases "
    yellow "  Android another client https://github.com/2dust/v2rayNG/releases "
    yellow "  Android client Clash https://github.com/Kr328/ClashForAndroid/releases "
    yellow "4 iOS Client please install Little Rocket https://shadowsockshelp.github.io/ios/ "
    yellow "  iOS Please install another address of Little Rocket https://lueyingpro.github.io/shadowrocket/index.html "
    yellow "  iOS Trouble with installing a small rocket tutorial https://github.com/shadowrocketHelp/help/ "
    green "======================================================================"
	green "Tutorials and other resources:"
	green "访问 https://www.v2rayssr.com/trojan-1.html ‎ 下载 浏览器插件 客户端 及教程"
	green "客户端汇总 https://tlanyan.me/trojan-clients-download ‎ 下载 trojan客户端"
    green "访问 https://westworldss.com/portal/page/download ‎ 下载 客户端 及教程"
	green "======================================================================"
	green "其他 Windows 客户端:"
	green "https://github.com/TheWanderingCoel/Trojan-Qt5/releases (exe为Win客户端, dmg为Mac客户端)"
	green "https://github.com/Qv2ray/Qv2ray/releases (exe为Win客户端, dmg为Mac客户端)"
	green "https://github.com/Dr-Incognito/V2Ray-Desktop/releases (exe为Win客户端, dmg为Mac客户端)"
	green "https://github.com/Fndroid/clash_for_windows_pkg/releases"
	green "======================================================================"
	green "其他 Mac 客户端:"
	green "https://github.com/TheWanderingCoel/Trojan-Qt5/releases (exe为Win客户端, dmg为Mac客户端)"
	green "https://github.com/Qv2ray/Qv2ray/releases (exe为Win客户端, dmg为Mac客户端)"
	green "https://github.com/Dr-Incognito/V2Ray-Desktop/releases (exe为Win客户端, dmg为Mac客户端)"
	green "https://github.com/JimLee1996/TrojanX/releases (exe为Win客户端, dmg为Mac客户端)"
	green "https://github.com/yichengchen/clashX/releases "
	green "======================================================================"
	green "其他 Android 客户端:"
	green "https://github.com/trojan-gfw/igniter/releases "
	green "https://github.com/Kr328/ClashForAndroid/releases "
	green "======================================================================"


    cat >> ${configReadme} <<-EOF

Trojan${promptInfoTrojanName} Version: ${configTrojanBaseVersion} Successful installation !
Trojan${promptInfoTrojanName} Server-side configuration path ${configTrojanBasePath}/server.json
Trojan${promptInfoTrojanName} Stop: systemctl stop trojan${promptInfoTrojanName}.service  Start: systemctl start trojan${promptInfoTrojanName}.service  Restart: systemctl restart trojan${promptInfoTrojanName}.service

Trojan${promptInfoTrojanName}server address: ${configSSLDomain}  port: $configV2rayTrojanPort

password1: ${trojanPassword1}
password2: ${trojanPassword2}
password3: ${trojanPassword3}
password4: ${trojanPassword4}
password5: ${trojanPassword5}
password6: ${trojanPassword6}
password7: ${trojanPassword7}
password8: ${trojanPassword8}
password9: ${trojanPassword9}
password10: ${trojanPassword10}
The number of passwords you specify the prefix: from ${configTrojanPasswordPrefixInput}202010 To ${configTrojanPasswordPrefixInput}202099 Can be used

If trojan-go opens Websocket, then the Websocket path is: /${configTrojanGoWebSocketPath}


EOF
}


function removeTrojan(){

    isTrojanGoInstall

    ${sudoCmd} systemctl stop trojan${promptInfoTrojanName}.service
    ${sudoCmd} systemctl disable trojan${promptInfoTrojanName}.service

    green " ================================================== "
    red " Ready to uninstall the installed trojan${promptInfoTrojanName}"
    green " ================================================== "

    rm -rf ${configTrojanBasePath}
    rm -f ${osSystemMdPath}trojan${promptInfoTrojanName}.service
    rm -f ${configTrojanLogFile}
    rm -f ${configTrojanGoLogFile}

    rm -f ${configReadme}

    crontab -r

    green " ================================================== "
    green "  trojan${promptInfoTrojanName} And nginx uninstallation is complete!"
    green "  crontab Timed tasks are deleted!"
    green " ================================================== "
}


function upgradeTrojan(){

    isTrojanGoInstall

    green " ================================================== "
    green "     Start to upgrade Trojan${promptInfoTrojanName} Version: ${configTrojanBaseVersion}"
    green " ================================================== "

    ${sudoCmd} systemctl stop trojan${promptInfoTrojanName}.service

    mkdir -p ${configDownloadTempPath}/upgrade/trojan${promptInfoTrojanName}

    if [ "$isTrojanGo" = "no" ] ; then
        # https://github.com/trojan-gfw/trojan/releases/download/v1.16.0/trojan-1.16.0-linux-amd64.tar.xz
        downloadAndUnzip "https://github.com/trojan-gfw/trojan/releases/download/v${versionTrojan}/${downloadFilenameTrojan}" "${configDownloadTempPath}/upgrade/trojan" "${downloadFilenameTrojan}"
        mv -f ${configDownloadTempPath}/upgrade/trojan/trojan ${configTrojanPath}
    else
        # https://github.com/p4gefau1t/trojan-go/releases/download/v0.8.1/trojan-go-linux-amd64.zip
        downloadAndUnzip "https://github.com/p4gefau1t/trojan-go/releases/download/v${versionTrojanGo}/${downloadFilenameTrojanGo}" "${configDownloadTempPath}/upgrade/trojan-go" "${downloadFilenameTrojanGo}"
        mv -f ${configDownloadTempPath}/upgrade/trojan-go/trojan-go ${configTrojanGoPath}
    fi

    ${sudoCmd} systemctl start trojan${promptInfoTrojanName}.service

    green " ================================================== "
    green "     update successed Trojan${promptInfoTrojanName} Version: ${configTrojanBaseVersion} !"
    green " ================================================== "

}






function installV2ray(){

    v2rayPassword1=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword2=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword3=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword4=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword5=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword6=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword7=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword8=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword9=$(cat /proc/sys/kernel/random/uuid)
    v2rayPassword10=$(cat /proc/sys/kernel/random/uuid)

    if [ -f "${configV2rayPath}/v2ray" ] || [ -f "/usr/local/bin/v2ray" ] || [ -f "/usr/bin/v2ray" ]; then
        green " =================================================="
        green "  V2ray or Xray has been installed, exit the installation!"
        green " =================================================="
        exit
    fi


    if [[ ( $configV2rayVlessMode == "trojan" ) || ( $configV2rayVlessMode == "vlessonly" ) || ( $configV2rayVlessMode == "vlesstrojan" ) ]] ; then
        promptInfoXrayName="xray"
        isXray="yes"
    else
        read -p "Do you use Xray kernel (default is V2ray kernel)? Please enter[y/N]?" isV2rayOrXrayInput
        isV2rayOrXrayInput=${isV2rayOrXrayInput:-n}

        if [[ $isV2rayOrXrayInput == [Yy] ]]; then
            promptInfoXrayName="xray"
            isXray="yes"
        fi
    fi


    if [[ -n "$configV2rayVlessMode" ]]; then
         configV2rayProtocol="vless"
    else 

        read -p "Whether to use VLESS protocol (default is VMess protocol)? Please enter[y/N]?" isV2rayUseVLessInput
        isV2rayUseVLessInput=${isV2rayUseVLessInput:-n}

        if [[ $isV2rayUseVLessInput == [Yy] ]]; then
            configV2rayProtocol="vless"
        else
            configV2rayProtocol="vmess"
        fi

    fi




    read -p "Do you use IPV6 to unlock the Google verification code? The default is not unlocked, and the unlocking requires wireguard)? Please enter[y/N]?" isV2rayUnlockGoogleInput
    isV2rayUnlockGoogleInput=${isV2rayUnlockGoogleInput:-n}

    V2rayUnlockText=""

    if [[ $isV2rayUnlockGoogleInput == [Yy] ]]; then
        V2rayUnlockText="\"geosite:google\""
    fi


    read -p "Do you use IPV6 to unlock Netflix by default, it is not unlocked by default, and you need to cooperate with wireguard to unlock it? Please enter[y/N]?" isV2rayUnlockNetflixInput
    isV2rayUnlockNetflixInput=${isV2rayUnlockNetflixInput:-n}
    
    if [[ $isV2rayUnlockNetflixInput == [Yy] ]]; then
        V2rayUnlockText="\"geosite:netflix\""
    fi

    if [[ $isV2rayUnlockGoogleInput == [Yy] && $isV2rayUnlockNetflixInput == [Yy] ]]; then
        V2rayUnlockText="\"geosite:netflix\", \"geosite:google\""
    fi



    if [ "$isXray" = "no" ] ; then
        getTrojanAndV2rayVersion "v2ray"
        green " =================================================="
        green "    start installation V2ray Version: ${versionV2ray} !"
        green " =================================================="
        promptInfoXrayInstall="V2ray"
        promptInfoXrayVersion=${versionV2ray}
    else
        getTrojanAndV2rayVersion "xray"
        green " =================================================="
        green "    start installation Xray Version: ${versionXray} !"
        green " =================================================="
        promptInfoXrayInstall="Xray"
        promptInfoXrayVersion=${versionXray}
    fi



    mkdir -p ${configV2rayPath}
    cd ${configV2rayPath}
    rm -rf ${configV2rayPath}/*


    if [ "$isXray" = "no" ] ; then
        # https://github.com/v2fly/v2ray-core/releases/download/v4.27.5/v2ray-linux-64.zip
        downloadAndUnzip "https://github.com/v2fly/v2ray-core/releases/download/v${versionV2ray}/${downloadFilenameV2ray}" "${configV2rayPath}" "${downloadFilenameV2ray}"

    else
        downloadAndUnzip "https://github.com/XTLS/Xray-core/releases/download/v${versionXray}/${downloadFilenameXray}" "${configV2rayPath}" "${downloadFilenameXray}"
    fi


    # Add v2ray server configuration

    trojanPassword1=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword2=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword3=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword4=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword5=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword6=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword7=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword8=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword9=$(cat /dev/urandom | head -1 | md5sum | head -c 10)
    trojanPassword10=$(cat /dev/urandom | head -1 | md5sum | head -c 10)

    read -r -d '' v2rayConfigUserpasswordTrojanInput << EOM
                    {
                        "password": "${trojanPassword1}",
                        "level": 0,
                        "email": "password111@gmail.com"
                    },
                    {
                        "password": "${trojanPassword2}",
                        "level": 0,
                        "email": "password112@gmail.com"
                    },
                    {
                        "password": "${trojanPassword3}",
                        "level": 0,
                        "email": "password113@gmail.com"
                    },
                    {
                        "password": "${trojanPassword4}",
                        "level": 0,
                        "email": "password114@gmail.com"
                    },
                    {
                        "password": "${trojanPassword5}",
                        "level": 0,
                        "email": "password115@gmail.com"
                    },
                    {
                        "password": "${trojanPassword6}",
                        "level": 0,
                        "email": "password116@gmail.com"
                    },
                    {
                        "password": "${trojanPassword7}",
                        "level": 0,
                        "email": "password117@gmail.com"
                    },
                    {
                        "password": "${trojanPassword8}",
                        "level": 0,
                        "email": "password118@gmail.com"
                    },
                    {
                        "password": "${trojanPassword9}",
                        "level": 0,
                        "email": "password119@gmail.com"
                    },
                    {
                        "password": "${trojanPassword10}",
                        "level": 0,
                        "email": "password120@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202000",
                        "level": 0,
                        "email": "password200@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202001",
                        "level": 0,
                        "email": "password201@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202002",
                        "level": 0,
                        "email": "password202@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202003",
                        "level": 0,
                        "email": "password203@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202004",
                        "level": 0,
                        "email": "password204@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202005",
                        "level": 0,
                        "email": "password205@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202006",
                        "level": 0,
                        "email": "password206@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202007",
                        "level": 0,
                        "email": "password207@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202008",
                        "level": 0,
                        "email": "password208@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202009",
                        "level": 0,
                        "email": "password209@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202010",
                        "level": 0,
                        "email": "password210@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202011",
                        "level": 0,
                        "email": "password211@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202012",
                        "level": 0,
                        "email": "password212@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202013",
                        "level": 0,
                        "email": "password213@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202014",
                        "level": 0,
                        "email": "password214@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202015",
                        "level": 0,
                        "email": "password215@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202016",
                        "level": 0,
                        "email": "password216@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202017",
                        "level": 0,
                        "email": "password217@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202018",
                        "level": 0,
                        "email": "password218@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202019",
                        "level": 0,
                        "email": "password219@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202020",
                        "level": 0,
                        "email": "password220@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202021",
                        "level": 0,
                        "email": "password221@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202022",
                        "level": 0,
                        "email": "password222@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202023",
                        "level": 0,
                        "email": "password223@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202024",
                        "level": 0,
                        "email": "password224@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202025",
                        "level": 0,
                        "email": "password225@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202026",
                        "level": 0,
                        "email": "password226@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202027",
                        "level": 0,
                        "email": "password227@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202028",
                        "level": 0,
                        "email": "password228@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202029",
                        "level": 0,
                        "email": "password229@gmail.com"
                    },
                    {
                        "password": "${configTrojanPasswordPrefixInput}202030",
                        "level": 0,
                        "email": "password230@gmail.com"
                    }
EOM


    read -r -d '' v2rayConfigUserpasswordInput << EOM
                    {
                        "id": "${v2rayPassword1}",
                        "level": 0,
                        "email": "password11@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword2}",
                        "level": 0,
                        "email": "password12@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword3}",
                        "level": 0,
                        "email": "password13@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword4}",
                        "level": 0,
                        "email": "password14@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword5}",
                        "level": 0,
                        "email": "password15@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword6}",
                        "level": 0,
                        "email": "password16@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword7}",
                        "level": 0,
                        "email": "password17@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword8}",
                        "level": 0,
                        "email": "password18@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword9}",
                        "level": 0,
                        "email": "password19@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword10}",
                        "level": 0,
                        "email": "password20@gmail.com"
                    }
EOM

    read -r -d '' v2rayConfigUserpasswordDirectInput << EOM
                    {
                        "id": "${v2rayPassword1}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password11@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword2}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password12@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword3}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password13@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword4}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password14@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword5}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password15@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword6}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password16@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword7}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password17@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword8}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password18@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword9}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password19@gmail.com"
                    },
                    {
                        "id": "${v2rayPassword10}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": "password20@gmail.com"
                    }
EOM


    if [[ $isV2rayUnlockGoogleInput == [Nn] && $isV2rayUnlockNetflixInput == [Nn] ]]; then
        
        read -r -d '' v2rayConfigOutboundInput << EOM
    "outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {}
        },
        {
            "tag": "blocked",
            "protocol": "blackhole",
            "settings": {}
        }
    ]
EOM
    else

        read -r -d '' v2rayConfigOutboundInput << EOM
    "outbounds": [
        {
            "tag":"IP4_out",
            "protocol": "freedom",
            "settings": {}
        },
        {
            "tag":"IP6_out",
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "UseIPv6" 
            }
        }
    ],    
    "routing": {
        "rules": [
            {
                "type": "field",
                "outboundTag": "IP6_out",
                "domain": [${V2rayUnlockText}] 
            },
            {
                "type": "field",
                "outboundTag": "IP4_out",
                "network": "udp,tcp"
            }
        ]
    }
EOM
        
    fi




    read -r -d '' v2rayConfigLogInput << EOM
    "log" : {
        "access": "${configV2rayAccessLogFilePath}",
        "error": "${configV2rayErrorLogFilePath}",
        "loglevel": "warning"
    },
EOM




    if [[ -z "$configV2rayVlessMode" ]]; then
        cat > ${configV2rayPath}/config.json <<-EOF
{
    ${v2rayConfigLogInput}
    "inbounds": [
        {
            "port": ${configV2rayPort},
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/${configV2rayWebSocketPath}"
                }
            }
        }
    ],
    ${v2rayConfigOutboundInput}
}
EOF
    fi


    if [[ "$configV2rayVlessMode" == "vlessws" ]]; then
        cat > ${configV2rayPath}/config.json <<-EOF
{
    ${v2rayConfigLogInput}
    "inbounds": [
        {
            "port": 443,
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": 80
                    },
                    {
                        "path": "/${configV2rayWebSocketPath}",
                        "dest": ${configV2rayPort},
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "${configSSLCertPath}/fullchain.cer",
                            "keyFile": "${configSSLCertPath}/private.key"
                        }
                    ]
                }
            }
        },
        {
            "port": ${configV2rayPort},
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "acceptProxyProtocol": true,
                    "path": "/${configV2rayWebSocketPath}" 
                }
            }
        }
    ],
    ${v2rayConfigOutboundInput}
}
EOF
    fi


    if [[ "$configV2rayVlessMode" == "vmessws" ]]; then
        cat > ${configV2rayPath}/config.json <<-EOF
{
    ${v2rayConfigLogInput}
    "inbounds": [
        {
            "port": 443,
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": 80
                    },
                    {
                        "path": "/${configV2rayWebSocketPath}",
                        "dest": ${configV2rayPort},
                        "xver": 1
                    },
                    {
                        "path": "/tcp${configV2rayWebSocketPath}",
                        "dest": ${configV2rayVmessTCPPort},
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "${configSSLCertPath}/fullchain.cer",
                            "keyFile": "${configSSLCertPath}/private.key"
                        }
                    ]
                }
            }
        },
        {
            "port": ${configV2rayPort},
            "listen": "127.0.0.1",
            "protocol": "vmess",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "path": "/${configV2rayWebSocketPath}" 
                }
            }
        },
        {
            "port": ${configV2rayVmessTCPPort},
            "listen": "127.0.0.1",
            "protocol": "vmess",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "tcpSettings": {
                    "acceptProxyProtocol": true,
                    "header": {
                        "type": "http",
                        "request": {
                            "path": [
                                "/tcp${configV2rayWebSocketPath}"
                            ]
                        }
                    }
                }
            }
        }
    ],
    ${v2rayConfigOutboundInput}
}
EOF
    fi



    if [[  $configV2rayVlessMode == "vlesstrojan" ]]; then
            cat > ${configV2rayPath}/config.json <<-EOF
{
    ${v2rayConfigLogInput}
    "inbounds": [
        {
            "port": 443,
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordDirectInput}
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": ${configV2rayTrojanPort},
                        "xver": 1
                    },
                    {
                        "path": "/${configV2rayWebSocketPath}",
                        "dest": ${configV2rayPort},
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "${configSSLCertPath}/fullchain.cer",
                            "keyFile": "${configSSLCertPath}/private.key"
                        }
                    ]
                }
            }
        },
        {
            "port": ${configV2rayTrojanPort},
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordTrojanInput}
                ],
                "fallbacks": [
                    {
                        "dest": 80 
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "tcpSettings": {
                    "acceptProxyProtocol": true
                }
            }
        },
        {
            "port": ${configV2rayPort},
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "acceptProxyProtocol": true,
                    "path": "/${configV2rayWebSocketPath}" 
                }
            }
        }
    ],
    ${v2rayConfigOutboundInput}
}
EOF
    fi


    if [[  $configV2rayVlessMode == "vlessonly" ]]; then
            cat > ${configV2rayPath}/config.json <<-EOF
{
    ${v2rayConfigLogInput}
    "inbounds": [
        {
            "port": 443,
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordDirectInput}
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": 80
                    },
                    {
                        "path": "/${configV2rayWebSocketPath}",
                        "dest": ${configV2rayPort},
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "${configSSLCertPath}/fullchain.cer",
                            "keyFile": "${configSSLCertPath}/private.key"
                        }
                    ]
                }
            }
        },
        {
            "port": ${configV2rayPort},
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "acceptProxyProtocol": true,
                    "path": "/${configV2rayWebSocketPath}" 
                }
            }
        }
    ],
    ${v2rayConfigOutboundInput}
}
EOF
    fi


    if [[ $configV2rayVlessMode == "trojan" ]]; then

            cat > ${configV2rayPath}/config.json <<-EOF
{
    ${v2rayConfigLogInput}
    "inbounds": [
        {
            "port": 443,
            "protocol": "${configV2rayProtocol}",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordDirectInput}
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": ${configV2rayTrojanPort},
                        "xver": 1
                    },
                    {
                        "path": "/${configTrojanGoWebSocketPath}",
                        "dest": ${configV2rayTrojanPort},
                        "xver": 1
                    },
                    {
                        "path": "/${configV2rayWebSocketPath}",
                        "dest": ${configV2rayPort},
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "${configSSLCertPath}/fullchain.cer",
                            "keyFile": "${configSSLCertPath}/private.key"
                        }
                    ]
                }
            }
        },
        {
            "port": ${configV2rayPort},
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [
                    ${v2rayConfigUserpasswordInput}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "acceptProxyProtocol": true,
                    "path": "/${configV2rayWebSocketPath}" 
                }
            }
        }
    ],
    ${v2rayConfigOutboundInput}
}
EOF

    fi





    # Add V2ray startup script
    if [ "$isXray" = "no" ] ; then
    
        cat > ${osSystemMdPath}v2ray.service <<-EOF
[Unit]
Description=V2Ray
Documentation=https://www.v2fly.org/
After=network.target nss-lookup.target

[Service]
Type=simple
# This service runs as root. You may consider to run it as another user for security concerns.
# By uncommenting User=nobody and commenting out User=root, the service will run as user nobody.
# More discussion at https://github.com/v2ray/v2ray-core/issues/1011
User=root
#User=nobody
#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=${configV2rayPath}/v2ray -config ${configV2rayPath}/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
    else
        cat > ${osSystemMdPath}xray.service <<-EOF
[Unit]
Description=Xray
Documentation=https://www.v2fly.org/
After=network.target nss-lookup.target

[Service]
Type=simple
# This service runs as root. You may consider to run it as another user for security concerns.
# By uncommenting User=nobody and commenting out User=root, the service will run as user nobody.
# More discussion at https://github.com/v2ray/v2ray-core/issues/1011
User=root
#User=nobody
#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=${configV2rayPath}/xray run -config ${configV2rayPath}/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
    fi

    ${sudoCmd} chmod +x ${configV2rayPath}/${promptInfoXrayName}
    ${sudoCmd} chmod +x ${osSystemMdPath}${promptInfoXrayName}.service
    ${sudoCmd} systemctl daemon-reload
    ${sudoCmd} systemctl restart ${promptInfoXrayName}.service
    ${sudoCmd} systemctl enable ${promptInfoXrayName}.service




    # Add client configuration instructions
    if [[ ${isInstallNginx} == "true" ]]; then
        configV2rayPortShowInfo=443
        configV2rayIsTlsShowInfo="tls"
    else
        configV2rayIsTlsShowInfo="none"
    fi

    if [[ -n "$configV2rayVlessMode" ]]; then
        configV2rayPortShowInfo=443
        configV2rayIsTlsShowInfo="tls"
    fi




    cat > ${configV2rayPath}/clientConfig.json <<-EOF
=========== ${promptInfoXrayInstall}Client configuration parameters =============
{
    protocol: ${configV2rayProtocol},
    address: ${configSSLDomain},
    port: ${configV2rayPortShowInfo},
    uuid: ${v2rayPassword1},
    Extra id: 0,  // AlterID If it is a Vless protocol, this item is not needed
    Encryption: aes-128-gcm,  // If it is a Vless protocol, it is none
    Transfer Protocol: ws,
    WS path:/${configV2rayWebSocketPath},
    Underlying transport protocol:${configV2rayIsTlsShowInfo},
    Alias: give yourself any name
}
EOF



if [[ "$configV2rayVlessMode" == "vmessws" ]]; then
    cat > ${configV2rayPath}/clientConfig.json <<-EOF
When 17selected Only install v2ray VLess runs on port443 (VLess-TCP-TLS) + (VMess-TCP-TLS) + (VMess-WS-TLS) Support CDN, donot install nginx
=========== ${promptInfoXrayInstall}Client VLess-TCP-TLS configuration parameters =============
{
    protocol: VLess,
    address: ${configSSLDomain},
    port: ${configV2rayPortShowInfo},
    uuid: ${v2rayPassword1},
    Extra id: 0,  // AlterID If it is a Vless protocol, this item is not needed
    Encryption: none,  // If it is a Vless protocol, it is none
    Transfer Protocol: tcp ,
    WS path: none,
    Underlying transmission:tls,
    Alias: give yourself any name
}

=========== ${promptInfoXrayInstall}Client VMess-WS-TLS configuration parameters support CDN =============
{
    protocol: VMess,
    address: ${configSSLDomain},
    port: ${configV2rayPortShowInfo},
    uuid: ${v2rayPassword1},
    Extra id: 0,  // AlterID If it is a Vless protocol, this item is not needed
    Encryption: none,  // If it is a Vless protocol, it is none
    Transfer Protocol: ws,
    WS path:/${configV2rayWebSocketPath},
    Underlying transmission:tls,
    Alias: give yourself any name
}

=========== ${promptInfoXrayInstall}Client VMess-TCP-TLS configuration parameters Support CDN =============
{
    protocol: VMess,
    address: ${configSSLDomain},
    port: ${configV2rayPortShowInfo},
    uuid: ${v2rayPassword1},
    Extra id: 0,  // AlterID If it is a Vless protocol, this item is not needed
    Encryption: none,  // If it is a Vless protocol, it is none
    Transfer Protocol: tcp,
    path:/tcp${configV2rayWebSocketPath},
    Underlying transmission:tls,
    Alias: give yourself any name
}
EOF
fi


if [[ "$configV2rayVlessMode" == "vlessws" ]]; then
    cat > ${configV2rayPath}/clientConfig.json <<-EOF
When you select16. Only install v2ray VLess runs on port443 (VLess-TCP-TLS) + (VLess-WS-TLS) support CDN, donot install nginx
=========== ${promptInfoXrayInstall}Client VLess-TCP-TLS configuration parameters =============
{
    protocol: VLess,
    address: ${configSSLDomain},
    port: ${configV2rayPortShowInfo},
    uuid: ${v2rayPassword1},
    Extra id: 0,  // AlterID If it is a Vless protocol, this item is not needed
    Flow control:  // Selected16 is empty
    Encryption: none,  // // If it is a Vless protocol, it is none
    Transfer Protocol: tcp ,
    WS path: none,
    Underlying transport protocol:tls,   
    Alias: give yourself any name
}

=========== ${promptInfoXrayInstall}Client VLess-WS-TLS configuration parameters Support CDN =============
{
    protocol: VLess,
    address: ${configSSLDomain},
    port: ${configV2rayPortShowInfo},
    uuid: ${v2rayPassword1},
    Extra id: 0,  // AlterID If it is a Vless protocol, this item is not needed
    Flow control:  // Selected16 is empty
    Encryption: none,  // // If it is a Vless protocol, it is none
    Transfer Protocol: ws,
    WS path:/${configV2rayWebSocketPath},
    Underlying transmission:tls,     
    Alias: give yourself any name
}
EOF
fi


if [[ "$configV2rayVlessMode" == "vlessonly" ]] || [[ "$configV2rayVlessMode" == "trojan" ]]; then
    cat > ${configV2rayPath}/clientConfig.json <<-EOF
=========== ${promptInfoXrayInstall}Client VLess-TCP-TLS configuration parameters =============
{
    protocol: VLess,
    address: ${configSSLDomain},
    port: ${configV2rayPortShowInfo},
    uuid: ${v2rayPassword1},
    Extra id: 0,  // AlterID If it is a Vless protocol, this item is not needed
    Flow control: xtls-rprx-direct
    Encryption: none,  // // If it is a Vless protocol, it is none
    Transfer Protocol: tcp ,
    WS path: none,
    Underlying transport protocol:xtls, 
    Alias: give yourself any name
}

=========== ${promptInfoXrayInstall}Client VLess-WS-TLS configuration parameters Support CDN =============
{
    protocol: VLess,
    address: ${configSSLDomain},
    port: ${configV2rayPortShowInfo},
    uuid: ${v2rayPassword1},
    Extra id: 0,  // AlterID If it is a Vless protocol, this item is not needed
    Flow control: xtls-rprx-direct // 16is selected as empty,20-23is selected as xtls-rprx-direct
    Encryption: none,  // // If it is a Vless protocol, it is none
    Transfer Protocol: ws,
    WS path:/${configV2rayWebSocketPath},
    Underlying transmission:tls,     
    Alias: give yourself any name
}
EOF
fi

if [[ "$configV2rayVlessMode" == "vlesstrojan" ]]; then
    cat > ${configV2rayPath}/clientConfig.json <<-EOF
=========== ${promptInfoXrayInstall}Client VLess-TCP-TLS configuration parameters =============
{
    protocol: VLess,
    address: ${configSSLDomain},
    port: ${configV2rayPortShowInfo},
    uuid: ${v2rayPassword1},
    Extra id: 0,  // AlterID If it is a Vless protocol, this item is not needed
    Flow control: xtls-rprx-direct
    Encryption: none,  // // If it is a Vless protocol, it is none
    Transfer Protocol: tcp ,
    WS path: none,
    Underlying transport protocol:xtls, 
    Alias: give yourself any name
}

=========== ${promptInfoXrayInstall}Client VLess-WS-TLS configuration parameters Support CDN =============
{
    protocol: VLess,
    address: ${configSSLDomain},
    port: ${configV2rayPortShowInfo},
    uuid: ${v2rayPassword1},
    Extra id: 0,  // AlterID If it is a Vless protocol, this item is not needed
    Flow control: xtls-rprx-direct // choose16 to be empty, choose20-23 to be xtls-rprx-direct
    Encryption: none,  // // If it is a Vless protocol, it is none
    Transfer Protocol: ws,
    WS path:/${configV2rayWebSocketPath},
    Underlying transmission:tls,     
    Alias: give yourself any name
}


Trojan${promptInfoTrojanName}server address: ${configSSLDomain}  port: $configV2rayTrojanPort

password1: ${trojanPassword1}
password2: ${trojanPassword2}
password3: ${trojanPassword3}
password4: ${trojanPassword4}
password5: ${trojanPassword5}
password6: ${trojanPassword6}
password7: ${trojanPassword7}
password8: ${trojanPassword8}
password9: ${trojanPassword9}
password10: ${trojanPassword10}
The number of passwords you specify the prefix: from ${configTrojanPasswordPrefixInput}202010 TO ${configTrojanPasswordPrefixInput}202030 Can be used

EOF
fi





    # Set up cron timing tasks
    # https://stackoverflow.com/questions/610839/how-can-i-programmatically-create-a-new-cron-job

    (crontab -l ; echo "20 4 * * 0,1,2,3,4,5,6 systemctl restart ${promptInfoXrayName}.service") | sort - | uniq - | crontab -


    green "======================================================================"
    green "    ${promptInfoXrayInstall} Version: ${promptInfoXrayVersion} Successful installation !"

    if [[ ${isInstallNginx} == "true" ]]; then
        green "    The fake site is https://${configSSLDomain}!"
    fi
	
	red "    ${promptInfoXrayInstall} Server-side configuration path ${configV2rayPath}/config.json !"
	red "    ${promptInfoXrayInstall} Access log ${configV2rayAccessLogFilePath} !"
	red "    ${promptInfoXrayInstall} Error log ${configV2rayErrorLogFilePath} ! Or run journalctl -n 50 -u ${promptInfoXrayName}.service View !"
	green "    ${promptInfoXrayInstall} Stop: systemctl stop ${promptInfoXrayName}.service  Start: systemctl start ${promptInfoXrayName}.service  Restart: systemctl restart ${promptInfoXrayName}.service"
	# green "    caddy 停止命令: systemctl stop caddy.service  启动命令: systemctl start caddy.service  重启命令: systemctl restart caddy.service"
	green "    ${promptInfoXrayInstall} The server will automatically restart every day to prevent memory leaks. run crontab -l Command View the timing restart command!"
	green "======================================================================"
	echo ""
	yellow "${promptInfoXrayInstall} The configuration information is as follows, please copy and save it yourself, choose one of the passwords (password is user ID or UUID) !!"
	yellow "server address: ${configSSLDomain}  port: ${configV2rayPortShowInfo}"
	yellow "User ID or password 1: ${v2rayPassword1}"
	yellow "User ID or password 2: ${v2rayPassword2}"
	yellow "User ID or password 3: ${v2rayPassword3}"
	yellow "User ID or password 4: ${v2rayPassword4}"
	yellow "User ID or password 5: ${v2rayPassword5}"
	yellow "User ID or password 6: ${v2rayPassword6}"
	yellow "User ID or password 7: ${v2rayPassword7}"
	yellow "User ID or password 8: ${v2rayPassword8}"
	yellow "User ID or password 9: ${v2rayPassword9}"
	yellow "User ID or password 10: ${v2rayPassword10}"
    echo ""
	cat "${configV2rayPath}/clientConfig.json"
	echo ""
    green "======================================================================"
    green "Please download the corresponding ${promptInfoXrayName} Client:"
    yellow "1 Windows Client V2rayN download：http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/v2ray-windows.zip"
    yellow "2 MacOS Client Downloads：http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/v2ray-mac.zip"
    yellow "3 Android Client Downloads https://github.com/2dust/v2rayNG/releases"
    #yellow "3 Android 客户端下载 http://${configSSLDomain}/download/${configTrojanWindowsCliPrefixPath}/v2ray-android.zip"
    yellow "4 iOS Client please install Little Rocket https://shadowsockshelp.github.io/ios/ "
    yellow "  iOS Please install another address of Little Rocket https://lueyingpro.github.io/shadowrocket/index.html "
    yellow "  iOS Trouble with installing a small rocket tutorial https://github.com/shadowrocketHelp/help/ "
    yellow "See other client programs https://www.v2fly.org/awesome/tools.html "
    green "======================================================================"

    cat >> ${configReadme} <<-EOF

${promptInfoXrayInstall} Version: ${promptInfoXrayVersion} Successful installation! 
${promptInfoXrayInstall} Server-side configuration path ${configV2rayPath}/config.json 
${promptInfoXrayInstall} Access log ${configV2rayAccessLogFilePath} , V2ray Error log ${configV2rayErrorLogFilePath}
${promptInfoXrayInstall} Stop: systemctl stop ${promptInfoXrayName}.service  Start: systemctl start ${promptInfoXrayName}.service  Restart: systemctl restart ${promptInfoXrayName}.service

${promptInfoXrayInstall} The configuration information is as follows, please copy and save by yourself, choose one of the passwords (password is user ID or UUID)!
server address: ${configSSLDomain}  
port: ${configV2rayPortShowInfo}"
User ID or password1: ${v2rayPassword1}"
User ID or password2: ${v2rayPassword2}"
User ID or password3: ${v2rayPassword3}"
User ID or password4: ${v2rayPassword4}"
User ID or password5: ${v2rayPassword5}"
User ID or password6: ${v2rayPassword6}"
User ID or password7: ${v2rayPassword7}"
User ID or password8: ${v2rayPassword8}"
User ID or password9: ${v2rayPassword9}"
User ID or password10: ${v2rayPassword10}"


EOF

    cat "${configV2rayPath}/clientConfig.json" >> ${configReadme}
}
    

function removeV2ray(){
    if [ -f "${configV2rayPath}/xray" ]; then
        promptInfoXrayName="xray"
        isXray="yes"
    fi

    green " ================================================== "
    red " Ready to uninstall installed ${promptInfoXrayName} "
    green " ================================================== "

    ${sudoCmd} systemctl stop ${promptInfoXrayName}.service
    ${sudoCmd} systemctl disable ${promptInfoXrayName}.service


    rm -rf ${configV2rayPath}
    rm -f ${osSystemMdPath}${promptInfoXrayName}.service
    rm -f ${configV2rayAccessLogFilePath}
    rm -f ${configV2rayErrorLogFilePath}

    green " ================================================== "
    green "  ${promptInfoXrayName} Uninstall complete !"
    green " ================================================== "
}


function upgradeV2ray(){
    if [ -f "${configV2rayPath}/xray" ]; then
        promptInfoXrayName="xray"
        isXray="yes"
    fi

    if [ "$isXray" = "no" ] ; then
        getTrojanAndV2rayVersion "v2ray"
        green " =================================================="
        green "       Start to upgrade V2ray Version: ${versionV2ray} !"
        green " =================================================="
    else
        getTrojanAndV2rayVersion "xray"
        green " =================================================="
        green "       Start to upgrade Xray Version: ${versionXray} !"
        green " =================================================="
    fi



    ${sudoCmd} systemctl stop ${promptInfoXrayName}.service

    mkdir -p ${configDownloadTempPath}/upgrade/${promptInfoXrayName}

    if [ "$isXray" = "no" ] ; then
        downloadAndUnzip "https://github.com/v2fly/v2ray-core/releases/download/v${versionV2ray}/${downloadFilenameV2ray}" "${configDownloadTempPath}/upgrade/${promptInfoXrayName}" "${downloadFilenameV2ray}"
        mv -f ${configDownloadTempPath}/upgrade/${promptInfoXrayName}/v2ctl ${configV2rayPath}
    else
        downloadAndUnzip "https://github.com/XTLS/Xray-core/releases/download/v${versionXray}/${downloadFilenameXray}" "${configDownloadTempPath}/upgrade/${promptInfoXrayName}" "${downloadFilenameXray}"
    fi

    mv -f ${configDownloadTempPath}/upgrade/${promptInfoXrayName}/${promptInfoXrayName} ${configV2rayPath}
    mv -f ${configDownloadTempPath}/upgrade/${promptInfoXrayName}/geoip.dat ${configV2rayPath}
    mv -f ${configDownloadTempPath}/upgrade/${promptInfoXrayName}/geosite.dat ${configV2rayPath}

    ${sudoCmd} chmod +x ${configV2rayPath}/${promptInfoXrayName}
    ${sudoCmd} systemctl start ${promptInfoXrayName}.service


    if [ "$isXray" = "no" ] ; then
        green " ================================================== "
        green "     update successed V2ray Version: ${versionV2ray} !"
        green " ================================================== "
    else
        getTrojanAndV2rayVersion "xray"
        green " =================================================="
        green "     update successed Xray Version: ${versionXray} !"
        green " =================================================="
    fi
}







function installTrojanWeb(){
    # wget -O trojan-web_install.sh -N --no-check-certificate "https://raw.githubusercontent.com/Jrohy/trojan/master/install.sh" && chmod +x trojan-web_install.sh && ./trojan-web_install.sh


    if [ -f "${configTrojanWebPath}/trojan-web" ] ; then
        green " =================================================="
        green "  The Trojan-web visual management panel has been installed, exit the installation!"
        green " =================================================="
        exit
    fi

    stopServiceNginx
    testLinuxPortUsage
    installPackage

    green " ================================================== "
    yellow " Please enter the domain name bound to this VPS such as www.xxx.com: (Please close CDN and install after this step)"
    green " ================================================== "

    read configSSLDomain
    if compareRealIpWithLocalIp "${configSSLDomain}" ; then

        getTrojanAndV2rayVersion "trojan-web"
        green " =================================================="
        green "   Start to install the Trojan-web visual management panel: ${versionTrojanWeb} !"
        green " =================================================="

        mkdir -p ${configTrojanWebPath}
        wget -O ${configTrojanWebPath}/trojan-web --no-check-certificate "https://github.com/Jrohy/trojan/releases/download/v${versionTrojanWeb}/${downloadFilenameTrojanWeb}"
        chmod +x ${configTrojanWebPath}/trojan-web

        # Add startup script
        cat > ${osSystemMdPath}trojan-web.service <<-EOF
[Unit]
Description=trojan-web
Documentation=https://github.com/Jrohy/trojan
After=network.target network-online.target nss-lookup.target mysql.service mariadb.service mysqld.service docker.service

[Service]
Type=simple
StandardError=journal
ExecStart=${configTrojanWebPath}/trojan-web web -p ${configTrojanWebPort}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF

        ${sudoCmd} systemctl daemon-reload
        ${sudoCmd} systemctl restart trojan-web.service
        ${sudoCmd} systemctl enable trojan-web.service

        green " =================================================="
        green " Trojan-web Visual management panel: ${versionTrojanWeb} Successful installation!"
        green " Trojan visual management panel address https://${configSSLDomain}/${configTrojanWebNginxPath}"
        green " Start running command ${configTrojanWebPath}/trojan-web Make initial settings."
        green " =================================================="



        ${configTrojanWebPath}/trojan-web

        installWebServerNginx "trojan-web"

        # Command completion environment variables
        echo "export PATH=$PATH:${configTrojanWebPath}" >> ${HOME}/.${osSystemShell}rc

        # (crontab -l ; echo '25 0 * * * "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" > /dev/null') | sort - | uniq - | crontab -
        (crontab -l ; echo "30 4 * * 0,1,2,3,4,5,6 systemctl restart trojan-web.service") | sort - | uniq - | crontab -

    else
        exit
    fi
}

function removeTrojanWeb(){
    # wget -O trojan-web_install.sh -N --no-check-certificate "https://raw.githubusercontent.com/Jrohy/trojan/master/install.sh" && chmod +x trojan-web_install.sh && ./trojan-web_install.sh --remove

    green " ================================================== "
    red " Ready to uninstall installed Trojan-web "
    green " ================================================== "

    ${sudoCmd} systemctl stop trojan.service
    ${sudoCmd} systemctl stop trojan-web.service
    ${sudoCmd} systemctl disable trojan-web.service

    # Remove trojan web management program and database leveldb file
    # rm -f /usr/local/bin/trojan
    rm -rf ${configTrojanWebPath}
    rm -f ${osSystemMdPath}trojan-web.service
    rm -rf /var/lib/trojan-manager

    # Remove trojan
    rm -rf /usr/bin/trojan
    rm -rf /usr/local/etc/trojan
    rm -f ${osSystemMdPath}trojan.service

    # Remove trojan's dedicated database
    docker rm -f trojan-mysql
    docker rm -f trojan-mariadb
    rm -rf /home/mysql
    rm -rf /home/mariadb


    # Remove environment variables
    sed -i '/trojan/d' ${HOME}/.${osSystemShell}rc

    crontab -r

    green " ================================================== "
    green "  Trojan-web Uninstall complete !"
    green " ================================================== "
}

function upgradeTrojanWeb(){
    getTrojanAndV2rayVersion "trojan-web"
    green " =================================================="
    green "    Start to upgrade the Trojan-web visual management panel: ${versionTrojanWeb} !"
    green " =================================================="

    ${sudoCmd} systemctl stop trojan-web.service

    mkdir -p ${configDownloadTempPath}/upgrade/trojan-web

    wget -O ${configDownloadTempPath}/upgrade/trojan-web/trojan-web "https://github.com/Jrohy/trojan/releases/download/v${versionTrojanWeb}/${downloadFilenameTrojanWeb}"
    mv -f ${configDownloadTempPath}/upgrade/trojan-web/trojan-web ${configTrojanWebPath}
    chmod +x ${configTrojanWebPath}/trojan-web

    ${sudoCmd} systemctl start trojan-web.service
    ${sudoCmd} systemctl restart trojan.service


    green " ================================================== "
    green "     Successfully upgraded Trojan-web visual management panel: ${versionTrojanWeb} !"
    green " ================================================== "
}
function runTrojanWebSSL(){
    ${sudoCmd} systemctl stop trojan-web.service
    ${sudoCmd} systemctl stop nginx.service
    ${sudoCmd} systemctl stop trojan.service
    ${configTrojanWebPath}/trojan-web tls
    ${sudoCmd} systemctl start trojan-web.service
    ${sudoCmd} systemctl start nginx.service
    ${sudoCmd} systemctl restart trojan.service
}
function runTrojanWebLog(){
    ${configTrojanWebPath}/trojan-web
}


function installV2rayUI(){

    stopServiceNginx
    testLinuxPortUsage
    installPackage

    green " ================================================== "
    yellow " Please enter the domain name bound to this VPS such as www.xxx.com: (Please close CDN and install after this step)"
    green " ================================================== "

    read configSSLDomain
    if compareRealIpWithLocalIp "${configSSLDomain}" ; then

        green " =================================================="
        green "    Start to install V2ray-UI visual management panel !"
        green " =================================================="

        wget -O v2_ui_install.sh -N --no-check-certificate "https://raw.githubusercontent.com/sprov065/v2-ui/master/install.sh" && chmod +x v2_ui_install.sh && ./v2_ui_install.sh

        green " V2ray-UI Visual management panel address http://${configSSLDomain}:65432"
        green " Please make sure that port65432 has been released, forexample, check whether port65432 is open on Linux firewall or VPS firewall"
        green " V2ray-UI visual management panel The default administrator user admin password is admin, to ensure security, please change the default password as soon as possible after loggingin "
        green " =================================================="

    else
        exit
    fi
}
function removeV2rayUI(){
    green " =================================================="
    /usr/bin/v2-ui
}
function upgradeV2rayUI(){
    green " =================================================="
    /usr/bin/v2-ui
}


function getHTTPSNoNgix(){
    #stopServiceNginx
    #testLinuxPortUsage

    installPackage

    green " ================================================== "
    yellow " Please enter the domain name bound to this VPS, such as www.xxx.com: (For this step, please close the CDN and install it after nginx to avoid port80 occupancy and failure to apply fora certificate)"
    green " ================================================== "

    read configSSLDomain

    read -p "Do you want to apply fora certificate? The default is to apply fora certificate automatically. If you have a second installation or an existing certificate, you can choose No. Please enter[Y/n]?" isDomainSSLRequestInput
    isDomainSSLRequestInput=${isDomainSSLRequestInput:-Y}

    isInstallNginx="false"

    if compareRealIpWithLocalIp "${configSSLDomain}" ; then
        if [[ $isDomainSSLRequestInput == [Yy] ]]; then

            getHTTPSCertificate "standalone"

            if test -s ${configSSLCertPath}/fullchain.cer; then
                green " =================================================="
                green "   Domain name SSL certificate application is successful !"
                green " ${configSSLDomain} Domain name certificate content file path ${configSSLCertPath}/fullchain.cer "
                green " ${configSSLDomain} Domain name certificate private key file path ${configSSLCertPath}/private.key "
                green " =================================================="

            else
                red "==================================="
                red " The https certificate was not successfully applied, and the installation failed!"
                red " Please check whether the domain name and DNS are valid, please donot apply forthe same domain name multiple times inone day!"
                red " Please check whether ports80 and443 are open, VPS service providers may need to add additional firewall rules, such as Alibaba Cloud, Google Cloud, etc.!"
                red " Restart the VPS, re-execute the script, and re-select the repair certificate option to apply forthe certificate again! "
                red "==================================="
                exit
            fi

        else
            green " =================================================="
            green "   Do not apply fora domain name certificate, please put the certificate inthe following directory, or modify the trojan or v2ray configuration yourself!"
            green " ${configSSLDomain} Domain name certificate content file path ${configSSLCertPath}/fullchain.cer "
            green " ${configSSLDomain} Domain name certificate private key file path ${configSSLCertPath}/private.key "
            green " =================================================="
        fi
    else
        exit
    fi



    if [[ $1 == "trojan" ]] ; then
        installTrojanServer
    fi

    if [[ $1 == "v2ray" ]] ; then
        installV2ray

        if [[ $configV2rayVlessMode == "trojan" ]]; then
            installTrojanServer
        fi
    fi
}









function startMenuOther(){
    clear
    green " =================================================="
    green " 1. Install trojan-web (trojan and trojan-go visual management panel) and nginx camouflage website"
    green " 2. Upgrade trojan-web to the latest version"
    green " 3. Re-apply for a certificate"
    green " 4. View logs, manage users, view configurations and other functions"
    red " 5. Uninstall trojan-web and nginx "
    echo
    green " 6. Install v2ray visual management panel V2ray UI can support trojan at the same time"
    green " 7. Upgrade v2ray UI to the latest version"
    red " 8. Uninstall v2ray UI"
    echo
    red " Install the above 2 visual management panels. Trojan or v2ray cannot be installed with this script before. Please uninstall with this script first!"
    red " Install the above 2 visual management panels. You cannot install trojan or v2ray with other scripts before. Please uninstall with other scripts first!"
    red " The above two visual management panels cannot be installed at the same time!"

    green " =================================================="

    green " 11. Apply fora domain SSL certificate separately"
    green " 12. Only install trojan and run on port443, donot install nginx, please make sure that port443 is not occupied by nginx"
    green " 13. Only install trojan-go and run on port443, donot support CDN, donot open websocket, donot install nginx. Please ensure that port80 is listening, otherwise trojan-go will not start"
    green " 14. Only install trojan-go and run on port443, support CDN, enable websocket, and donot install nginx. Please ensure that port80 is listening, otherwise trojan-go cannot be started"    
    green " 15. Only install V2Ray or Xray (VLess or VMess protocol) open websocket, support CDN, (VLess/VMess+WS) donot install nginx, no TLS encryption, easy to integrate with existing websites or pagoda panels"
    green " 16. Only install V2Ray VLess runs on port443 (VLess-TCP-TLS) + (VLess-WS-TLS) Support CDN, donot install nginx"
    green " 17. Only install V2Ray VLess runs on port443 (VLess-TCP-TLS) + (VMess-TCP-TLS) + (VMess-WS-TLS) Support CDN, donot install nginx"
    green " 20. Only install Xray VLess running on port443 (VLess-TCP-XTLS direct) + (VLess-WS-TLS), don’t install nginx" 
    green " 21. Only install Xray VLess running on port443 (VLess-TCP-XTLS direct) + (VLess-WS-TLS) + trojan supports CDN of VLess, don’t install nginx"    
    green " 22. Only install Xray VLess and run on port443 (VLess-TCP-XTLS direct) + (VLess-WS-TLS) + trojan-go Support CDN of VLess, don't install nginx"   
    green " 23. Only install Xray VLess and run on port443 (VLess-TCP-XTLS direct) + (VLess-WS-TLS) + trojan-go Support VLess CDN and trojan-go CDN, do not install nginx"   
    green " 24. Only install Xray VLess running on port 443 (VLess-TCP-XTLS direct) + (VLess-WS-TLS) + xray's own trojan supports CDN of VLess, don’t install nginx"    

    red " 27. Uninstall trojan"    
    red " 28. Uninstall trojan-go"   
    red " 29. Uninstall v2ray或Xray"   

    green " =================================================="
    echo
    green " The following is the VPS network speed measurement tool"
    red " Script speed measurement will consume a lot of VPS traffic, please be aware!"
    green " 31. Test whether the VPS supports Netflix, check the IP unlock range and the corresponding region"
    echo
    green " 32. superspeed three-network pure speed measurement (full speed measurement of some nodes of the three major operators across the country)"
    green " 33. Bench comprehensive test written by teddysun (including system information IO test node test in multiple data centers)"
	green " 34. testrace backhaul routing test (four network routing test)"
	green " 35. LemonBench fast all-round test (including CPU memory performance, backhaul, speed)"
    green " 36. ZBench comprehensive network speed test (including node speed test, Ping and routing test)"

    echo
    green " 41. Install the new version of BBR-PLUS to accelerate the 6-in-1 script" 
    green " 42. Install WireGuard to unlock google verification codes and Netflix restrictions" 
    green " 43. Uninstall WireGuard" 
    echo
    green " 9. Return to the previous menu"
    green " 0. Exit script"
    echo
    read -p "Please enter the number:" menuNumberInput
    case "$menuNumberInput" in
        1 )
            setLinuxDateZone
            installTrojanWeb
        ;;
        2 )
            upgradeTrojanWeb
        ;;
        3 )
            runTrojanWebSSL
        ;;
        4 )
            runTrojanWebLog
        ;;
        5 )
            removeNginx
            removeTrojanWeb
        ;;
        6 )
            setLinuxDateZone
            installV2rayUI
        ;;
        7 )
            upgradeV2rayUI
        ;;
        8 )
            # removeNginx
            removeV2rayUI
        ;;
        11 )
            getHTTPSNoNgix
        ;;
        12 )
            getHTTPSNoNgix "trojan"
        ;;
        13 )
            isTrojanGo="yes"
            getHTTPSNoNgix "trojan"
        ;;
        14 )
            isTrojanGo="yes"
            isTrojanGoSupportWebsocket="true"
            getHTTPSNoNgix "trojan"
        ;;          
        15 )
            getHTTPSNoNgix "v2ray"
        ;;     
        16 )
            configV2rayVlessMode="vlessws"
            getHTTPSNoNgix "v2ray"
        ;; 
        17 )
            configV2rayVlessMode="vmessws"
            getHTTPSNoNgix "v2ray"
        ;;    
        20 )
            configV2rayVlessMode="vlessonly"
            getHTTPSNoNgix "v2ray"
        ;; 
        21 )
            configV2rayVlessMode="trojan"
            getHTTPSNoNgix "v2ray"
        ;;
        22 )
            configV2rayVlessMode="trojan"
            isTrojanGo="yes"
            getHTTPSNoNgix "v2ray"
        ;;    
        23 )
            configV2rayVlessMode="trojan"
            isTrojanGo="yes"
            isTrojanGoSupportWebsocket="true"
            getHTTPSNoNgix "v2ray"
        ;;
        24 )
            configV2rayVlessMode="vlesstrojan"
            getHTTPSNoNgix "v2ray"
        ;;          
        27 )
            removeTrojan
        ;;    
        28 )
            isTrojanGo="yes"
            removeTrojan
        ;;
        29 )
            removeV2ray
        ;;  
        31 )
            installPackage
            vps_netflix
        ;;                                                         
        32 )
            vps_superspeed
        ;;
        33 )
            vps_bench
        ;;        
        34 )
            vps_testrace
        ;;
        35 )
            vps_LemonBench
        ;;
        36 )
            vps_zbench
        ;;        
        41 )
            installBBR2
        ;; 
        42 )
            installWireguard
        ;;   
        43 )
            removeWireguard
        ;;                       
        9)
            start_menu
        ;;
        0 )
            exit 1
        ;;
        * )
            clear
            red "Please enter the correct number !"
            sleep 2s
            startMenuOther
        ;;
    esac
}







function start_menu(){
    clear

    if [[ $1 == "first" ]] ; then
        getLinuxOSRelease
        ${osSystemPackage} -y install wget curl git 
    fi

    green " =================================================="
    green " Trojan Trojan-go V2ray One-click installation script 2021-03-12 update. System support：centos7+ / debian9+ / ubuntu16.04+"
    red " *Please donot use this script inany production environment Please donot have other programs occupy80 and 443ports"
    green " =================================================="
    green " 1. Install BBR-PLUS to accelerate 4-in-1 script"
    echo
    green " 2. Installing trojan and nginx does not support CDN"
    green " 3. Repair the certificate and continue to install trojan"
    green " 4. Upgrade trojan to the latest version"
    red " 5. Uninstall trojan and nginx"
    echo
    green " 6. Install trojan-go and nginx does not support CDN, donot open websocket (compatible with trojan client)"
    green " 7. Repair the certificate and continue to install trojan-go does not support CDN, donot open websocket"
    green " 8. Install trojan-go and nginx to support CDN and open websocket (compatible with trojan client but not compatible with websocket)"
    green " 9. Repair the certificate and continue to install trojan-go to support CDN, open websocket"
    green " 10. Upgrade trojan-go to the latest version"
    red " 11. Uninstall trojan-go and nginx"
    echo
    green " 12. Install v2ray or xray and nginx, support websocket tls1.3, support CDN"
    green " 13. Upgrade v2ray or xray to the latest version"
    red " 14. Uninstall v2ray or xray and nginx"
    echo
    green " 15. Install trojan + v2ray or xray and nginx at the same time, CDN is not supported"
    green " 16. Upgrade v2ray or xray and trojan to the latest version"
    red " 17. Uninstall trojan, v2ray or xray and nginx"
    green " 18. Install trojan-go + v2ray or xray and nginx at the same time, CDN is not supported"
    green " 19. Install trojan-go + v2ray or xray and nginx at the same time, both trojan-go and v2ray support CDN"
    green " 20. Upgrade v2ray or xray and trojan-go to the latest version"
    red " 21. Uninstall trojan-go, v2ray or xray and nginx"
    echo
    green " 28. View information such as installed configuration and user password"
    green " 29. Submenu install trojan and v2ray visual management panel"
    green " 30. Do not install nginx, only install trojan or v2ray or xray, and optionally install an SSL certificate to facilitate integration with existing websites or pagoda panels"
    green " =================================================="
    green " 31. Install OhMyZsh and plug-in zsh-autosuggestions, Micro editor and other software"
    green " 32. Enable root user SSH login, for example, Google Cloud turns off root login by default, you can enable it through this option"
    green " 33. Modify the SSH login port number"
    green " 34. Set the time zone to Beijing time"
    green " 35. Use VI to edit the authorized_keys file, which is convenient to fill in the public key, log in without password, and increase security"
    green " 41. Submenu Internet Speed Test Tool, Netflix Test Tool, Unblock Netflix and Remove Google Verification Code Tool"
    green " 0. Exit script"
    echo
    read -p "Please enter the number:" menuNumberInput
    case "$menuNumberInput" in
        1 )
            installBBR
        ;;
        2 )
            installTrojanWholeProcess
        ;;
        3 )
            installTrojanWholeProcess "repair"
        ;;
        4 )
            upgradeTrojan
        ;;
        5 )
            removeNginx
            removeTrojan
        ;;
        6 )
            isTrojanGo="yes"
            installTrojanWholeProcess
        ;;
        7 )
            isTrojanGo="yes"
            installTrojanWholeProcess "repair"
        ;;
        8 )
            isTrojanGo="yes"
            isTrojanGoSupportWebsocket="true"
            installTrojanWholeProcess
        ;;
        9 )
            isTrojanGo="yes"
            isTrojanGoSupportWebsocket="true"
            installTrojanWholeProcess "repair"
        ;;
        10 )
            isTrojanGo="yes"
            upgradeTrojan
        ;;
        11 )
            isTrojanGo="yes"
            removeNginx
            removeTrojan
        ;;
        12 )
            isNginxWithSSL="yes"
            installTrojanWholeProcess
        ;;
        13 )
            upgradeV2ray
        ;;
        14 )
            removeNginx
            removeV2ray
        ;;
        15 )
            installTrojanWholeProcess
            installV2ray
        ;;
        16 )
            upgradeTrojan
            upgradeV2ray
        ;;
        17 )
            removeNginx
            removeTrojan
            removeV2ray
        ;;
        18 )
            isTrojanGo="yes"
            installTrojanWholeProcess
            installV2ray
        ;;
        19 )
            isTrojanGo="yes"
            isTrojanGoSupportWebsocket="true"
            installTrojanWholeProcess
            installV2ray
        ;;
        20 )
            isTrojanGo="yes"
            upgradeTrojan
            upgradeV2ray
        ;;
        21 )
            isTrojanGo="yes"
            removeNginx
            removeTrojan
            removeV2ray
        ;;
        28 )
            cat "${configReadme}"
        ;;        
        31 )
            setLinuxDateZone
            testLinuxPortUsage
            installPackage
            installSoftEditor
            installSoftOhMyZsh
        ;;
        32 )
            setLinuxRootLogin
            sleep 4s
            start_menu
        ;;
        33 )
            changeLinuxSSHPort
            sleep 10s
            start_menu
        ;;
        34 )
            setLinuxDateZone
            sleep 4s
            start_menu
        ;;
        35 )
            editLinuxLoginWithPublicKey
        ;;        
        29 )
            startMenuOther
        ;;
        30 )
            startMenuOther
        ;;        
        41 )
            startMenuOther
        ;;
        89 )
            installPackage
        ;;
        88 )
            installBBR2
        ;;
        99 )
            getTrojanAndV2rayVersion "trojan"
            getTrojanAndV2rayVersion "trojan-go"
            getTrojanAndV2rayVersion "trojan-web"
            getTrojanAndV2rayVersion "v2ray"
            getTrojanAndV2rayVersion "xray"
            getTrojanAndV2rayVersion "wgcf"
        ;;
        0 )
            exit 1
        ;;
        * )
            clear
            red "Please enter the correct number !"
            sleep 2s
            start_menu
        ;;
    esac
}



start_menu "first"

