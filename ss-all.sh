#! /bin/bash
# Maintainer: Lewis Liu <rhinoceromirinda@gmail.com>
# This script wrapped up shadowsocks executables, with proper iptables settings.
# See https://github.com/clowwindy/shadowsocks-libev/README.md for more information.
# Options are in accordance with ss-* executables, for example -s, -p, -l, -k, -m 
#   usage are the same as ss-*.
# Non option arguments are commands user want to execute: start service, stop service
#   and update config file.
# Usage:
iptss_help() {
    echo " Usage: iptss-[local|redir|server|tunnel] <options> -- start|stop|update-config"
    echo " Options:"
    echo "               <-h>   : show this help"
    echo "               <-c> <config_filename> : set config file, default is: /etc/shadowsocks.json"
    echo "               <-l> <port_number> : set local port ss-redir should listen, default is 1080"
    echo "               <-s> <server_ip> : set shadowsocks server's IP address"
    echo "               <-p> <port_number> : set shadowsocks server's listening port"
    echo "               <-k> <password>: set password of your shadowsocks server"
    echo "               <-m> <encryption method>: set encryption method your server is using"
    echo " Non option arguments:"
    echo "                -- :  '--' is used to seperate options with non-option arguments, see GNU getopt manual for more details"
    echo "               start  : start shadowsocks service"
    echo "               stop   : stop shadowsocks service"
    echo "               update-config   : update shadowsocks local config file"

}

this_dir=`pwd`
__file="ss-all.sh"
# check user permissions
user=`whoami`
if [ "$user" != "root" ];then
    echo "$__file: Only root user can manipulate iptables! Exit now."
    exit 127
fi
# check iptables availability
iptables --version 2>&1 >/dev/null
if [ "$?" -ne 0 ];then
   echo "$__file: Couldn't run $iptables."
   exit 127
fi
iptables=`which iptables`

# Default mode
ss_mode=local
# For some complex iptables routines
source iptables_op.sh

# setup iptables for shadowsocks redirection mode
# param:
#       <1.server ip>
#       <2.local port>
ss_setup_redir_iptables() {
    local __table=nat
    local __chain=CHAIN_SS_REDIR
    local __result=
    local __server_ip=$1
    local __local_port=$2
    # Delete $chain if it's already there. NOTE: this will also delete all rules that referenced this chain
    ipt_delete_chain __result $__table $__chain
    if [ "$__result" == "false" ];then
        echo "$__file: Delete chain $__chain failed. Still trying to create a new chain $__chain..." 2>&1 |tee -a $ss_log_file
    fi

    # Create a new chain 
    $iptables -t $__table -N $__chain

    # Ignore shadowsocks server address
    $iptables -t $__table -A $__chain -d $__server_ip -j RETURN

    # Ignore LANS
    __result=
    ipt_nat_bypass_local __result $__chain
    if [ "$result" == "false" ];then
        echo "$__file: Bypass local address in $__chain failed." 2>&1 |tee -a $ss_log_file
    fi

    # Redirect anything else to shadowsocks's local port
    $iptables -t $__table -A $__chain -p tcp -j REDIRECT --to-ports $__local_port
    $iptables -t $__table -A $__chain -p udp -j REDIRECT --to-ports $__local_port

    # Apply the rules
    $iptables -t $__table -A OUTPUT -j $__chain

}

# setup iptables according to shadowsocks mode
# param:
#       <1.ss_mode> : shadowsocks running mode
ss_setup_iptables() {
   case $1 in
       local)
           ;; #TODO: add iptables setup for local mode
       redir)
           # call actual setup function
           ss_setup_redir_iptables $ss_server_ip $ss_local_port
           ;;
       server)
           ;; #TODO: add iptables setup for server mode
       tunnel)
           ;; #TODO: add iptables setup for tunnel mode
       *)
           echo "$__file: Invalid shadowsocks mode: $1!"
           exit 127
           ;;
   esac
}

# parse user provided options and run shadowsocks with proper iptables settings
ss_parse_options_and_exec() {

    # though we can just simply pass all options to ss executables, we still need to parse all options 
    # provided by user because we need them to setup iptables.

    parsed_opt=`getopt -o c:hk:l:m:p:s: -n "$0" -- "$@"`

    # Parse option failed
    if [ $? != 0 ]; then echo "Parsing option failed. Terminating..." >&2 ; exit 1; fi
    
    eval set -- "$parsed_opt"
    # validate options
    error="No error"
    while true; do
        case "$1" in
             -c)
                 ss_config_file="$2"
                 if [ ! -f "$ss_config_file" ];then
                    error="can not find config file"
                    echo "$__file: Validating option failed: $error!" 2>&1 |tee -a $ss_log_file
                 fi
                 shift 2 ;;
             -h)   
                 iptss_help
                 shift ; exit 0;;
             -k)
                 ss_password="$2"
                 shift 2 ;;

             -l)
                 ss_local_port="$2"
                 echo $ss_local_port |grep -q '[0-9]\{3,5\}'
                 if [[ "$?" != 0 ]];then
                    error="invalid local port number ( at least 3 digits port number required )"
                    echo "$__file: Validating option failed: $error!" 2>&1 |tee -a $ss_log_file
                    ss_local_port=1080
                 fi
                 shift 2 ;;
             -m)
                 shift 2 ;; # iptables don't care encryption method
             -p)
                 ss_server_port="$2"
                 echo $ss_server_port |grep -q '[0-9]\{3,5\}'
                 if [[ "$?" != 0 ]];then
                    error="invalid server port number ( at least 3 digits port number required )"
                    echo "$__file: Validating option failed: $error!" 2>&1 |tee -a $ss_log_file
                 fi
                 shift 2 ;;
              -s)
                 ss_server_ip="$2"
                 # Check server's IP address
                 echo "$ss_server_ip" |grep -q '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'
                 if [[ "$?" != 0 ]];then
                     error="invalid server ip address"
                     echo "$__file: Validating option failed: $error!" 2>&1 |tee -a $ss_log_file
                 fi
                 shift 2 ;;

             --)   
                 shift ; break;;
             *)   
                 error="invalid option" 
                 echo "$__file: Validating option failed: $error!" 2>&1 |tee -a $ss_log_file
                 break;;
        esac
    done
 
    if [ "$error" != "No error" ];then
        echo "$__file: Error occurred during checking user provided parameters." 
        echo "$__file: See $ss_log_file for more details." 
        echo "$__file: ss-${ss_mode} may not run properly."
    fi

    # remaining non-option arguments
    for arg ;do
        case $arg in
            start)
                #ss_mode=${0##ss-}
                # Setup shadowsocks chain in iptables
                ss_setup_iptables $ss_mode
                # delete stale pid file
                if [ -f "$ss_pid_file" ];then
                    rm -f "$ss_pid_file"    
                fi
                # simply pass all options to ss executables but no non-option arguments
                parsed_options=${parsed_opt%%--*}
                ss-${ss_mode} ${parsed_options} 2>&1 >> $ss_log_file
                if [ "$?" -eq 0 ];then
                    echo "$__file: ss-${ss_mode} is running now, pid: $$, log file: $ss_log_file." |tee -a "$ss_log_file"
                else
                    echo "$__file: ss-${ss_mode} failed to start.See log file $ss_log_file for more information."
                    exit 1
                fi
                ;;
            stop)
                # Stop shadowsocks service
                cat "$ss_pid_file" |xargs kill -9
                ps aux|grep -q "ss-${ss_mode}\ ${parsed_options}"
                if [ "$?" -eq 0 ];then
                    echo "$__file: Stop ss-${ss_mode} service failed, you need to manually stop it." |tee -a "$ss_log_file"
                fi
                # Remove iptable's shadowsocks chain in $table
                declare -u ss_chain
                ss_chain="chain_${ss_mode}"
                ipt_delete_chain $table $ss_chain
                if [ "$?" -ne 0 ];then
                    echo "$__file: Failed to remove chain $ss_chain, you need to manually remove it." |tee -a "$ss_log_file"
                    exit 1
                fi
                ;;
            update-config)
                # TODO: update config file with user provided options
                echo "$__file: Updating config with user provided options"
                ;;
            *)
                error="invalid non-option argument"
                echo "$__file: An error: $error detected!"
                break;;
        esac
    done
}
# run shadowsocks redirection mode
ss_run_redir() {
    # Default settings
    table=nat
    ss_mode=redir
    ss_local_port=1080
    ss_server_ip=
    ss_server_port=
    ss_config_file="${this_dir}/shadowsocks.json"
    ss_pid_file="/var/run/shadowsocks.pid"
    ss_log_file="/var/log/ss-${ss_mode}.log"
  
    ss_parse_options_and_exec "$@"
}

# =============== Main =============== 
cmd_name=${0##/*/}
case "${cmd_name}" in
    ss-local.bash)
        ;; # TODO: scripts for ss-local mode
    ss-redir.bash)
        ss_run_redir "$@"
        ;;
    ss-server.bash)
        ;; # TODO: scripts for ss-server mode
    ss-tunnel.bash)
        ;; # TODO: scripts for ss-tunnel mode
    *)
        echo "$__file: Invalid command name: ${cmd_name}!"
        exit 127
        ;;
esac

