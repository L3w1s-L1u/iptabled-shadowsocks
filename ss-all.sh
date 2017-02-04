#! /bin/bash
# Maintainer: Lewis Liu <rhinoceromirinda@gmail.com>
#
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
# check user permissions
user=`whoami`
if [ "$user" != "root" ];then
    echo "$__file: Only root user can manipulate iptables! Exit now."
    exit 127
fi
# check iptables availability
iptables --version 2>&1 >/dev/null
if [ "$?" -ne 0 ];then
   echo "ss-all.sh: Couldn't run $iptables."
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
    if [ "$__result" == "false" ];then
        echo "$__file: Bypass local address in $__chain failed." 2>&1 |tee -a $ss_log_file
    fi

    # Redirect anything else to shadowsocks's local port
    $iptables -t $__table -A $__chain -p tcp -j REDIRECT --to-ports $__local_port
    $iptables -t $__table -A $__chain -p udp -j REDIRECT --to-ports $__local_port

    # Apply the rules
    $iptables -t $__table -A OUTPUT -j $__chain

}
# validate config parameters. 
# this can be used to check options in config file or check individual option submitted by user
# param:
#       <1. result>: "true" if all parameters are valid and "false" if any invalid
#       <config options...> remaining arguments are config options that need checking
ss_validate_config_param() {
    eval "$1='true'"
    __error="No error"
    while [ "$#" -gt 1 ]
    do
        case "$2" in
          config_file)
              if [ ! -f "$ss_config_file" ];then
                  __error="can not find config file"
              fi    
              shift;;
          server_ip)
              echo "$ss_server_ip" |grep -q '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'
              if [[ "$?" != 0 ]];then
                  __error="invalid server ip address"
              fi
              shift;;
          server_port)            
              echo $ss_server_port |grep -q '[0-9]\{3,5\}'
              if [[ "$?" != 0 ]];then
                  __error="invalid server port number ( at least 3 digits port number required )"
              fi
              shift;;
          local_port)
              echo $ss_local_port |grep -q '[0-9]\{3,5\}'
              if [[ "$?" != 0 ]];then
                 __error="invalid local port number ( at least 3 digits port number required )"
              fi
              shift;;
          *)
              __error="invalid validation option!"
              break;;
        esac
    done
    # positional arg $1 been shifted out, set it back. FIXME: better way to avoid shifting out $1?
    set -- __result
    if [[ "$__error" != "No error" ]];then
        echo "Warning! Validating config options failed, last error caught: $__error" 2>&1 |tee -a "$ss_config_file"
        eval "$1='false'"
    fi
}


# parse config file for server settings if user doesn't provide any server configs
ss_parse_config_file() {
    local __result="true"
    if [[ "$ss_config_file" == "${this_dir}/shadowsocks.json.tmpl" ]];then
        echo "$_file: Warning! No config file provided. Using $ss_config_file with incomplete config settings." 2>&1 |tee -a "$ss_log_file"
        __result="false" 
    fi
    ss_server_ip=`awk -v pat="\"server\"" -f config_parser.awk -- $ss_config_file`
    ss_server_port=`awk -v pat="\"server_port\"" -f config_parser.awk -- $ss_config_file`
    ss_local_port=`awk -v pat="\"local_port\"" -f config_parser.awk -- $ss_config_file`
    ss_validate_config_param __result server_ip server_port local_port
    if [[ "$__result" == "false" ]];then
        echo "$__file: Parsing config file failed. Shadowsocks may not run properly." 2>&1 |tee -a "$ss_log_file"
        echo "$__file: See more details in $ss_log_file." 2>&1 |tee -a $ss_log_file
    fi
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
# param: all bash command line options are passed, except non-option arguments. 
ss_parse_options_and_exec() {
    # though we can just simply pass all options to ss executables, we still need to parse all options 
    # provided by user because we need them to setup iptables.

    parsed_opt=`getopt -o c:hk:l:m:p:s: -n "$0" -- "$@"`

    # Parse option failed
    if [ $? != 0 ]; then echo "Parsing option failed. Terminating..." >&2 ; exit 1; fi
    
    eval set -- "$parsed_opt"
    # validate options
    local __error="No error"
    local __result="true"
    while true; do
        case "$1" in
             -c)
                ss_config_file="$2"
                ss_validate_config_param __result config_file
                if [[ "$__result" == "false" ]];then
                   echo "$__file: Warning! Can not find named config file." 2>&1 |tee -a "$ss_log_file"
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
                ss_validate_config_param __result local_port
                if [[ "$__result" == "false" ]];then
                   echo "$__file: Warning! Invalid loal port number, will use default value instead." 2>&1 |tee -a "$ss_log_file"
                fi
                shift 2 ;;
             -m)
                shift 2 ;; # iptables don't care encryption method
             -p)
                ss_server_port="$2"
                ss_validate_config_param __result server_port
                echo "$__file: Warning! Invalid server port number, will use default value instead." 2>&1 |tee -a "$ss_log_file"
                shift 2 ;;
              -s)
                ss_server_ip="$2"
                ss_validate_config_param __result server_ip
                if [[ "$__result" == "false" ]];then
                    echo "$__file: Warning! Invalid server ip address, will use default value instead." 2>&1 |tee -a "$ss_log_file"
                fi
                shift 2 ;;

             --)   
                shift ; break;;
             *)   
                __error="invalid option: $1" 
                echo "$__file: Validating option failed: $__error!" 2>&1 |tee -a "$ss_log_file"
                exit 127;;
        esac
    done
 
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
                # if no option except config file provided by user, we should use options set in config file
                ss_parse_config_file 
                # simply pass all options to ss executables but no non-option arguments
                parsed_options=${parsed_opt%%--*}
                ss-${ss_mode} ${parsed_options} 2>&1 >> "$ss_log_file"
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
                __error="invalid non-option argument: $arg"
                echo "$__file: Error parsing non option arguments: $__error" 2>&1 |tee -a "$ss_log_file"
                break;;
        esac
    done
}
# run shadowsocks redirection mode
ss_run_redir() {
    local __file="ss-all.sh"
    # Default settings
    table=nat
    ss_mode=redir
    ss_local_port=1080
    ss_config_file="${this_dir}/shadowsocks.json.tmpl"
    ss_pid_file="/var/run/sh-${ss_mode}.pid"
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
        echo "ss-all.sh: Invalid command name: ${cmd_name}!"
        exit 127
        ;;
esac

