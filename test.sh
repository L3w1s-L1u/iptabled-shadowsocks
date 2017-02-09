#! /bin/bash

source "iptables_op.sh"

# test functions for "iptables_op.sh"
t_get_chains() {
    local __chain_list
    # normal case
    for t in filter nat mangle raw security
    do
        _get_chains __chain_list $t
        if [ "X$__chain_list" == "X" ];then
            $debug "No chains in $t."
        else
            $debug "chains in $t: $__chain_list."
        fi
    done
    # abnormal case
    _get_chains __chain_list no_such_table
}

t_check_ref_count() {
    local __chain=CHAIN_SS_REDIR
    local __table=nat
    local __ref_count="X"
    # normal case, manually validate result
    _check_ref_count __ref_count $__table $__chain 
}

t_delete_rules_by_ref() {
    local __chain=CHAIN_SS_REDIR
    local __table=nat
    local __result=
    $debug "Test delete all rules reference chain $__chain."
    # add some rules in chain
    ipt_bypass_local __result $__chain
    if [ "$__result" == "false" ];then
       $debug "Couldn't add rules to chain $__chain." 
    fi
    # delete all rules which reference $__chain
    __result=true
    _delete_rules_by_ref __result $__table $__chain 
    local __ref_count="X"
    _check_ref_count $__ref_count $__table $__chain

    if [ "$__result" == "false" ] || [ "$__ref_count" -ne 0 ];then
        $debug "Delete rules by reference failed." 
    else
        $debug "Delete rules by reference completed."
    fi 
}
# test functions for "ss-all.sh"
run_ss_service() {
    echo "run_ss_service: ss_mode: $1"
    echo "run_ss_service: parsed_options: $@"
}

# validate config parameters. 
# this can be used to check options in config file or check individual option submitted by user
# param:
#       <1. result>: "true" if all parameters are valid and "false" if any invalid
#       <config options...> remaining arguments are config options that need checking
ss_validate_config_param() {
    eval "$1='true'"
    local __error="No error"
    while [ "$#" -gt 1 ]
    do
        echo "debug: \$1: $1, \$2: $2"
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
              __error="invalid validation option: $2!"
              break;;
        esac
    done
    set -- __result
    if [[ "$__error" != "No error" ]];then
        echo "Warning! Validating config options failed, last error caught: $__error" 2>&1 |tee -a "$ss_log_file"
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
    echo "Validation result: $__result"
    if [[ "$__result" == "false" ]];then
        echo "$__file: Parsing config file failed. Shadowsocks may not run properly." 2>&1 |tee -a "$ss_log_file"
        echo "$__file: See more details in $ss_log_file." 2>&1 |tee -a $ss_log_file
    fi
}


test_config_parser(){
    ss_server_ip=
    ss_server_port=
    ss_local_port=
    ss_config_file="shadowsocks.json.tmpl"
    ss_log_file="/var/log/ss-test.log"
    ss_parse_config_file
    echo "server_ip: $ss_server_ip"
    echo "server_port: $ss_server_port"
    echo "local_port: $ss_local_port"
}

parse_option_and_exec() {

    parsed_opt=`getopt -o c:hk:l:m:p:s: -n "$0" -- "$@"`

    # Parse option failed
    if [ $? != 0 ]; then echo "Parsing option failed. Terminating..." >&2 ; exit 1; fi
    
    eval set -- "$parsed_opt"
    while true; do
        case "$1" in
            -c)
                echo "config file is $2"
                ss_config_file="$2"
                shift 2
                ;;
            -h)
                echo "show help info for $ss_mode"
                shift
                ;;
            -k)
                echo "password is $2"
                shift 2
                ;;
            -l)
                echo "local port number: $2"
                shift 2
                ;;
            -m)
                echo "encryption method: $2"
                shift 2
                ;;
            --)
                shift
                break
                ;;
            *)
                echo "invalid option: $1!"
                exit 127
                ;;
        esac
    done
    # remaining non-option arguments
    for arg ;do
        case $arg in
            start)
                echo "start service"
                run_ss_service "$ss_mode" "${parsed_opt%%--*}"
                shift
                ;;
            stop)
                echo "stop service"
                shift
                ;;
            update-config)
                echo "update config file"
                shift
                ;;
            *)
                echo "invalid command"
                exit 127
                ;;
        esac
    done
}

run_ss_redir() {
    ss_mode=redir
    test_config_parser
    parse_option_and_exec "$@"
}

# main
#cmd_name=${0##*/}
#echo $cmd_name
#case "$cmd_name" in
#    "ss-local.bash")
#        ;; # TODO: scripts for ss-local mode
#    "test.sh")
#        echo "$@"
#        run_ss_redir "$@"
#        ;;
#    "ss-server.bash")
#        ;; # TODO: scripts for ss-server mode
#    "ss-tunnel.bash")
#        ;; # TODO: scripts for ss-tunnel mode
#    *)
#        echo "Invalid command name!"
#        exit 127
#        ;;
#esac

