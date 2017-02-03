#! /bin/bash
# test functions
config_file="shadowsocks.json.tmpl"
run_ss_service() {
    echo "run_ss_service: ss_mode: $1"
    echo "run_ss_service: parsed_options: $@"
}

test_config_parser(){
    ss_server_ip=
    ss_server_port=
    ss_local_port=
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
case "$0" in
    "ss-local.bash")
        ;; # TODO: scripts for ss-local mode
    "test.sh")
        echo "$@"
        test_config_parser
        run_ss_redir "$@"
        ;;
    "ss-server.bash")
        ;; # TODO: scripts for ss-server mode
    "ss-tunnel.bash")
        ;; # TODO: scripts for ss-tunnel mode
    *)
        echo "Invalid command name!"
        exit 127
        ;;
esac

