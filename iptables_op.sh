#! /bin/bash
# Frequently used iptables operations.
# Maintainer: Lewis Liu <rhinoceromirinda@gmail.com>

log_file=/var/log/iptables_op.log

# FIXME: only work when source this file in another shell script
# Will not work if directly source it from command line
__debug() 
{
    echo "${FUNCNAME[1]}:${BASH_LINENO[0]}: $* 2>&1 |tee -a $log_file"
}

if [ "$DEBUG" == "verbose" ];then
    debug=__debug       
else
    debug=echo 
fi

# check iptables
ipt_check_iptables() {
    local __file="iptables_op.sh"
    # check user permissions
    user=`whoami`
    if [ "$user" != "root" ];then
        $debug "Only root user can manipulate iptables! Exit now." 
        exit 127
    fi
    # check iptables availability
    iptables --version 2>&1 >/dev/null
    if [ "$?" -ne 0 ];then
       $debug "Couldn't run iptables." 
       exit 127
    fi
}

# PRIVATE: check reference count of a chain
# param:
#   1.<__ref_count>: reference count of a chain, if no rule references this chain
#                   the __ref_count should be 0.
#   2.<__table>:    on which table to operate
#   3.<__chain>:    the chain being referenced by rules
_check_ref_count() {
    local __table=$2
    local __chain=$3
    local __count=`iptables -t $__table -nL |awk -F " " -v pat="$__chain" \
        '$2 ~ pat { print $3 } |grep -o -E "[0-9]{1,}"'`
    if [ "X$__count" == "X" ];then
        eval "$1='0'"
    else
        eval "$1='$__count'"
    fi
}

# PRIVATE: get chains in a table
# param:
#   1.<result>: a list of chains in table
#   2.<table>: table to operate on
# return:
#   empty string if no chain in table
#   a list of all chains in table, separated by blanks
_get_chains() {
    local __file="iptables_op.sh"
    local __table=$2
    local __chains=`iptables -t $__table -nL| awk 'BEGIN{ ORS=" " } /^Chain\ [A-Z]*/{print $2}'`
    echo "Debug:$LINENO: $__chains"
    if [[ "X$__chains" == "X" ]];then
        $debug "Warning! No chains in table $__table."
        eval "$1= "
    else
        eval "$1='$__chains'"
    fi
}

# PRIVATE: delete rules by reference to a chain
# it's intended to use internally, user should avoid directly invoke this function
# param: 
#   1.<result>: "ture" if delete success, "false" if failed
#   2.<table>: table to operate on
#   3.<ref_chain>: the chain referenced by rules we want to delete
_delete_rules_by_ref()
{
    local __file="iptables_op.sh"
    local __table=$2
    local __ref_chain=$3
    local __chain_list=
    eval "$1='true'"
    _get_chains __chain_list $__table
    echo "Debug:$LINENO:__chains: $__chain_list"
    if [[ "X$__chain_list" == "X" ]];then
        $debug "Warning! No chains in table $__table."
        eval "$1='false'"
        return
    else
        # for every chain in $table
        for c in $__chain_list
        do
           $debug "Processing chain $c ..." $__to_log
           # for every rule that referenced $__ref_chain
           # n_rule: rule numbers
           for n_rule in `iptables -t $__table -nL $c --line-numbers | \
              awk /$__ref_chain/'{\
                  if ( $1 != "Chain" )\
                       print $1 }'`
           do
             iptables -t $__table -D $c $n_rule
             if [[ "$?" -ne "0" ]];then
                 $debug "Warning! Delete rule #$n_rule in $c failed!" 
                 eval "$1='false'"
             fi
           done
         done
     fi
}

# API: query if named chain exists
# param: 
#   <1.rerult>: query result
#   <2.table> : table to operate on
#   <3.chain> : name of the chain to query
# return:
#   "true" if chain exists
#   "false" if chain does not exist
ipt_query_chain() {
    local __table=$2
    local __chain=$3
    local __chain_list=
    _get_chains __chain_list "$__table" 
    $debug "__chains: $__chain_list"
    for c in $__chain_list;do
        if [[ "$c" == "$__chain" ]];then
           $debug "Found match chain: $c"
           eval "$1='true'"  
           return
        fi
    done
    eval "$1='false'"  
}

# API: delete rules reference a chain
# param:
#   1.<result>: "true" if delete success, "false" if failed
#   2.<table>: the table to operate on
#   3.<chain>: the name of the chain to which the rules to be deleted reference
ipt_delete_rules_by_ref()
{
    local __file="iptables_op.sh"
    # validate input
    local __table=$2
    local __ref_chain=$3
    local __result=
    eval "$1='true'"
    _delete_rules_by_ref __result $__table $__ref_chain 
    if [[ "$__result" == "false" ]];then
        $debug "Warning! Delete rules referenced $__ref_chain failed!" 
        eval "$1='false'"
    fi
}

# API: delete a chain
# delete a chain requires 3 steps:
#   1. flush all rules in this chain
#   2. delete references to this chain
#   3. delete the chain
# param:
#   1.<result>: "true" if delete success, "false" is failed
#   2.<table> : the table which contains this chain
#   3.<chain> : the name of the chain
ipt_delete_chain() {
    local __file="iptables_op.sh"
    local __table=$2
    local __chain=$3 
    local __result=
    eval "$1='true'"
    ipt_query_chain __result $__table $__chain 
    if [[ "$__result" == "false" ]];then
        $debug "Warning! Query chain: $__chain failed."
        eval "$1='false'"
        return
    fi
    echo "Delete chain $__chain will also delete any rule that references this chain. Continue? (Y|N)"
    read line
    case "$line" in
        YES|Yes|yes|Y|y)
            ;;
        NO|No|no|N|n)
            $debug "User canceled delete operation."
            eval "$1='false'"
            return
            ;;
        *)
            echo "Only YES or NO accepted."
            eval "$1='false'"
            return
            ;;
    esac

    # flush all rules in $chain
    iptables -t "$__table" -F "$__chain"
    if [ "$?" -ne 0 ];then
        $debug "Couldn't flush all rules in chain $__chain. You need to manually delete them." 
    fi
    # delete rules referenced $chain
    _delete_rules_by_ref $__result $__table $__chain 
    if [[ "$__result" == "false" ]];then
        $debug "Delete rules which reference $__chain failed!" 
        eval "$1='false'"
    fi
    # delete $chain
    iptables -t "$__table" -X "$__chain"
    if [ "$?" -ne 0 ];then
        $debug "Couldn't delete chain $__chain. You need to manually delete it." 
        eval "$1='false'"
    fi
}

# API: bypass local address by adding rules in nat table
# param:
#   <1.result>: "true" if add success and "false" if failed
#   <2.chain> : the name of the chain

ipt_nat_bypass_local() {
    local __file="iptables_op.sh"
    local __table=nat
    local __chain=$2
    eval "$1='true'"
    local __local_address=" 0.0.0.0/8 
                    10.0.0.0/8 
                    127.0.0.0/8 
                    169.254.0.0/16 
                    172.16.0.0/12 
                    192.168.0.0/16 
                    224.0.0.0/4 
                    240.0.0.0/4"
    for addr in $__local_address
    do
        iptables -t "$__table" -A "$__chain" -d "$addr" -j RETURN; 
        if [[ "$?" -ne 0 ]];then
            eval "$1='false'"
            $debug "Bypass local address $addr failed. You need to manually set iptables rules."
            break
        fi
    done
}

