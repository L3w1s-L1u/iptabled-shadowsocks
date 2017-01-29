#! /bin/bash
# Frequently used iptables operations.
# Maintainer: Lewis Liu <rhinoceromirinda@gmail.com>
__file="iptables_op.sh"

__to_log=
if [[ "$debug" == "verbose" ]];then
    __to_log=" 2>&1 |tee -a $ss_log_file"
fi

# check user permissions
user=`whoami`
if [ "$user" != "root" ];then
    echo "$__file: Only root user can manipulate iptables! Exit now." $__to_log
    exit 127
fi
# check iptables availability
iptables --version 2>&1 >/dev/null
if [ "$?" -ne 0 ];then
   echo "$__file: Couldn't run iptables." $__to_log
   exit 127
fi
# PRIVATE: get chains in a table
# param:
#   1.<result>: a list of chains in table
#   2.<table>: table to operate on
# return:
#   empty string if no chain in table
#   a list of all chains in table, separated by blanks
_get_chains() {
    local __table=$2
    local __chains=`iptables -t $__table -nL  |  \
        awk '/^Chain\ [A-Z]*/{print $2}'`
    if [[ "X$__chains" == "X" ]];then
        echo "$__file: Warning! No chains in table $__table." $__to_log
        eval "$1= "
    else
        eval "$1=$__chains"
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
    local __table=$2
    local __ref_chain=$3
    local __chains=""
    eval "$1='true'"
    _get_chains __chains $__table
    #debug:  echo "$__chains"
    if [["X$__chains" == "X" ]];then
        echo "$__file: Warning! No chains in table $__table."  $__to_log
        eval "$1='false'"
        return
    else
        # for every chain in $table
        for c in $__chains
        do
           echo "$__file: Processing chain $c ..." $__to_log
           # for every rule that referenced $__ref_chain
           # n_rule: rule numbers
           for n_rule in `iptables -t $__table -nL $c --line-numbers | \
              awk /$__ref_chain/'{\
                  if ( $1 != "Chain" )\
                       print $1 }'`
           do
             iptables -t $__table -D $c $n_rule
             if [[ "$?" -ne "0" ]];then
                 echo "$__file: Warning! Delete rule #$n_rule in $c failed!" $__to_log
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
    local __chains=""
    _get_chains __chains $__table 
    eval "$1='false'"  
    for c in $__chains;do
        if [[ "$c" == "$__chain" ]];then
           eval "$1='true'"  
           break
        fi
    done
}

# API: delete rules reference a chain
# param:
#   1.<result>: "true" if delete success, "false" if failed
#   2.<table>: the table to operate on
#   3.<chain>: the name of the chain to which the rules to be deleted reference
ipt_delete_rules_by_ref()
{
   # validate input
   local __table=$2
   local __ref_chain=$3
   local __result=
   eval "$1='true'"
   _delete_rules_by_ref __result $__table $__ref_chain 
   if [[ "$__result" == "false" ]];then
       echo "$__file: Warning! Delete rules referenced $__ref_chain failed!" $__to_log
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
    local __table=$2
    local __chain=$3 
    local __result=
    eval "$1='true'"
    ipt_query_chain __result $__chain 
    if [[ "$__result" == "false" ]];then
        echo "$__file: Warning! Named chain $__chain does not exist." $__to_log
        eval "$1='false'"
        return
    fi
    echo "Delete chain $__chain will also delete any rule that references this chain. Continue? (Y|N)"
    read line
    case "$line" in
        YES|Yes|yes|Y|y)
            ;;
        NO|No|no|N|n)
            echo "User canceled delete operation."
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
        echo "$__file: Couldn't flush all rules in chain $__chain. You need to manually delete them." $__to_log
    fi
    # delete rules referenced $chain
    _delete_rules_by_ref $__result $__table $__chain 
    if [[ "$__result" == "false" ]];then
        echo "$__file: Delete rules which reference $__chain failed!" $__to_log
        eval "$1='false'"
    fi
    # delete $chain
    iptables -t "$__table" -X "$__chain"
    if [ "$?" -ne 0 ];then
        echo "$__file: Couldn't delete chain $__chain. You need to manually delete it." $__to_log
        eval "$1='false'"
    fi
}

# API: bypass local address by adding rules in nat table
# param:
#   <1.result>: "true" if add success and "false" if failed
#   <2.chain> : the name of the chain

ipt_nat_bypass_local() {
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
            echo "$__file: Bypass local address $addr failed. You need to manually set iptables rules." $__to_log
            break
        fi
    done
}

