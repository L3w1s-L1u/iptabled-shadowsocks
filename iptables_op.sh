#! /bin/bash
# Frequently used iptables operations.
# Maintainer: Lewis Liu <rhinoceromirinda@gmail.com>
file="iptables_op.sh"
# check user permissions
user=`whoami`
if [ "$user" != "root" ];then
    echo "$file: Only root user can manipulate iptables! Exit now."
    exit 127
fi
# check iptables availability
iptables --version 2>&1 >/dev/null
if [ "$?" -ne 0 ];then
   echo "$file: Couldn't run iptables."
   exit 127
fi
# API: query if named chain exists
# param: 
#   <1.table> : table to operate on
#   <2.chain> : name of the chain to query
#   <3.rerult>: query result
# return:
#   "true" if chain exists
#   "false" if chain does not exist
ipt_query_chain() {
    table=$1
    chain=$2
    chains=""
    _get_chains $table 
    eval "$3='false'"  
    for c in $chains;do
        if [[ "$c" == "$chain" ]];then
           eval "$3='true'"  
           break
        fi
    done
}

# PRIVATE: get chains in a table
# param:
#   1.<table>: table to operate on
_get_chains() {
    table=$1
    chains=`iptables -t $table -nL  |  \
        awk '/^Chain\ [A-Z]*/{print $2}'`
    if [[ "X$chains" == "X" ]];then
        echo "$file: Warning! No chains in table $table."
    fi
}

# PRIVATE: this implements delete rules by reference to a chain
# it's intended to use internally, user should avoid directly invoke this function
# param: 
#   1.<table>: table to operate on
#   2.<ref_chain>: the chain referenced by rules we want to delete
_delete_rules_by_ref()
{
    table=$1
    ref_chain=$2
    _get_chains $table
    #debug:  echo "$chains"
    # for every chain in $table
    for chain in $chains
    do
        echo "$file: Processing chain $chain ..."
        # for every rule that referenced $ref_chain
        # n_rule: rule numbers
        for n_rule in `iptables -t $table -nL $chain --line-numbers | \
             awk /$ref_chain/'{\
                 if ( $1 != "Chain" )\
                      print $1 }'`
        do
            iptables -t $table -D $chain $n_rule
        done
    done
}

# API: delete rules reference a chain
# param:
#   1.<table>: the table to operate on
#   2.<chain>: the name of the chain to which the rules to be deleted reference
#   3.<result>: "true" if delete success, "false" is failed
ipt_delete_rules_by_ref()
{
   # validate input
   table=$1
   ref_chain=$2
   eval "$3='true'"
   _delete_rules_by_ref "$table" "$ref_chain"
   if [ "$?" -ne 0 ];then
       echo "$file: Warning! Delete rules referenced $ref_chain failed!"
       eval "$3='false'"
   fi
}

# API: delete a chain
# delete a chain requires 3 steps:
#   1. flush all rules in this chain
#   2. delete references to this chain
#   3. delete the chain
# parameters:
#   1.<table> : the table which contains this chain
#   2.<chain> : the name of the chain
#   3.<result>: "true" if delete success, "false" is failed
ipt_delete_chain() {
    table=$1
    chain=$2 
    eval "$3='true'"
    ipt_query_chain $chain
    if [[ "$?" -eq "1" ]];then
        echo "$file: Warning! Named chain $chain does not exist."
        eval "$3='false'"
        return
    fi
    echo "Delete chain $chain will also delete any rule that references this chain. Continue? (Y|N)"
    read line
    case "$line" in
        YES|Yes|yes|Y|y)
            ;;
        NO|No|no|N|n)
            echo "User canceled delete operation."
            exit 0
            ;;
        *)
            echo "Only YES or NO accepted.Exit now."
            exit 0
            ;;
    esac

    # flush all rules in $chain
    iptables -t "$table" -F "$chain"

    if [ "$?" -ne 0 ];then
        echo "$file: Couldn't flush all rules in chain $chain. You need to manually delete them. Exit now."
        exit 127
    fi
    # delete rules referenced $chain
    _delete_rules_by_ref $table $chain

    # delete $chain
    iptables -t "$table" -X "$chain"
    if [ "$?" -ne 0 ];then
        echo "Couldn't delete chain $chain. You need to manually delete it. Exit now."
        exit 127
    fi
}

# API: bypass local address by adding rules in nat table
# param:
#   <chain> : the name of the chain

ipt_nat_bypass_local() {
    table=nat
    chain=$1

    local_address=" 0.0.0.0/8 
                    10.0.0.0/8 
                    127.0.0.0/8 
                    169.254.0.0/16 
                    172.16.0.0/12 
                    192.168.0.0/16 
                    224.0.0.0/4 
                    240.0.0.0/4"
    for addr in $local_address
    do
        iptables -t "$table" -A "$chain" -d "$addr" -j RETURN; 
    done
}

