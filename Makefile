# Makefile for iptabled-shadowsocks

SHELL				:= /bin/bash
LN					:= ln
RM					:= rm
MKDIR				:= mkdir
CAT					:= cat
CP					:= cp
GREP				:= grep

# User must run make in the folder which contains this Makefile 
top_dir				:= $(shell pwd)
iptables			:= $(shell which iptables)
ipt_script			:= ${top_dir}/iptables_op.sh
config_templ		:= ${top_dir}/shadowsocks.json.tmpl
ss_script			:= ${top_dir}/ss-all.sh
ss_script_bin		:= ${top_dir}/ss-bash
bashrc				:= ~/.bashrc
bashrc_bk			:= ~/.bashrc.bk

# Shadowsocks modes, if new mode available, this variable should be updated with new mode
ss_modes			:= local redir server tunnel

ss_available_modes := $(foreach mode,$(ss_modes),$(subst  \
	ss-,,$(notdir $(shell which ss-$(mode)))))

# install iptabled-shadowsocks
define install-scripts
	if [ ! -x "${iptables}" ];then \
		echo "No iptables found in system. Please install iptables first."; \
		exit -1; \
	fi

	if [ -d "${ss_script_bin}" ];then \
		$(RM) -rv ${ss_script_bin};	\
	fi
	$(MKDIR) -p ${ss_script_bin} && \
	for mode in ${ss_available_modes}; \
	do \
		$(LN) -s "${ss_script}" "${ss_script_bin}/ss-$${mode}.bash"; \
	done
	$(LN) -s "${ipt_script}" "${ss_script_bin}/iptables_op.sh"; \
	if [ ! -x "${bashrc}" ];then \
		touch ${bashrc}; \
	fi
	if ! ${GREP} -q "${ss_script_bin}" ${bashrc};then \
		$(CP) -v ${bashrc} ${bashrc_bk} && \
		echo '\
		if [ -d "${ss_script_bin}" ] && \
	   		! ${GREP} -q "${ss_script_bin}" <<< $${PATH};then \
   			export PATH="$${PATH}:${ss_script_bin}";\
		else \
			export PATH="$${PATH%%:${ss_script_bin}}";\
		fi' >> ${bashrc}; \
	fi
	. ${bashrc}
endef

# uninstall iptabled-shadowsocks
define delete-scripts
	if [ -d ${ss_script_bin} ];then 	\
		$(RM) -rvf ${ss_script_bin};	\
	fi
	if [ -f ${bashrc_bk} ] && [ -s ${bashrc_bk} ];then \
		$(RM) -f ${bashrc} && \
		$(CP) ${bashrc_bk} ${bashrc}; \
	fi
	. ${bashrc}
endef

.PHONY: all install clean

all: install

install: ${iptables} ${ss_script}
	@echo "available modes: $(ss_available_modes)"
	@$(install-scripts)
	@echo "Shadowsocks scripts successfully installed to ${ss_script_bin}."
	@echo "Try ss-*.bash in a new shell to see available service."
clean:
	@$(delete-scripts)
	@echo "Shadowsocks scripts uninstalled."
