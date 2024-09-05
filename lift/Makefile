
# FwdMap is a learning based system which automatically builds assembly to IR
# translators using code generators of modern compilers.

# Copyright (C) 2014 - 2015 by Niranjan Hasabnis and R.Sekar in Secure Systems
# Lab, Stony Brook University, Stony Brook, NY 11794.

# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version. 

# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. 

# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA 02111-1307 USA.

.DEFAULT_GOAL := all

FMT=ITC
#FMT=ATT
#FMT=ARM
#FMT=AVR

export OCAMLRUNPARAM=b
TESTS := $(wildcard *.imap)

LEX_FILES := $(wildcard *.mll)
YACC_FILES := $(wildcard *.mly) 
GENERATED_ML_FILES := $(LEX_FILES:%.mll=%.ml) $(YACC_FILES:%.mly=%.ml) \
                      $(LEX_FILES:%.mll=%.mli) $(YACC_FILES:%.mly=%.mli) \
                      $(LEX_FILES:%.mll=%.output) $(YACC_FILES:%.mly=%.output) 

CAMLC :=    ocamlc   -g -pp "camlp4o pa_macro.cmo -DFMT_${FMT}" 
CAMLOPTC := ocamlopt -g -pp "camlp4o pa_macro.cmo -DFMT_${FMT}"
CAMLFIND := ocamlfind

FMT_PARSER=parse${FMT}

%.cmo: %.ml
	$(CAMLC) -c -g $<

%.cmx: %.ml
	$(CAMLOPTC) -c -g $<

%.cmi: %.mli
	$(CAMLC) -c -g $<

%.ml: %.mll
	ocamllex $<

%.ml: %.mly
	ocamlyacc -v $<

%.mli: %.mly %.ml
	ocamlyacc -v $<

learnopt: learn.cmi ${FMT_PARSER}.cmi lexAsm.cmx ${FMT_PARSER}.cmx parseRtl.cmi lexRtl.cmx parseRtl.cmx learn.cmx main.cmx
	$(CAMLOPTC) -g -o $@ str.cmxa  learn.cmx lexAsm.cmx ${FMT_PARSER}.cmx lexRtl.cmx parseRtl.cmx main.cmx

learn: learn.cmi ${FMT_PARSER}.cmi lexAsm.cmo ${FMT_PARSER}.cmo parseRtl.cmi lexRtl.cmo parseRtl.cmo learn.cmo main.cmo
	$(CAMLC) -g -o $@ str.cma learn.cmo lexAsm.cmo ${FMT_PARSER}.cmo lexRtl.cmo parseRtl.cmo main.cmo

main.cmx: main.ml learn.ml learn.mli

lift: learn.cmi ${FMT_PARSER}.cmi lexAsm.cmx ${FMT_PARSER}.cmx parseRtl.cmi lexRtl.cmx parseRtl.cmx learn.cmx
	$(CAMLOPTC) -output-obj -o lift.o str.cmxa learn.cmx lexAsm.cmx ${FMT_PARSER}.cmx lexRtl.cmx parseRtl.cmx main.ml

all: lift learnopt

.PHONY: check
check:
	for testf in `ls 64test/test*.imap`; \
	do \
		echo -n "Checking $${testf} ..."; \
		outf=`mktemp -p /tmp` ; \
		./learnopt -tr $${testf} > $${outf} 2>&1; \
		fs=`grep "FAIL" -w $${outf} | cut -d ':' -f 2` ; \
		if [ "$${fs}" -eq "0" ]; \
		then	 \
			echo "Pass"; \
		else \
			echo "Fail"; \
		fi  \
	done; \

clean:
	rm -f learnopt learn *.o *.cmi *.cmo *.cmx *.a *.so *.cma *.cmxa
	rm -f $(GENERATED_ML_FILES)
