NAME := howto

CHAPTERS := setupTEMU.tex traces.tex
FIGURES := ../install-temu-release.sh

all: $(NAME).pdf $(NAME).html

$(NAME).dvi: $(NAME).tex $(CHAPTERS) $(FIGURES)
	latex $(NAME).tex
	latex $(NAME).tex
	latex $(NAME).tex

$(NAME).html: $(NAME).tex $(CHAPTERS) $(FIGURES)
	hevea -fix $(NAME).tex

$(NAME).pdf: $(NAME).dvi
	dvipdf $<

clean:
	-rm -f $(NAME).dvi $(NAME).pdf $(NAME).aux $(NAME).out $(NAME).log
	-rm -f $(NAME).toc
	-rm -f comment.cut
	-rm -f $(NAME).html $(NAME)[0-9][0-9][0-9].png
	-rm -f $(NAME).haux $(NAME).htoc 
	-rm -f $(NAME).image.tex $(NAME).image.out
	-rm -f *.eps

