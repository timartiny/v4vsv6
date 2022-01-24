all: ndss

ndss:
	pdflatex main
	bibtex main
	pdflatex main
	pdflatex main

fast:
	pdflatex main

diff:
	latexdiff --flatten old/main.tex main.tex > diff.tex
	pdflatex diff.tex

clean:
	@rm -f *.aux *.log *.blg *.bbl *.out main.pdf
