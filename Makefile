test:
	node node_modules/lab/bin/lab -v
test-cov: 
	node node_modules/lab/bin/lab -vt 100
test-cov-html:
	node node_modules/lab/bin/lab -r html -o coverage.html

.PHONY: test test-cov test-cov-html

