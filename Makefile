doc:
	epydoc-2.7 -v --exclude jose.test --exclude jose.cryptlib jose

clean:
	find . -name "*.pyc" -exec rm '{}' \;
	rm -r html
