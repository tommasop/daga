.PHONY: test

test:
	cutest -r ./test/helper test/*.rb

console:
	@env $$(cat .env) irb -r ./lib
