.PHONY: install test demo clean
install:
	pip install -e ".[dev]"
test:
	pytest -q
demo:
	socpilot run-all --brain heuristic
clean:
	rm -rf out .pytest_cache src/*.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} +
