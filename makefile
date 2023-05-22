VENV_DIR=.venv
VENV=source $(VENV_DIR)/bin/activate

.PHONY: install
install: .venv
	$(VENV) && python tools/install.py

.PHONY: setup
setup: .venv/pyvenv.cfg

.PHONY: list
list: setup
	$(VENV) && python tools/proper-list.py

.PHONY: config
config: .venv/ProperTree/ProperTree.py
	$(VENV) && python .venv/ProperTree/ProperTree.py OC/config.plist

.PHONY: env
env: .env
	@sh -c '$${EDITOR-vi} .env'

# Implementation detail
.venv/pyvenv.cfg: tools/requirements.txt
	python3 -m venv .venv
	$(VENV) && pip install -r tools/requirements.txt

.venv/ProperTree/ProperTree.py: .venv/pyvenv.cfg
	$(VENV) && python tools/get-propertree.py .venv/ProperTree

# XXX: The update message isn't very obvious when the editor opens
.env: .env.sample
	@if [ -f .env ]; then echo "New .env.sample file detected. There may be new settings to check out."; else echo "No .env file found, copying .env.sample to .env"; cp .env.sample .env; fi
