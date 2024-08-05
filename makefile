VENV_DIR=.venv
VENV=source $(VENV_DIR)/bin/activate

.PHONY: install
install: .venv
	$(VENV) && python3 tools/install.py

.PHONY: mountesp
mountesp:
	$(VENV) && python3 tools/install.py --mount-esp

.PHONY: setup
setup: .venv/pyvenv.cfg

.PHONY: update
update: setup
	$(VENV) && python3 -m pip install --upgrade -r tools/requirements.txt

.PHONY: list
list: setup
	$(VENV) && python3 tools/proper-list.py OC/config.plist kexts

.PHONY: ssdts
ssdts: setup
	$(VENV) && python3 tools/proper-list.py OC/config.plist ssdts

.PHONY: newkext
newkext: setup
	$(VENV) && python3 tools/update-kexts.py OC/config.plist

# Don't use venv for ProperTree since it may break Tkinter
.PHONY: config
config: .venv/ProperTree/ProperTree.py
	python3 .venv/ProperTree/ProperTree.py OC/config.plist

.PHONY: env
env: .env
	@sh -c '$${EDITOR-vi} .env'

# Implementation detail
.venv/pyvenv.cfg: tools/requirements.txt
	python3 -m venv .venv
	# Install cachier manually so pathtools isn't pulled in. It's broken on Python 3.12
	$(VENV) \
		&& pip install watchdog portalocker \
		&& pip install --no-deps cachier \
		&& pip install -r tools/requirements.txt

.venv/ProperTree/ProperTree.py: .venv/pyvenv.cfg
	$(VENV) && python3 tools/get-propertree.py .venv/ProperTree

# XXX: The update message isn't very obvious when the editor opens
.env: .env.sample
	@if [ -f .env ]; then echo "New .env.sample file detected. There may be new settings to check out."; else echo "No .env file found, copying .env.sample to .env"; cp .env.sample .env; fi

