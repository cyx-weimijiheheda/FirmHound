# FirmHound 开发入口。只支持 Linux，命令统一委托给 scripts/dev.py。
#
#   make          列出可用目标
#   make dev      建 .venv、装依赖、editable 安装
#   make test     单元测试
#   make doctor   环境自检
#
# 宿主依赖（binwalk / unsquashfs / sasquatch / qemu 等）见 docs/guide/install.md。
# 换解释器：make dev PYTHON=python3.13

PYTHON ?= python3
VENV   ?= .venv
PY     := $(VENV)/bin/python

.DEFAULT_GOAL := help
.PHONY: help venv dev test test-all integration ext-smoke firmrec-doctor \
        firmrec-smoke lint format smoke doctor lab-firmware clean clean-venv

help: ## 列出可用目标
	@$(PYTHON) scripts/dev.py help

venv: ## 创建 .venv（已存在则跳过）
	@$(PYTHON) scripts/dev.py venv

dev: venv ## 安装依赖并 editable 安装本项目
	@$(PY) scripts/dev.py dev

test: venv ## 单元测试
	@$(PY) scripts/dev.py test

test-all: venv ## 单元 + 宿主集成测试（缺工具自动跳过）
	@$(PY) scripts/dev.py test-all

integration: venv ## 仅宿主集成测试
	@$(PY) scripts/dev.py integration

ext-smoke: venv ## 探测四个外部分析器是否可用
	@$(PY) scripts/dev.py ext-smoke

firmrec-doctor: venv ## 检查 FirmRec 原生后端依赖
	@$(PY) scripts/dev.py firmrec-doctor

firmrec-smoke: venv ## 对已有 run 跑一次 FirmRec（RUN_DIR=runs/<id>）
	@$(PY) scripts/dev.py firmrec-smoke --run-dir "$(RUN_DIR)"

lint: venv ## ruff 检查
	@$(PY) scripts/dev.py lint

format: venv ## ruff 格式化
	@$(PY) scripts/dev.py format

smoke: venv ## 用合成 rootfs 跑一次端到端
	@$(PY) scripts/dev.py smoke

doctor: venv ## 环境自检（发行版、工具、Schema）
	@$(PY) -m fsa.cli doctor

lab-firmware: ## 构建本地多漏洞合成固件样本
	@$(PYTHON) scripts/build_lab_firmware.py

clean: ## 清理构建与缓存产物（保留 .venv）
	@$(PYTHON) scripts/dev.py clean

clean-venv: ## 删除 .venv
	rm -rf $(VENV)
