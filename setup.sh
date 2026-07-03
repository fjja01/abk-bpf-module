#!/usr/bin/env bash
# ABK 自定义外部模块：为 GKI 5.15 内核追加 eBPF 增强
# 阶段：after_patch（在 SUSFS/SukiSU 等内置补丁之后执行）
# 设备：Xiaomi Redmi K70 Pro (vermeer) / android13-5.15.119
#
# 诊断结论（首轮构建）：
#   - defconfig 修改生效（FUNCTION_ERROR_INJECTION 从 n→y）
#   - 但 FUNCTION_TRACER 被 Kconfig 源码强制关闭（依赖满足但仍 n）
#   - SECURITY_BPF 的 Kconfig 条目被 GKI 移除（symbol 不存在）
#   - BPF_KPROBE_OVERRIDE 缺 arm64 的 HAVE_BPF_KPROBE_OVERRIDE，无法启用
#
# 本脚本同时修改 defconfig 和 Kconfig 源码

set -euo pipefail

echo "==================================================="
echo "[ABK-BPF] 开始应用 eBPF 增强（defconfig + Kconfig）"
echo "==================================================="

# 检查关键环境变量
if [[ -z "${DEFCONFIG:-}" ]]; then
    echo "[ABK-BPF][ERROR] DEFCONFIG 环境变量未设置"
    exit 1
fi

if [[ ! -f "$DEFCONFIG" ]]; then
    echo "[ABK-BPF][ERROR] defconfig 文件不存在: $DEFCONFIG"
    exit 1
fi

echo "[ABK-BPF] 目标 defconfig: $DEFCONFIG"
echo "[ABK-BPF] CONFIG 变量:    ${CONFIG:-未知}"
echo "[ABK-BPF] KERNEL_ROOT:    ${KERNEL_ROOT:-未知}"

# 定位内核源码根目录（即包含 kernel/, security/, net/ 等子目录的 common/）
# ABK 约定：KERNEL_ROOT 指向 android13-5.15-119 等，内核源码在其下的 common/
# DEFCONFIG 路径形如 .../android13-5.15-119/common/arch/arm64/configs/gki_defconfig
KERNEL_SRC=""
if [[ -n "${KERNEL_ROOT:-}" ]]; then
    KERNEL_SRC="${KERNEL_ROOT}/common"
fi
if [[ ! -d "$KERNEL_SRC" ]]; then
    KERNEL_SRC=""
fi

if [[ -z "$KERNEL_SRC" ]] && [[ -n "${DEFCONFIG:-}" ]]; then
    # 从 DEFCONFIG 路径推断：找路径中 "common" 所在位置
    case "$DEFCONFIG" in
        */common/arch/arm64/configs/*)
            KERNEL_SRC="${DEFCONFIG%/arch/arm64/configs/*}"
            ;;
        */common/arch/*)
            KERNEL_SRC="${DEFCONFIG%/arch/*}"
            ;;
        *)
            KERNEL_SRC=$(dirname "$(dirname "$(dirname "$DEFCONFIG")")")
            ;;
    esac
fi

if [[ -z "$KERNEL_SRC" ]] || [[ ! -d "$KERNEL_SRC" ]]; then
    echo "[ABK-BPF][ERROR] 无法定位内核源码根目录"
    echo "[ABK-BPF][ERROR] KERNEL_ROOT=${KERNEL_ROOT:-未设置}"
    echo "[ABK-BPF][ERROR] DEFCONFIG=${DEFCONFIG:-未设置}"
    echo "[ABK-BPF][ERROR] 推断 KERNEL_SRC=${KERNEL_SRC:-空}"
    exit 1
fi

echo "[ABK-BPF] 内核源码根: $KERNEL_SRC"

# 验证源码根目录结构
for subdir in kernel security net; do
    if [[ ! -d "$KERNEL_SRC/$subdir" ]]; then
        echo "[ABK-BPF][WARN] $KERNEL_SRC/$subdir 不存在（可能影响 Kconfig patch）"
    fi
done
echo "[ABK-BPF] 路径验证完成"

# 备份原始 defconfig
BACKUP="${DEFCONFIG}.abk-bpf.bak"
if [[ ! -f "$BACKUP" ]]; then
    cp "$DEFCONFIG" "$BACKUP"
    echo "[ABK-BPF] 已备份 defconfig: $BACKUP"
fi

# 追加 CONFIG 的函数（幂等）
append_config() {
    local cfg="$1"
    local val="$2"
    sed -i "/^# ${cfg} is not set\$/d" "$DEFCONFIG"
    sed -i "/^${cfg}=/d" "$DEFCONFIG"
    echo "${cfg}=${val}" >> "$DEFCONFIG"
    echo "[ABK-BPF] defconfig: ${cfg}=${val}"
}

echo ""
echo "[ABK-BPF] === 第 1 步：修改 defconfig ==="
echo "---------------------------------------------------"

# 函数追踪基础设施
append_config "CONFIG_FUNCTION_TRACER" "y"
append_config "CONFIG_DYNAMIC_FTRACE" "y"
append_config "CONFIG_DYNAMIC_FTRACE_WITH_REGS" "y"
append_config "CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS" "y"
append_config "CONFIG_FTRACE_SYSCALLS" "y"

# 函数错误注入
append_config "CONFIG_FUNCTION_ERROR_INJECTION" "y"
# 注意：BPF_KPROBE_OVERRIDE 在 arm64 上无法启用（缺 HAVE_BPF_KPROBE_OVERRIDE）
# append_config "CONFIG_BPF_KPROBE_OVERRIDE" "y"

# BPF LSM 安全模块
append_config "CONFIG_SECURITY_BPF" "y"
append_config "CONFIG_BPF_LSM" "y"

# 辅助可观测性选项
append_config "CONFIG_BPF_EVENTS" "y"
append_config "CONFIG_BPF_STREAM_PARSER" "y"
append_config "CONFIG_DEBUG_INFO_BTF" "y"
append_config "CONFIG_DEBUG_INFO_BTF_MODULES" "y"

echo ""
echo "[ABK-BPF] === 第 2 步：patch Kconfig 源码 ==="
echo "---------------------------------------------------"

# Kconfig patch 函数（幂等，用标记防止重复）
patch_kconfig() {
    local kcfg_file="$1"
    local marker="$2"
    local content="$3"

    if [[ ! -f "$kcfg_file" ]]; then
        echo "[ABK-BPF][WARN] Kconfig 文件不存在: $kcfg_file"
        return 0
    fi

    if grep -q "$marker" "$kcfg_file" 2>/dev/null; then
        echo "[ABK-BPF] 已 patch (跳过): $kcfg_file"
        return 0
    fi

    # 备份
    if [[ ! -f "${kcfg_file}.abk-bpf.bak" ]]; then
        cp "$kcfg_file" "${kcfg_file}.abk-bpf.bak"
    fi

    # 追加 patch 内容
    echo "" >> "$kcfg_file"
    echo "# === ABK-BPF PATCH START ($marker) ===" >> "$kcfg_file"
    echo "$content" >> "$kcfg_file"
    echo "# === ABK-BPF PATCH END ($marker) ===" >> "$kcfg_file"

    echo "[ABK-BPF] 已 patch: $kcfg_file"
}

# --- 2.1 patch kernel/trace/Kconfig：强制 FUNCTION_TRACER 可用 ---
TRACE_KCFG="${KERNEL_SRC}/kernel/trace/Kconfig"
echo "[ABK-BPF] 检查 FUNCTION_TRACER Kconfig: $TRACE_KCFG"

if [[ -f "$TRACE_KCFG" ]]; then
    # 查看当前 FUNCTION_TRACER 定义
    echo "[ABK-BPF] 当前 FUNCTION_TRACER Kconfig 定义:"
    grep -A 12 "^config FUNCTION_TRACER" "$TRACE_KCFG" 2>/dev/null || echo "  (未找到 config FUNCTION_TRACER 条目)"

    if [[ ! -f "${TRACE_KCFG}.abk-bpf.bak" ]]; then
        cp "$TRACE_KCFG" "${TRACE_KCFG}.abk-bpf.bak"
    fi

    # 用 python 精确替换 config 块（比 awk 更可靠）
    # 策略：删除原 config FUNCTION_TRACER 块，追加新块（无 depends on，default y）
    python3 - "$TRACE_KCFG" <<'PYEOF'
import re, sys
path = sys.argv[1]
with open(path) as f:
    content = f.read()

new_block = '''config FUNCTION_TRACER
	bool "Function Tracer"
	default y
	help
	  Enable the function tracer.

config FTRACE_SYSCALLS
	bool "Trace syscalls"
	depends on FTRACE
	default y
	help
	  Enable tracing of syscalls.
'''

# 匹配 config FUNCTION_TRACER 块到下一个 config 或文件末尾
pattern = r'config FUNCTION_TRACER\b.*?(?=\nconfig [A-Z_]|\Z)'
content_new, n1 = re.subn(pattern, '', content, flags=re.DOTALL)

# 匹配 config FTRACE_SYSCALLS 块
pattern2 = r'config FTRACE_SYSCALLS\b.*?(?=\nconfig [A-Z_]|\Z)'
content_new, n2 = re.subn(pattern2, '', content_new, flags=re.DOTALL)

# 追加新块（在文件末尾）
if n1 > 0 or n2 > 0:
    content_new = content_new.rstrip() + '\n\n' + new_block
    with open(path, 'w') as f:
        f.write(content_new)
    print(f"[ABK-BPF] 已替换 FUNCTION_TRACER (n={n1}) 和 FTRACE_SYSCALLS (n={n2}) Kconfig 块")
else:
    # 没找到原块，直接追加
    with open(path, 'a') as f:
        f.write('\n\n' + new_block)
    print("[ABK-BPF] FUNCTION_TRACER/FTRACE_SYSCALLS 未找到原块，已追加新块")
PYEOF

    echo "[ABK-BPF] patch 后的 FUNCTION_TRACER 定义:"
    grep -A 6 "^config FUNCTION_TRACER" "$TRACE_KCFG" 2>/dev/null
else
    echo "[ABK-BPF][ERROR] kernel/trace/Kconfig 不存在: $TRACE_KCFG"
fi

# --- 2.2 patch security/Kconfig：添加 SECURITY_BPF 和 BPF_LSM 条目 ---
SEC_KCFG="${KERNEL_SRC}/security/Kconfig"
echo ""
echo "[ABK-BPF] 检查 SECURITY_BPF Kconfig: $SEC_KCFG"

if [[ -f "$SEC_KCFG" ]]; then
    # 检查是否已有 SECURITY_BPF 定义
    if grep -q "^config SECURITY_BPF" "$SEC_KCFG"; then
        echo "[ABK-BPF] SECURITY_BPF 已存在于 Kconfig（检查为何未生效）"
        grep -A 8 "^config SECURITY_BPF" "$SEC_KCFG"
    else
        echo "[ABK-BPF] SECURITY_BPF 不存在，添加 Kconfig 条目"
        SECURITY_BPF_KCFG='
config SECURITY_BPF
	bool "BPF MAC policy"
	depends on SECURITY
	depends on BPF_SYSCALL
	default y
	help
	  This enables the BPF MAC policy module which allows loading
	  of BPF programs for mandatory access control.

	  If you are unsure how to answer this question, answer N.

config SECURITY_BPF_HOOKS
	bool "BPF MAC policy hooks"
	depends on SECURITY_BPF
	default y
	help
	  This enables the BPF hooks for MAC policy.

config BPF_LSM
	bool "Enable BPF LSM"
	depends on SECURITY_BPF
	depends on BPF_SYSCALL
	default y
	help
	  Record LSM events as BPF events to allow BPF programs to
	  implement security policy.
'
        patch_kconfig "$SEC_KCFG" "SECURITY_BPF" "$SECURITY_BPF_KCFG"
    fi
else
    echo "[ABK-BPF][WARN] security/Kconfig 不存在"
fi

# --- 2.3 patch net/Kconfig：确保 BPF_STREAM_PARSER 可用 ---
NET_KCFG="${KERNEL_SRC}/net/Kconfig"
echo ""
echo "[ABK-BPF] 检查 BPF_STREAM_PARSER Kconfig: $NET_KCFG"

if [[ -f "$NET_KCFG" ]]; then
    if grep -q "^config BPF_STREAM_PARSER" "$NET_KCFG"; then
        echo "[ABK-BPF] BPF_STREAM_PARSER 已存在"
    else
        echo "[ABK-BPF] BPF_STREAM_PARSER 不存在，添加 Kconfig 条目"
        BPF_STREAM_PARSER_KCFG='
config BPF_STREAM_PARSER
	bool "enable BPF STREAM_PARSER"
	depends on INET
	depends on BPF_SYSCALL
	default y
	help
	  Allows BPF programs to be attached to stream sockets.
'
        patch_kconfig "$NET_KCFG" "BPF_STREAM_PARSER" "$BPF_STREAM_PARSER_KCFG"
    fi
else
    echo "[ABK-BPF][WARN] net/Kconfig 不存在"
fi

echo ""
echo "[ABK-BPF] === 第 3 步：诊断输出 ==="
echo "---------------------------------------------------"

# 验证 defconfig
echo "[ABK-BPF] defconfig 中的关键 CONFIG:"
for cfg in CONFIG_FUNCTION_TRACER CONFIG_DYNAMIC_FTRACE CONFIG_FTRACE_SYSCALLS \
           CONFIG_FUNCTION_ERROR_INJECTION CONFIG_SECURITY_BPF CONFIG_BPF_LSM \
           CONFIG_BPF_EVENTS CONFIG_BPF_STREAM_PARSER CONFIG_DEBUG_INFO_BTF; do
    result=$(grep "^${cfg}=" "$DEFCONFIG" 2>/dev/null || echo "未找到")
    printf "  %-50s %s\n" "$cfg" "$result"
done

echo ""
echo "[ABK-BPF] Kconfig 文件状态:"
for f in "$TRACE_KCFG" "$SEC_KCFG" "$NET_KCFG"; do
    if [[ -f "$f" ]]; then
        patched=$(grep -c "ABK-BPF PATCH" "$f" 2>/dev/null || echo 0)
        printf "  %-60s patched=%s\n" "$f" "$patched"
    fi
done

echo ""
echo "[ABK-BPF] === 完成 ==="
echo "[ABK-BPF] 注意事项："
echo "  1. FUNCTION_TRACER 已 patch Kconfig default y + defconfig y"
echo "  2. SECURITY_BPF 已添加 Kconfig 条目 + defconfig y"
echo "  3. BPF_KPROBE_OVERRIDE 在 arm64 无法启用（缺 HAVE_BPF_KPROBE_OVERRIDE）"
echo "  4. 如果编译失败，检查 Kconfig 语法错误"
echo "  5. 刷入后验证: zcat /proc/config.gz | grep -E 'BPF_LSM|FUNCTION_TRACER|SECURITY_BPF'"
echo "==================================================="
