#!/usr/bin/env bash
# ABK 自定义外部模块：为 GKI 5.15 内核追加激进 eBPF 增强
# 阶段：after_patch（在 SUSFS/SukiSU 等内置补丁之后执行）
# 设备：Xiaomi Redmi K70 Pro (vermeer) / android13-5.15.119
#
# 激进版策略：基于之前构建经验，启用尽可能多的 eBPF 功能
#   - BPF_LSM=y（已验证可工作，通过 AK3 刷入）
#   - FUNCTION_ERROR_INJECTION=y（已验证可工作）
#   - FUNCTION_TRACER=y（之前导致 bootloop，但当时 Kconfig 未正确 patch，重试）
#   - DYNAMIC_FTRACE + WITH_REGS + WITH_DIRECT_CALLS（fentry/fexit BPF 需要）
#   - HIST_TRIGGERS / TRACING_MAP（BPF histogram）
#   - CGROUP_BPF / NET_ACT_BPF（网络 BPF）
#
# 关键经验：
#   1. PRE_BUILD_CMDS 在 olddefconfig 之后执行（主要策略）
#   2. Kconfig 修改需要移除 depends on + 添加 default y
#   3. 不要修改 build/build.sh（会破坏内部逻辑）
#   4. BPF_LSM 通过 AK3 刷入 slot _a 可正常启动
#   5. FUNCTION_TRACER 之前 bootloop，但当时未 patch Kconfig

set -euo pipefail

echo "==================================================="
echo "[ABK-BPF] 激进版 eBPF 增强（defconfig + Kconfig）"
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

# 定位内核源码根目录
KERNEL_SRC=""
if [[ -n "${KERNEL_ROOT:-}" ]]; then
    KERNEL_SRC="${KERNEL_ROOT}/common"
fi
if [[ ! -d "$KERNEL_SRC" ]]; then
    KERNEL_SRC=""
fi

if [[ -z "$KERNEL_SRC" ]] && [[ -n "${DEFCONFIG:-}" ]]; then
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
    exit 1
fi

echo "[ABK-BPF] 内核源码根: $KERNEL_SRC"

# 验证源码根目录结构
for subdir in kernel security net; do
    if [[ ! -d "$KERNEL_SRC/$subdir" ]]; then
        echo "[ABK-BPF][WARN] $KERNEL_SRC/$subdir 不存在"
    fi
done

# 备份原始 defconfig
BACKUP="${DEFCONFIG}.abk-bpf.bak"
if [[ ! -f "$BACKUP" ]]; then
    cp "$DEFCONFIG" "$BACKUP"
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

# 通用 Kconfig patch 函数：为指定 config 条目添加 default y 并移除 depends on
patch_kconfig_default_y() {
    local kcfg_file="$1"
    local config_name="$2"
    local marker="$3"

    if [[ ! -f "$kcfg_file" ]]; then
        echo "[ABK-BPF][WARN] Kconfig 文件不存在: $kcfg_file"
        return 0
    fi

    if grep -q "$marker" "$kcfg_file" 2>/dev/null; then
        echo "[ABK-BPF] 已 patch (跳过): $config_name in $kcfg_file"
        return 0
    fi

    if [[ ! -f "${kcfg_file}.abk-bpf.bak" ]]; then
        cp "$kcfg_file" "${kcfg_file}.abk-bpf.bak"
    fi

    echo "[ABK-BPF] 修改前 $config_name 条目:"
    grep -A 8 "^config ${config_name}$" "$kcfg_file" 2>/dev/null || echo "  (未找到)"

    # 使用 awk 修改：
    # 1. 移除 depends on 行
    # 2. 在 bool/def_bool 行后添加 default y
    awk -v cfg="config ${config_name}" -v marker="$marker" '
        BEGIN { in_entry=0; added_default=0 }
        $0 ~ "^" cfg "$" { in_entry=1 }
        in_entry && /^config / && $0 !~ "^" cfg "$" { in_entry=0; added_default=0 }
        in_entry && /^menuconfig / { in_entry=0; added_default=0 }
        in_entry && /^endmenu/ { in_entry=0; added_default=0 }
        in_entry && /^\tdepends on/ { next }
        in_entry && /^\t(def_)?bool/ && added_default==0 {
            print
            print "\tdefault y"
            added_default=1
            next
        }
        in_entry && /^\tdefault y$/ && added_default==1 { next }
        { print }
    ' "$kcfg_file" > "${kcfg_file}.tmp" && mv "${kcfg_file}.tmp" "$kcfg_file"

    echo "# ${marker}: removed depends on, added default y" >> "$kcfg_file"

    echo "[ABK-BPF] 修改后 $config_name 条目:"
    grep -A 6 "^config ${config_name}$" "$kcfg_file" 2>/dev/null || echo "  (未找到)"
    echo "[ABK-BPF] 已修改 $config_name Kconfig（移除 depends on，添加 default y）"
}

echo ""
echo "[ABK-BPF] === 第 1 步：修改 defconfig（激进版） ==="
echo "---------------------------------------------------"

# === A. 核心 BPF 功能 ===
append_config "CONFIG_BPF_SYSCALL" "y"
append_config "CONFIG_BPF_JIT" "y"
append_config "CONFIG_BPF_JIT_ALWAYS_ON" "y"
append_config "CONFIG_BPF_JIT_DEFAULT_ON" "y"
append_config "CONFIG_BPF_EVENTS" "y"
append_config "CONFIG_BPF_STREAM_PARSER" "y"
append_config "CONFIG_BPF_LSM" "y"
append_config "CONFIG_SECURITY_BPF" "y"
append_config "CONFIG_FUNCTION_ERROR_INJECTION" "y"
append_config "CONFIG_DEBUG_INFO_BTF" "y"
append_config "CONFIG_DEBUG_INFO_BTF_MODULES" "y"

# === B. ftrace 基础设施（激进：重试 FUNCTION_TRACER） ===
# 之前 bootloop 可能是因为未 patch Kconfig，这次同时 patch Kconfig
append_config "CONFIG_FUNCTION_TRACER" "y"
append_config "CONFIG_DYNAMIC_FTRACE" "y"
append_config "CONFIG_DYNAMIC_FTRACE_WITH_REGS" "y"
append_config "CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS" "y"
append_config "CONFIG_DYNAMIC_FTRACE_WITH_ARGS" "y"
append_config "CONFIG_FTRACE_SYSCALLS" "y"
append_config "CONFIG_FUNCTION_GRAPH_TRACER" "y"
append_config "CONFIG_STACK_TRACER" "y"
append_config "CONFIG_FUNCTION_PROFILER" "y"

# === C. kprobes / uprobes ===
append_config "CONFIG_KPROBES" "y"
append_config "CONFIG_KRETPROBES" "y"
append_config "CONFIG_UPROBES" "y"
append_config "CONFIG_UPROBE_EVENTS" "y"
append_config "CONFIG_KPROBE_EVENTS" "y"

# === D. tracing 基础设施 ===
append_config "CONFIG_TRACING" "y"
append_config "CONFIG_EVENT_TRACING" "y"
append_config "CONFIG_CONTEXT_SWITCH_TRACER" "y"
append_config "CONFIG_TRACING_MAP" "y"
append_config "CONFIG_HIST_TRIGGERS" "y"
append_config "CONFIG_BRANCH_TRACER" "y"
append_config "CONFIG_HW_BRANCH_TRACER" "y"
append_config "CONFIG_TRACE_CLOCK" "y"

# === E. 网络 BPF ===
append_config "CONFIG_CGROUP_BPF" "y"
append_config "CONFIG_NET_ACT_BPF" "y"
append_config "CONFIG_NET_SCH_BPF" "y"
append_config "CONFIG_XDP_SOCKETS" "y"

# === F. perf / 可观测性 ===
append_config "CONFIG_PERF_EVENTS" "y"
append_config "CONFIG_TRACEPOINTS" "y"
append_config "CONFIG_STACKTRACE" "y"
append_config "CONFIG_FRAME_POINTER" "y"

# === G. 调试信息 ===
append_config "CONFIG_KALLSYMS" "y"
append_config "CONFIG_KALLSYMS_ALL" "y"
append_config "CONFIG_KALLSYMS_BASE_RELATIVE" "y"
append_config "CONFIG_DEBUG_INFO" "y"
append_config "CONFIG_DEBUG_INFO_DWARF" "y"

# === H. 安全模块（BPF_LSM 需要） ===
append_config "CONFIG_SECURITY" "y"
append_config "CONFIG_SECURITYFS" "y"
append_config "CONFIG_SECURITY_NETWORK" "y"
append_config "CONFIG_LSM" "string"
# 注意：LSM 是 string 类型，需要特殊处理
sed -i '/^CONFIG_LSM=/d' "$DEFCONFIG"
echo 'CONFIG_LSM="lockdown,capability,yama,loadpin,safesetid,bpf"' >> "$DEFCONFIG"
echo "[ABK-BPF] defconfig: CONFIG_LSM=\"...,bpf\""

# === I. BPF 系统调用相关 ===
append_config "CONFIG_BPF_UNPRIV_DEFAULT_OFF" "y"

echo ""
echo "[ABK-BPF] === 第 2 步：patch Kconfig 源码 ==="
echo "---------------------------------------------------"

# --- 2.1 patch kernel/bpf/Kconfig：BPF_LSM 移除依赖 + default y ---
BPF_KCFG="${KERNEL_SRC}/kernel/bpf/Kconfig"
echo ""
echo "[ABK-BPF] --- patch BPF_LSM ---"
patch_kconfig_default_y "$BPF_KCFG" "BPF_LSM" "ABK-BPF-BPF_LSM-MOD"

# --- 2.2 patch lib/Kconfig.debug：FUNCTION_ERROR_INJECTION 移除依赖 ---
DEBUG_KCFG="${KERNEL_SRC}/lib/Kconfig.debug"
echo ""
echo "[ABK-BPF] --- patch FUNCTION_ERROR_INJECTION ---"
patch_kconfig_default_y "$DEBUG_KCFG" "FUNCTION_ERROR_INJECTION" "ABK-BPF-FUNC_ERR_INJ-MOD"

# --- 2.3 patch kernel/trace/Kconfig：FUNCTION_TRACER + DYNAMIC_FTRACE ---
# 激进策略：patch trace Kconfig，添加 default y
TRACE_KCFG="${KERNEL_SRC}/kernel/trace/Kconfig"
echo ""
echo "[ABK-BPF] --- patch FUNCTION_TRACER ---"
patch_kconfig_default_y "$TRACE_KCFG" "FUNCTION_TRACER" "ABK-BPF-FUNC_TRACER-MOD"

echo ""
echo "[ABK-BPF] --- patch DYNAMIC_FTRACE ---"
patch_kconfig_default_y "$TRACE_KCFG" "DYNAMIC_FTRACE" "ABK-BPF-DYN_FTRACE-MOD"

echo ""
echo "[ABK-BPF] --- patch DYNAMIC_FTRACE_WITH_REGS ---"
patch_kconfig_default_y "$TRACE_KCFG" "DYNAMIC_FTRACE_WITH_REGS" "ABK-BPF-DYN_FTRACE_REGS-MOD"

echo ""
echo "[ABK-BPF] --- patch DYNAMIC_FTRACE_WITH_DIRECT_CALLS ---"
patch_kconfig_default_y "$TRACE_KCFG" "DYNAMIC_FTRACE_WITH_DIRECT_CALLS" "ABK-BPF-DYN_FTRACE_DIRECT-MOD"

echo ""
echo "[ABK-BPF] --- patch FTRACE_SYSCALLS ---"
patch_kconfig_default_y "$TRACE_KCFG" "FTRACE_SYSCALLS" "ABK-BPF-FTRACE_SYSCALLS-MOD"

echo ""
echo "[ABK-BPF] --- patch FUNCTION_GRAPH_TRACER ---"
patch_kconfig_default_y "$TRACE_KCFG" "FUNCTION_GRAPH_TRACER" "ABK-BPF-FUNC_GRAPH_TRACER-MOD"

# --- 2.4 patch net/Kconfig：BPF_STREAM_PARSER ---
NET_KCFG="${KERNEL_SRC}/net/Kconfig"
echo ""
echo "[ABK-BPF] --- 检查 BPF_STREAM_PARSER ---"
if [[ -f "$NET_KCFG" ]]; then
    if grep -q "^config BPF_STREAM_PARSER" "$NET_KCFG"; then
        echo "[ABK-BPF] BPF_STREAM_PARSER 已存在"
    else
        echo "[ABK-BPF] 添加 BPF_STREAM_PARSER 到 net/Kconfig"
        if [[ ! -f "${NET_KCFG}.abk-bpf.bak" ]]; then
            cp "$NET_KCFG" "${NET_KCFG}.abk-bpf.bak"
        fi
        cat >> "$NET_KCFG" <<'BPEOF'

config BPF_STREAM_PARSER
	bool "enable BPF STREAM_PARSER"
	depends on INET
	depends on BPF_SYSCALL
	default y
	help
	  Allows BPF programs to be attached to stream sockets.
# ABK-BPF-BPF_STREAM_PARSER-MOD: added
BPEOF
        echo "[ABK-BPF] 已添加 BPF_STREAM_PARSER"
    fi
fi

# --- 2.5 搜索并修改 GKI ABI fragment ---
echo ""
echo "[ABK-BPF] 搜索 GKI ABI fragment..."
FRAGMENTS_FOUND=0
for frag in \
    "${KERNEL_SRC}/arch/arm64/configs/abi_gki_aarch64"*.config \
    "${KERNEL_SRC}/arch/arm64/configs/abi_gki_aarch64"*.fragment \
    "${KERNEL_SRC}/arch/arm64/configs/"*gki*.fragment \
    "${KERNEL_SRC}/arch/arm64/configs/"*gki*.config; do
    if [[ -f "$frag" ]]; then
        FRAGMENTS_FOUND=$((FRAGMENTS_FOUND + 1))
        echo "[ABK-BPF] 检查 fragment: $(basename "$frag")"
        if grep -qE "(BPF_LSM|FUNCTION_ERROR_INJECTION|FUNCTION_TRACER|DYNAMIC_FTRACE|FTRACE_SYSCALLS)" "$frag" 2>/dev/null; then
            echo "[ABK-BPF] 发现相关配置行，移除中..."
            if [[ ! -f "${frag}.abk-bpf.bak" ]]; then
                cp "$frag" "${frag}.abk-bpf.bak"
            fi
            sed -i '/BPF_LSM/d' "$frag"
            sed -i '/FUNCTION_ERROR_INJECTION/d' "$frag"
            sed -i '/FUNCTION_TRACER/d' "$frag"
            sed -i '/DYNAMIC_FTRACE/d' "$frag"
            sed -i '/FTRACE_SYSCALLS/d' "$frag"
            echo "[ABK-BPF] 已从 $(basename "$frag") 移除相关禁用行"
        fi
    fi
done
if [[ $FRAGMENTS_FOUND -eq 0 ]]; then
    echo "[ABK-BPF] 未找到 GKI ABI fragment 文件"
fi

# --- 2.6 修改 build.config.gki.aarch64 ---
BUILD_CONFIG="${KERNEL_SRC}/build.config.gki.aarch64"
echo ""
echo "[ABK-BPF] 修改 build.config: $BUILD_CONFIG"

if [[ -f "$BUILD_CONFIG" ]]; then
    if grep -q "ABK_BPF_PRE_BUILD_CMDS" "$BUILD_CONFIG" 2>/dev/null; then
        echo "[ABK-BPF] build.config 已包含 PRE_BUILD_CMDS（跳过）"
    else
        if [[ ! -f "${BUILD_CONFIG}.abk-bpf.bak" ]]; then
            cp "$BUILD_CONFIG" "${BUILD_CONFIG}.abk-bpf.bak"
        fi
        cat >> "$BUILD_CONFIG" <<'BCEOF'

# === ABK_BPF_POST_DEFCONFIG ===
# 在 make olddefconfig 后强制启用（备份策略，可能被 olddefconfig 覆盖）
if [ -z "${POST_DEFCONFIG_CMDS:-}" ]; then
  POST_DEFCONFIG_CMDS="common/scripts/config --file \${OUT_DIR}/.config -e BPF_LSM -e FUNCTION_ERROR_INJECTION -e FUNCTION_TRACER -e DYNAMIC_FTRACE -e DYNAMIC_FTRACE_WITH_REGS -e DYNAMIC_FTRACE_WITH_DIRECT_CALLS -e FTRACE_SYSCALLS -e FUNCTION_GRAPH_TRACER -e BPF_EVENTS -e BPF_STREAM_PARSER -e HIST_TRIGGERS -e TRACING_MAP -e CGROUP_BPF -e NET_ACT_BPF"
else
  POST_DEFCONFIG_CMDS="${POST_DEFCONFIG_CMDS} ; common/scripts/config --file \${OUT_DIR}/.config -e BPF_LSM -e FUNCTION_ERROR_INJECTION -e FUNCTION_TRACER -e DYNAMIC_FTRACE -e DYNAMIC_FTRACE_WITH_REGS -e DYNAMIC_FTRACE_WITH_DIRECT_CALLS -e FTRACE_SYSCALLS -e FUNCTION_GRAPH_TRACER -e BPF_EVENTS -e BPF_STREAM_PARSER -e HIST_TRIGGERS -e TRACING_MAP -e CGROUP_BPF -e NET_ACT_BPF"
fi
# === ABK_BPF_POST_DEFCONFIG END ===

# === ABK_BPF_PRE_BUILD_CMDS ===
# 在 make olddefconfig 之后、make Image 之前执行（主要策略）
if [ -z "${PRE_BUILD_CMDS:-}" ]; then
  PRE_BUILD_CMDS="common/scripts/config --file \${OUT_DIR}/.config -e BPF_LSM -e FUNCTION_ERROR_INJECTION -e FUNCTION_TRACER -e DYNAMIC_FTRACE -e DYNAMIC_FTRACE_WITH_REGS -e DYNAMIC_FTRACE_WITH_DIRECT_CALLS -e FTRACE_SYSCALLS -e FUNCTION_GRAPH_TRACER -e BPF_EVENTS -e BPF_STREAM_PARSER -e HIST_TRIGGERS -e TRACING_MAP -e CGROUP_BPF -e NET_ACT_BPF"
else
  PRE_BUILD_CMDS="${PRE_BUILD_CMDS} ; common/scripts/config --file \${OUT_DIR}/.config -e BPF_LSM -e FUNCTION_ERROR_INJECTION -e FUNCTION_TRACER -e DYNAMIC_FTRACE -e DYNAMIC_FTRACE_WITH_REGS -e DYNAMIC_FTRACE_WITH_DIRECT_CALLS -e FTRACE_SYSCALLS -e FUNCTION_GRAPH_TRACER -e BPF_EVENTS -e BPF_STREAM_PARSER -e HIST_TRIGGERS -e TRACING_MAP -e CGROUP_BPF -e NET_ACT_BPF"
fi
# === ABK_BPF_PRE_BUILD_CMDS END ===
BCEOF
        echo "[ABK-BPF] 已添加 POST_DEFCONFIG_CMDS 和 PRE_BUILD_CMDS（激进版）"
    fi
else
    echo "[ABK-BPF][ERROR] build.config.gki.aarch64 不存在"
fi

echo ""
echo "[ABK-BPF] === 第 3 步：诊断输出 ==="
echo "---------------------------------------------------"

echo "[ABK-BPF] defconfig 中的关键 CONFIG:"
for cfg in CONFIG_BPF_LSM CONFIG_FUNCTION_ERROR_INJECTION \
           CONFIG_FUNCTION_TRACER CONFIG_DYNAMIC_FTRACE \
           CONFIG_DYNAMIC_FTRACE_WITH_REGS CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS \
           CONFIG_FTRACE_SYSCALLS CONFIG_FUNCTION_GRAPH_TRACER \
           CONFIG_BPF_EVENTS CONFIG_BPF_STREAM_PARSER \
           CONFIG_HIST_TRIGGERS CONFIG_TRACING_MAP \
           CONFIG_CGROUP_BPF CONFIG_NET_ACT_BPF \
           CONFIG_DEBUG_INFO_BTF CONFIG_KALLSYMS_ALL; do
    result=$(grep "^${cfg}=" "$DEFCONFIG" 2>/dev/null || echo "未找到")
    printf "  %-55s %s\n" "$cfg" "$result"
done

echo ""
echo "[ABK-BPF] Kconfig 文件 patch 状态:"
for f in "$BPF_KCFG" "$DEBUG_KCFG" "$TRACE_KCFG" "$NET_KCFG"; do
    if [[ -f "$f" ]]; then
        patched=$(grep -c "ABK-BPF" "$f" 2>/dev/null || echo 0)
        printf "  %-60s patched=%s\n" "$f" "$patched"
    fi
done

echo ""
echo "[ABK-BPF] build.config 状态:"
if [[ -f "$BUILD_CONFIG" ]]; then
    has_post=$(grep -c "ABK_BPF_POST_DEFCONFIG" "$BUILD_CONFIG" 2>/dev/null || echo 0)
    has_pre=$(grep -c "ABK_BPF_PRE_BUILD_CMDS" "$BUILD_CONFIG" 2>/dev/null || echo 0)
    printf "  POST_DEFCONFIG_CMDS=%s\n" "$has_post"
    printf "  PRE_BUILD_CMDS=%s\n" "$has_pre"
fi

echo ""
echo "[ABK-BPF] === 完成（激进版） ==="
echo "[ABK-BPF] 启用功能清单："
echo "  [核心] BPF_LSM / FUNCTION_ERROR_INJECTION / SECURITY_BPF"
echo "  [核心] BPF_SYSCALL / BPF_JIT / BPF_EVENTS / BPF_STREAM_PARSER"
echo "  [核心] DEBUG_INFO_BTF / DEBUG_INFO_BTF_MODULES"
echo "  [ftrace] FUNCTION_TRACER / DYNAMIC_FTRACE / WITH_REGS / WITH_DIRECT_CALLS"
echo "  [ftrace] FTRACE_SYSCALLS / FUNCTION_GRAPH_TRACER / STACK_TRACER"
echo "  [tracing] HIST_TRIGGERS / TRACING_MAP / EVENT_TRACING"
echo "  [kprobe] KPROBES / KRETPROBES / KPROBE_EVENTS / UPROBE_EVENTS"
echo "  [网络] CGROUP_BPF / NET_ACT_BPF / NET_SCH_BPF / XDP_SOCKETS"
echo "  [调试] KALLSYMS_ALL / DEBUG_INFO / FRAME_POINTER / STACKTRACE"
echo "  [安全] SECURITY / SECURITYFS / SECURITY_NETWORK / LSM(bpf)"
echo ""
echo "[ABK-BPF] 策略：Kconfig patch + defconfig + POST_DEFCONFIG_CMDS + PRE_BUILD_CMDS"
echo "[ABK-BPF] 风险：FUNCTION_TRACER 可能导致 bootloop（之前发生过）"
echo "[ABK-BPF] 救砖：fastboot flash:raw boot_a boot-original-backup.img"
echo "==================================================="
