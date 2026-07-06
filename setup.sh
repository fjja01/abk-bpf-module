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

# === 警告：FUNCTION_TRACER / FTRACE_SYSCALLS / DYNAMIC_FTRACE 已禁用 ===
# 原因：启用后卡第一屏（ftrace 早期启动死锁或 GKI ABI 校验失败）
# 改为保守策略：只启用 BPF LSM 相关，不动 ftrace 基础设施
# append_config "CONFIG_FUNCTION_TRACER" "y"
# append_config "CONFIG_DYNAMIC_FTRACE" "y"
# append_config "CONFIG_DYNAMIC_FTRACE_WITH_REGS" "y"
# append_config "CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS" "y"
# append_config "CONFIG_FTRACE_SYSCALLS" "y"

# 函数错误注入（已默认 y，保留以确保）
append_config "CONFIG_FUNCTION_ERROR_INJECTION" "y"
# 注意：BPF_KPROBE_OVERRIDE 在 arm64 上无法启用（缺 HAVE_BPF_KPROBE_OVERRIDE）
# append_config "CONFIG_BPF_KPROBE_OVERRIDE" "y"

# BPF LSM 安全模块（核心目标）
append_config "CONFIG_SECURITY_BPF" "y"
append_config "CONFIG_BPF_LSM" "y"

# 辅助可观测性选项（BPF 相关，安全）
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

# --- 2.1 跳过 FUNCTION_TRACER Kconfig patch ---
# 原因：启用 FUNCTION_TRACER 导致卡第一屏（ftrace 早期启动死锁或 GKI ABI 校验失败）
# 不再修改 kernel/trace/Kconfig
TRACE_KCFG="${KERNEL_SRC}/kernel/trace/Kconfig"
echo "[ABK-BPF] 跳过 FUNCTION_TRACER Kconfig patch（保守策略，避免卡 logo）"
echo "[ABK-BPF] kernel/trace/Kconfig 当前 FUNCTION_TRACER 状态（仅查询，不修改）:"
if [[ -f "$TRACE_KCFG" ]]; then
    grep -A 4 "^config FUNCTION_TRACER" "$TRACE_KCFG" 2>/dev/null || echo "  (未找到)"
else
    echo "  $TRACE_KCFG 不存在"
fi

# --- 2.1.5 修改 kernel/bpf/Kconfig：移除 BPF_LSM 依赖 + 添加 default y ---
# 诊断结论（2026-07-04，构建 28693529318）：
#   - BPF_LSM 依赖（BPF_EVENTS/BPF_SYSCALL/SECURITY/BPF_JIT）全部满足
#   - POST_DEFCONFIG_CMDS 成功设置 BPF_LSM=y
#   - 但随后的 make olddefconfig 仍然清除了 BPF_LSM（原因未知，疑似 GKI 隐藏机制）
#   - FUNCTION_ERROR_INJECTION 同样被清除（HAVE_FUNCTION_ERROR_INJECTION=y 已满足）
# 解决方案：直接修改 Kconfig 源码
#   1. 移除 BPF_LSM 的 depends on（让 olddefconfig 无法因依赖未满足而清除）
#   2. 添加 default y（让 olddefconfig 对新符号默认启用）
BPF_KCFG="${KERNEL_SRC}/kernel/bpf/Kconfig"
echo ""
echo "[ABK-BPF] 修改 BPF_LSM Kconfig: $BPF_KCFG"

if [[ -f "$BPF_KCFG" ]]; then
    if grep -q "ABK-BPF-BPF_LSM-MOD" "$BPF_KCFG" 2>/dev/null; then
        echo "[ABK-BPF] BPF_LSM Kconfig 已修改（跳过）"
    else
        # 备份
        if [[ ! -f "${BPF_KCFG}.abk-bpf.bak" ]]; then
            cp "$BPF_KCFG" "${BPF_KCFG}.abk-bpf.bak"
        fi

        echo "[ABK-BPF] 修改前 BPF_LSM 条目:"
        grep -A 8 "^config BPF_LSM$" "$BPF_KCFG" 2>/dev/null || echo "  (未找到)"

        # 使用 awk 修改 BPF_LSM 条目：
        # 1. 移除 depends on 行
        # 2. 在 bool 行后添加 default y（如果不存在）
        awk '
            BEGIN { in_entry=0; added_default=0 }
            /^config BPF_LSM$/ { in_entry=1 }
            in_entry && /^config / && !/^config BPF_LSM$/ { in_entry=0; added_default=0 }
            in_entry && /^menuconfig / { in_entry=0; added_default=0 }
            in_entry && /^endmenu/ { in_entry=0; added_default=0 }
            in_entry && /^\tdepends on/ { next }
            in_entry && /^\tbool/ && added_default==0 {
                print
                print "\tdefault y"
                added_default=1
                next
            }
            in_entry && /^\tdefault y/ && added_default==1 { next }
            { print }
        ' "$BPF_KCFG" > "${BPF_KCFG}.tmp" && mv "${BPF_KCFG}.tmp" "$BPF_KCFG"

        # 添加标记
        echo "# ABK-BPF-BPF_LSM-MOD: removed depends on, added default y" >> "$BPF_KCFG"

        echo "[ABK-BPF] 修改后 BPF_LSM 条目:"
        grep -A 8 "^config BPF_LSM$" "$BPF_KCFG" 2>/dev/null || echo "  (未找到)"
        echo "[ABK-BPF] 已修改 BPF_LSM Kconfig（移除 depends on，添加 default y）"
    fi
else
    echo "[ABK-BPF][ERROR] kernel/bpf/Kconfig 不存在: $BPF_KCFG"
fi

# --- 2.1.6 修改 lib/Kconfig.debug：移除 FUNCTION_ERROR_INJECTION 依赖 ---
DEBUG_KCFG="${KERNEL_SRC}/lib/Kconfig.debug"
echo ""
echo "[ABK-BPF] 修改 FUNCTION_ERROR_INJECTION Kconfig: $DEBUG_KCFG"

if [[ -f "$DEBUG_KCFG" ]]; then
    if grep -q "ABK-BPF-FUNC_ERR_INJ-MOD" "$DEBUG_KCFG" 2>/dev/null; then
        echo "[ABK-BPF] FUNCTION_ERROR_INJECTION Kconfig 已修改（跳过）"
    else
        # 备份
        if [[ ! -f "${DEBUG_KCFG}.abk-bpf.bak" ]]; then
            cp "$DEBUG_KCFG" "${DEBUG_KCFG}.abk-bpf.bak"
        fi

        echo "[ABK-BPF] 修改前 FUNCTION_ERROR_INJECTION 条目:"
        grep -A 6 "^config FUNCTION_ERROR_INJECTION$" "$DEBUG_KCFG" 2>/dev/null || echo "  (未找到)"

        # 移除 FUNCTION_ERROR_INJECTION 的 depends on 行
        awk '
            BEGIN { in_entry=0 }
            /^config FUNCTION_ERROR_INJECTION$/ { in_entry=1 }
            in_entry && /^config / && !/^config FUNCTION_ERROR_INJECTION$/ { in_entry=0 }
            in_entry && /^\tdepends on/ { next }
            { print }
        ' "$DEBUG_KCFG" > "${DEBUG_KCFG}.tmp" && mv "${DEBUG_KCFG}.tmp" "$DEBUG_KCFG"

        # 添加标记
        echo "# ABK-BPF-FUNC_ERR_INJ-MOD: removed depends on" >> "$DEBUG_KCFG"

        echo "[ABK-BPF] 修改后 FUNCTION_ERROR_INJECTION 条目:"
        grep -A 6 "^config FUNCTION_ERROR_INJECTION$" "$DEBUG_KCFG" 2>/dev/null || echo "  (未找到)"
        echo "[ABK-BPF] 已修改 FUNCTION_ERROR_INJECTION Kconfig（移除 depends on）"
    fi
else
    echo "[ABK-BPF][WARN] lib/Kconfig.debug 不存在: $DEBUG_KCFG"
    # 尝试在其他位置查找
    for alt_path in "${KERNEL_SRC}/kernel/trace/Kconfig" "${KERNEL_SRC}/lib/Kconfig.kasan"; do
        if [[ -f "$alt_path" ]] && grep -q "^config FUNCTION_ERROR_INJECTION$" "$alt_path" 2>/dev/null; then
            echo "[ABK-BPF] 在 $alt_path 找到 FUNCTION_ERROR_INJECTION"
            DEBUG_KCFG="$alt_path"
            break
        fi
    done
fi

# --- 2.1.7 搜索并修改 GKI ABI fragment ---
# GKI 内核可能通过 abi_gki_aarch64.config 等 fragment 强制禁用某些 CONFIG
# 这些 fragment 在 make gki_defconfig 时合并，可能导致 olddefconfig 清除我们的设置
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
        echo "[ABK-BPF] 检查 fragment: $frag"
        # 检查是否包含 BPF_LSM 或 FUNCTION_ERROR_INJECTION 的禁用行
        if grep -qE "(BPF_LSM|FUNCTION_ERROR_INJECTION)" "$frag" 2>/dev/null; then
            echo "[ABK-BPF] 发现相关配置行:"
            grep -nE "(BPF_LSM|FUNCTION_ERROR_INJECTION)" "$frag"
            # 备份
            if [[ ! -f "${frag}.abk-bpf.bak" ]]; then
                cp "$frag" "${frag}.abk-bpf.bak"
            fi
            # 移除禁用行
            sed -i '/BPF_LSM/d' "$frag"
            sed -i '/FUNCTION_ERROR_INJECTION/d' "$frag"
            echo "[ABK-BPF] 已从 $(basename "$frag") 移除 BPF_LSM/FUNCTION_ERROR_INJECTION 相关行"
        fi
    fi
done

# 也检查 build.config 中的 fragment 引用
BUILD_CONFIG_FILE="${BUILD_CONFIG:-${KERNEL_SRC}/build.config.gki.aarch64}"
if [[ -f "$BUILD_CONFIG_FILE" ]]; then
    echo "[ABK-BPF] 检查 build.config 中的 fragment 引用: $BUILD_CONFIG_FILE"
    grep -i "fragment\|DEFCONFIG" "$BUILD_CONFIG_FILE" 2>/dev/null || echo "  (无 fragment 引用)"
fi

if [[ $FRAGMENTS_FOUND -eq 0 ]]; then
    echo "[ABK-BPF] 未找到 GKI ABI fragment 文件"
fi

# --- 2.2 修改 build.config.gki.aarch64：添加 POST_DEFCONFIG_CMDS ---
# 诊断结论（2026-07-04）：
#   - BPF_LSM 定义在 kernel/bpf/Kconfig（不在 security/Kconfig）
#   - 依赖：BPF_EVENTS + BPF_SYSCALL + SECURITY + BPF_JIT（全部满足）
#   - 但 make olddefconfig 会把 defconfig 中的 BPF_LSM=y 清除（原因未知）
#   - SECURITY_BPF 在 GKI 内核中不存在（不需要）
# 解决方案：在 make olddefconfig 后用 POST_DEFCONFIG_CMDS 直接修改 .config
BUILD_CONFIG="${KERNEL_SRC}/build.config.gki.aarch64"
SEC_KCFG="${KERNEL_SRC}/security/Kconfig"
echo ""
echo "[ABK-BPF] 修改 build.config: $BUILD_CONFIG"

if [[ -f "$BUILD_CONFIG" ]]; then
    if grep -q "ABK_BPF_POST_DEFCONFIG" "$BUILD_CONFIG" 2>/dev/null; then
        echo "[ABK-BPF] build.config 已包含 POST_DEFCONFIG_CMDS（跳过）"
    else
        # 备份
        if [[ ! -f "${BUILD_CONFIG}.abk-bpf.bak" ]]; then
            cp "$BUILD_CONFIG" "${BUILD_CONFIG}.abk-bpf.bak"
        fi
        # 追加 POST_DEFCONFIG_CMDS
        # OUT_DIR 是 build/build.sh 设置的环境变量，指向输出目录的 common 子目录
        # 即 OUT_DIR=.../out/android13-5.15/common
        # .config 在 ${OUT_DIR}/.config（不要加 /common，否则路径重复）
        # 用 \${OUT_DIR} 转义，在 source 时不展开，在 eval 执行时展开
        # common/scripts/config -e 启用 CONFIG，-d 禁用 CONFIG
        # 注意：POST_DEFCONFIG_CMDS 不能以分号开头（build/build.sh 用 eval 执行会语法错误）
        # 如果 POST_DEFCONFIG_CMDS 已有值，用分号连接；否则直接赋值
        cat >> "$BUILD_CONFIG" <<'BCEOF'

# === ABK_BPF_POST_DEFCONFIG ===
# 在 make olddefconfig 后强制启用 BPF_LSM 和 FUNCTION_ERROR_INJECTION
# 原因：make olddefconfig 会清除 defconfig 中的 BPF_LSM=y（原因未知）
# BPF_LSM 依赖（BPF_EVENTS/BPF_SYSCALL/SECURITY/BPF_JIT）全部满足
# 注意：OUT_DIR 已指向 .../out/android13-5.15/common，不要再加 /common
if [ -z "${POST_DEFCONFIG_CMDS:-}" ]; then
  POST_DEFCONFIG_CMDS="common/scripts/config --file \${OUT_DIR}/.config -e BPF_LSM -e FUNCTION_ERROR_INJECTION"
else
  POST_DEFCONFIG_CMDS="${POST_DEFCONFIG_CMDS} ; common/scripts/config --file \${OUT_DIR}/.config -e BPF_LSM -e FUNCTION_ERROR_INJECTION"
fi
# === ABK_BPF_POST_DEFCONFIG END ===

# === ABK_BPF_PRE_BUILD_CMDS ===
# 在 make olddefconfig 和 ABI 处理之后、make Image 之前强制启用 BPF_LSM
# 诊断：POST_DEFCONFIG_CMDS 在 olddefconfig 之前执行，被 olddefconfig 覆盖
# PRE_BUILD_CMDS 在 olddefconfig 之后执行（如果 build/build.sh 支持）
if [ -z "${PRE_BUILD_CMDS:-}" ]; then
  PRE_BUILD_CMDS="common/scripts/config --file \${OUT_DIR}/.config -e BPF_LSM -e FUNCTION_ERROR_INJECTION"
else
  PRE_BUILD_CMDS="${PRE_BUILD_CMDS} ; common/scripts/config --file \${OUT_DIR}/.config -e BPF_LSM -e FUNCTION_ERROR_INJECTION"
fi
# === ABK_BPF_PRE_BUILD_CMDS END ===
BCEOF
        echo "[ABK-BPF] 已添加 POST_DEFCONFIG_CMDS 和 PRE_BUILD_CMDS 到 build.config"
        echo "[ABK-BPF] POST_DEFCONFIG_CMDS 内容:"
        grep -A 4 "ABK_BPF_POST_DEFCONFIG ===" "$BUILD_CONFIG" | tail -4
    fi
else
    echo "[ABK-BPF][ERROR] build.config.gki.aarch64 不存在: $BUILD_CONFIG"
fi

# 同时也 patch security/Kconfig 添加 SECURITY_BPF（作为兼容，即使 BPF_LSM 不依赖它）
# 注意：这是可选的，BPF_LSM 在 GKI 内核中不依赖 SECURITY_BPF
if [[ -f "$SEC_KCFG" ]]; then
    if grep -q "^config SECURITY_BPF" "$SEC_KCFG"; then
        echo "[ABK-BPF] SECURITY_BPF 已存在于 security/Kconfig"
    else
        echo "[ABK-BPF] SECURITY_BPF 不存在于 security/Kconfig（GKI 移除了，不影响 BPF_LSM）"
    fi
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

# --- 2.5 修改 build/build.sh：在 olddefconfig 之后插入 config 修改 ---
# 诊断结论（2026-07-04，构建 28699313001）：
#   - POST_DEFCONFIG_CMDS 在 make olddefconfig 之前执行（名为 "post defconfig" 但实际是 "pre olddefconfig"）
#   - make olddefconfig 会覆盖 POST_DEFCONFIG_CMDS 设置的 BPF_LSM=y
#   - 即使修改了 Kconfig 源码（移除 depends on + 添加 default y），olddefconfig 仍然清除 BPF_LSM
#   - 第3次 config write 发生在 ABI symbol list generation 过程中，可能也回退了 BPF_LSM
# 解决方案：直接修改 build/build.sh，在 olddefconfig 之后和 "Building kernel" 之后插入 config 修改
BUILD_SH="${KERNEL_ROOT}/build/build.sh"
echo ""
echo "[ABK-BPF] === 第 2.5 步：修改 build/build.sh ==="
echo "---------------------------------------------------"
echo "[ABK-BPF] 检查 build/build.sh: $BUILD_SH"

if [[ -f "$BUILD_SH" ]]; then
    if grep -q "ABK_BPF_POST_OLDDEFCONFIG" "$BUILD_SH" 2>/dev/null; then
        echo "[ABK-BPF] build/build.sh 已修改（跳过）"
    else
        # 备份
        if [[ ! -f "${BUILD_SH}.abk-bpf.bak" ]]; then
            cp "$BUILD_SH" "${BUILD_SH}.abk-bpf.bak"
        fi

        # 检查 olddefconfig 出现次数
        OLDDEFCONFIG_COUNT=$(grep -c 'make.*olddefconfig' "$BUILD_SH" 2>/dev/null || echo 0)
        echo "[ABK-BPF] build/build.sh 中 'make.*olddefconfig' 出现次数: $OLDDEFCONFIG_COUNT"

        # 检查 Building kernel 出现次数
        BUILDING_COUNT=$(grep -c 'Building kernel' "$BUILD_SH" 2>/dev/null || echo 0)
        echo "[ABK-BPF] build/build.sh 中 'Building kernel' 出现次数: $BUILDING_COUNT"

        # 用 awk 修改 build/build.sh：
        # 1. 在 olddefconfig 行之后插入 config 修改（防止 olddefconfig 回退）
        # 2. 在 "Building kernel" 行之后插入 config 修改（防止 ABI syncconfig 回退）
        awk '
            /make.*olddefconfig/ && !inserted_olddefconfig {
                print
                print "    # ABK_BPF_POST_OLDDEFCONFIG"
                print "    common/scripts/config --file ${OUT_DIR}/.config -e BPF_LSM -e FUNCTION_ERROR_INJECTION"
                print "    # ABK_BPF_POST_OLDDEFCONFIG END"
                inserted_olddefconfig=1
                next
            }
            /Building kernel/ && !inserted_building {
                print
                print "    # ABK_BPF_PRE_BUILD_CONFIG"
                print "    common/scripts/config --file ${OUT_DIR}/.config -e BPF_LSM -e FUNCTION_ERROR_INJECTION"
                print "    # ABK_BPF_PRE_BUILD_CONFIG END"
                inserted_building=1
                next
            }
            { print }
        ' "$BUILD_SH" > "${BUILD_SH}.tmp" && mv "${BUILD_SH}.tmp" "$BUILD_SH"

        echo "[ABK-BPF] 已修改 build/build.sh"
        echo "[ABK-BPF] 修改后 olddefconfig 附近的代码:"
        grep -A 3 "olddefconfig" "$BUILD_SH" 2>/dev/null | head -10
        echo ""
        echo "[ABK-BPF] 修改后 Building kernel 附近的代码:"
        grep -A 3 "Building kernel" "$BUILD_SH" 2>/dev/null | head -10
    fi
else
    echo "[ABK-BPF][WARN] build/build.sh 不存在: $BUILD_SH"
    # 尝试其他路径
    for alt_path in "${KERNEL_SRC}/build/build.sh" "${KERNEL_ROOT}/build.sh"; do
        if [[ -f "$alt_path" ]]; then
            echo "[ABK-BPF] 在 $alt_path 找到 build.sh"
            BUILD_SH="$alt_path"
            break
        fi
    done
fi

echo ""
echo "[ABK-BPF] === 第 3 步：诊断输出 ==="
echo "---------------------------------------------------"

# 验证 defconfig
echo "[ABK-BPF] defconfig 中的关键 CONFIG:"
for cfg in CONFIG_FUNCTION_ERROR_INJECTION CONFIG_BPF_LSM \
           CONFIG_BPF_EVENTS CONFIG_BPF_STREAM_PARSER CONFIG_DEBUG_INFO_BTF \
           CONFIG_DEBUG_INFO_BTF_MODULES; do
    result=$(grep "^${cfg}=" "$DEFCONFIG" 2>/dev/null || echo "未找到")
    printf "  %-50s %s\n" "$cfg" "$result"
done

echo ""
echo "[ABK-BPF] 已禁用的 CONFIG（避免卡 logo）:"
for cfg in CONFIG_FUNCTION_TRACER CONFIG_FTRACE_SYSCALLS CONFIG_DYNAMIC_FTRACE; do
    result=$(grep "^${cfg}=" "$DEFCONFIG" 2>/dev/null || echo "(未启用)")
    printf "  %-50s %s\n" "$cfg" "$result"
done

echo ""
echo "[ABK-BPF] build.config 状态:"
if [[ -f "$BUILD_CONFIG" ]]; then
    has_post=$(grep -c "ABK_BPF_POST_DEFCONFIG" "$BUILD_CONFIG" 2>/dev/null || echo 0)
    has_pre=$(grep -c "ABK_BPF_PRE_BUILD_CMDS" "$BUILD_CONFIG" 2>/dev/null || echo 0)
    printf "  %-60s POST_DEFCONFIG_CMDS=%s\n" "$BUILD_CONFIG" "$has_post"
    printf "  %-60s PRE_BUILD_CMDS=%s\n" "$BUILD_CONFIG" "$has_pre"
fi

echo ""
echo "[ABK-BPF] build/build.sh 状态:"
if [[ -f "$BUILD_SH" ]]; then
    has_olddefconfig=$(grep -c "ABK_BPF_POST_OLDDEFCONFIG" "$BUILD_SH" 2>/dev/null || echo 0)
    has_building=$(grep -c "ABK_BPF_PRE_BUILD_CONFIG" "$BUILD_SH" 2>/dev/null || echo 0)
    printf "  %-60s POST_OLDDEFCONFIG=%s\n" "$BUILD_SH" "$has_olddefconfig"
    printf "  %-60s PRE_BUILD_CONFIG=%s\n" "$BUILD_SH" "$has_building"
fi

echo ""
echo "[ABK-BPF] Kconfig 文件状态:"
for f in "$NET_KCFG" "$BPF_KCFG" "$DEBUG_KCFG"; do
    if [[ -f "$f" ]]; then
        patched=$(grep -c "ABK-BPF" "$f" 2>/dev/null || echo 0)
        printf "  %-60s patched=%s\n" "$f" "$patched"
    fi
done

echo ""
echo "[ABK-BPF] BPF_LSM Kconfig 条目（修改后）:"
if [[ -f "$BPF_KCFG" ]]; then
    grep -A 6 "^config BPF_LSM$" "$BPF_KCFG" 2>/dev/null || echo "  (未找到)"
fi

echo ""
echo "[ABK-BPF] FUNCTION_ERROR_INJECTION Kconfig 条目（修改后）:"
if [[ -f "$DEBUG_KCFG" ]]; then
    grep -A 4 "^config FUNCTION_ERROR_INJECTION$" "$DEBUG_KCFG" 2>/dev/null || echo "  (未找到)"
fi

echo ""
echo "[ABK-BPF] === 完成 ==="
echo "[ABK-BPF] 策略说明："
echo "  1. FUNCTION_TRACER/FTRACE_SYSCALLS/DYNAMIC_FTRACE 已禁用（启用后卡第一屏）"
echo "  2. BPF_LSM: 修改 Kconfig 移除 depends on + 添加 default y"
echo "  3. FUNCTION_ERROR_INJECTION: 修改 Kconfig 移除 depends on"
echo "  4. POST_DEFCONFIG_CMDS: 在 olddefconfig 之前设置 BPF_LSM=y（被覆盖）"
echo "  5. PRE_BUILD_CMDS: 在 olddefconfig 之后设置 BPF_LSM=y（新策略）"
echo "  6. 修改 build/build.sh: 在 olddefconfig 和 Building kernel 之后插入 config 修改（新策略）"
echo "  7. 搜索并修改 GKI ABI fragment（防止强制禁用）"
echo "  8. BPF_KPROBE_OVERRIDE 在 arm64 无法启用（缺 HAVE_BPF_KPROBE_OVERRIDE）"
echo "  9. 刷入后验证: zcat /proc/config.gz | grep -E 'BPF_LSM|FUNCTION_ERROR_INJECTION'"
echo "==================================================="
