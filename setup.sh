#!/usr/bin/env bash
# ABK 自定义外部模块：为 GKI 5.15 内核追加 eBPF 增强 CONFIG
# 阶段：after_patch（在 SUSFS/SukiSU 等内置补丁之后执行）
# 目标：启用 BPF_LSM、FUNCTION_TRACER、BPF_KPROBE_OVERRIDE 等限制项
# 设备：Xiaomi Redmi K70 Pro (vermeer) / android13-5.15.119

set -euo pipefail

echo "==================================================="
echo "[ABK-BPF] 开始应用 eBPF 增强 CONFIG"
echo "==================================================="

# 检查关键环境变量
if [[ -z "${DEFCONFIG:-}" ]]; then
    echo "[ABK-BPF][ERROR] DEFCONFIG 环境变量未设置"
    echo "[ABK-BPF][ERROR] 请确认阶段为 after_patch 或 before_build"
    exit 1
fi

if [[ ! -f "$DEFCONFIG" ]]; then
    echo "[ABK-BPF][ERROR] defconfig 文件不存在: $DEFCONFIG"
    exit 1
fi

echo "[ABK-BPF] 目标 defconfig: $DEFCONFIG"
echo "[ABK-BPF] CONFIG 变量:    ${CONFIG:-未知}"
echo "[ABK-BPF] KERNEL_ROOT:    ${KERNEL_ROOT:-未知}"

# 备份原始 defconfig
BACKUP="${DEFCONFIG}.abk-bpf.bak"
if [[ ! -f "$BACKUP" ]]; then
    cp "$DEFCONFIG" "$BACKUP"
    echo "[ABK-BPF] 已备份原始 defconfig 到: $BACKUP"
else
    echo "[ABK-BPF] 备份已存在，跳过: $BACKUP"
fi

# 追加 CONFIG 的函数（幂等）
# 1. 删除已有的 "# CONFIG_xxx is not set" 行
# 2. 删除已有的 "CONFIG_xxx=任何值" 行
# 3. 追加新值
append_config() {
    local cfg="$1"
    local val="$2"
    local line="${cfg}=${val}"

    sed -i "/^# ${cfg} is not set\$/d" "$DEFCONFIG"
    sed -i "/^${cfg}=/d" "$DEFCONFIG"
    echo "$line" >> "$DEFCONFIG"

    echo "[ABK-BPF] 已设置: ${line}"
}

echo ""
echo "[ABK-BPF] 开始追加 CONFIG（按依赖顺序）..."
echo "---------------------------------------------------"

# === 1. 函数追踪基础设施（fentry/fexit/trampoline 前置条件）===
# 原 defconfig 中: # CONFIG_FUNCTION_TRACER is not set
# 启用后可用 BPF trampoline (fentry/fexit)，比 kprobe 快 10 倍且隐蔽
append_config "CONFIG_FUNCTION_TRACER" "y"
append_config "CONFIG_DYNAMIC_FTRACE" "y"
append_config "CONFIG_DYNAMIC_FTRACE_WITH_REGS" "y"
append_config "CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS" "y"

# === 2. ftrace syscall 追踪 ===
# 原 defconfig 中: # CONFIG_FTRACE_SYSCALLS is not set
append_config "CONFIG_FTRACE_SYSCALLS" "y"

# === 3. 函数错误注入（BPF_KPROBE_OVERRIDE 前置条件）===
# 原 defconfig 中: # CONFIG_FUNCTION_ERROR_INJECTION is not set
append_config "CONFIG_FUNCTION_ERROR_INJECTION" "y"

# === 4. BPF 修改返回值（fmod_ret）===
append_config "CONFIG_BPF_KPROBE_OVERRIDE" "y"

# === 5. BPF LSM 安全模块 ===
# 原 defconfig 中: # CONFIG_BPF_LSM is not set
# 启用后可编写 BPF 安全策略（拦截 exec/file_mmap 等 LSM hook）
append_config "CONFIG_SECURITY_BPF" "y"
append_config "CONFIG_BPF_LSM" "y"

# === 6. 辅助可观测性选项（强化 BPF 信息采集能力）===
append_config "CONFIG_BPF_EVENTS" "y"
append_config "CONFIG_BPF_STREAM_PARSER" "y"
append_config "CONFIG_DEBUG_INFO_BTF" "y"
append_config "CONFIG_DEBUG_INFO_BTF_MODULES" "y"

echo "---------------------------------------------------"
echo ""

# 验证结果
echo "[ABK-BPF] 验证追加结果:"
echo "---------------------------------------------------"
for cfg in CONFIG_FUNCTION_TRACER CONFIG_DYNAMIC_FTRACE CONFIG_DYNAMIC_FTRACE_WITH_REGS \
           CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS CONFIG_FTRACE_SYSCALLS \
           CONFIG_FUNCTION_ERROR_INJECTION CONFIG_BPF_KPROBE_OVERRIDE \
           CONFIG_SECURITY_BPF CONFIG_BPF_LSM \
           CONFIG_BPF_EVENTS CONFIG_BPF_STREAM_PARSER \
           CONFIG_DEBUG_INFO_BTF CONFIG_DEBUG_INFO_BTF_MODULES; do
    result=$(grep "^${cfg}=" "$DEFCONFIG" 2>/dev/null || echo "未找到")
    printf "  %-50s %s\n" "$cfg" "$result"
done
echo "---------------------------------------------------"

echo ""
echo "[ABK-BPF] 完成！"
echo "[ABK-BPF] 重要提示："
echo "  1. 如果构建失败提示 KMI/symbol 冲突，请反馈错误日志"
echo "  2. CONFIG_FUNCTION_TRACER 会改变函数入口，可能影响 KMI"
echo "  3. 刷入后请验证: zcat /proc/config.gz | grep -E 'BPF_LSM|FUNCTION_TRACER'"
echo "  4. BPF LSM 启用后还需在启动参数追加 lsm=...,bpf（通常由 init.rc 处理）"
echo "==================================================="
