# ida_export_for_ai.py
# IDA Plugin to export decompiled functions, strings, memory, imports and exports for AI analysis

import os
import sys
import json
import time
import ida_hexrays
import ida_funcs
import ida_nalt
import ida_xref
import ida_segment
import ida_bytes
import ida_entry
import idautils
import idc
import ida_auto
import ida_kernwin
import ida_idaapi
import ida_undo
import ida_idp
import ida_ida
import ida_typeinf
import ida_frame
import ida_fixup
import ida_moves
import ida_lines
import ida_problems
import gc
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import multiprocessing as mp

HAS_QT = False
try:
    from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QGridLayout,
                                  QLabel, QLineEdit, QPushButton, QCheckBox,
                                  QProgressBar, QPlainTextEdit, QFileDialog,
                                  QApplication, QGroupBox, QSplitter, QWidget)
    from PyQt5.QtCore import Qt
    HAS_QT = True
except Exception:
    pass

WORKER_COUNT = max(1, mp.cpu_count() - 1)
TASK_BATCH_SIZE = 50
_LAST_SUB_PROGRESS = [0]  # mutable for closure


def print_sub_progress(current, total, label=""):
    """Print granular sub-task progress (throttled to every 2%)"""
    if total <= 0:
        return
    pct = int(100 * current / total)
    # Only print every 2% or at the end
    if pct == _LAST_SUB_PROGRESS[0] and current < total:
        return
    _LAST_SUB_PROGRESS[0] = pct
    width = 30
    filled = int(width * current / total)
    bar = "█" * filled + "░" * (width - filled)
    print("    [{}] {}/{} {:.0f}% {}".format(bar, current, total, pct, label))


def get_worker_count():
    """获取用户配置的并行工作线程数"""
    return WORKER_COUNT


def get_idb_directory():
    """获取 IDB 文件所在目录"""
    idb_path = ida_nalt.get_input_file_path()
    if not idb_path:
        import ida_loader
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    return os.path.dirname(idb_path) if idb_path else os.getcwd()


def ensure_dir(path):
    """确保目录存在"""
    if not os.path.exists(path):
        os.makedirs(path)


def clear_undo_buffer():
    """清理 IDA 撤销缓冲区，防止内存溢出"""
    try:
        ida_undo.clear_undo_buffer()
        gc.collect()
    except:
        pass


def disable_undo():
    """禁用撤销功能（IDA 7.0+）"""
    try:
        ida_idp.disable_undo(True)
    except:
        pass


def enable_undo():
    """启用撤销功能"""
    try:
        ida_idp.disable_undo(False)
    except:
        pass


def get_callers(func_ea):
    """获取调用当前函数的地址列表"""
    callers = []
    for ref in idautils.XrefsTo(func_ea, 0):
        if idc.is_code(idc.get_full_flags(ref.frm)):
            caller_func = ida_funcs.get_func(ref.frm)
            if caller_func:
                callers.append(caller_func.start_ea)
    return sorted(list(set(callers)))


def get_callees(func_ea):
    """获取当前函数调用的函数地址列表"""
    callees = []
    func = ida_funcs.get_func(func_ea)
    if not func:
        return callees

    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            for ref in idautils.XrefsFrom(head, 0):
                if ref.type in [ida_xref.fl_CF, ida_xref.fl_CN]:
                    callee_func = ida_funcs.get_func(ref.to)
                    if callee_func:
                        callees.append(callee_func.start_ea)
    return sorted(list(set(callees)))


def format_address_list(addr_list):
    """格式化地址列表为逗号分隔的十六进制字符串"""
    return ", ".join([hex(addr) for addr in addr_list])


def sanitize_filename(name):
    """清理函数名，使其适合作为文件名"""
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        name = name.replace(char, '_')
    name = name.replace('.', '_')
    if len(name) > 200:
        name = name[:200]
    return name


def save_progress(export_dir, processed_addrs, failed_funcs, skipped_funcs):
    """保存当前进度到文件"""
    progress_file = os.path.join(export_dir, ".export_progress")
    try:
        with open(progress_file, 'w', encoding='utf-8') as f:
            f.write("# Export Progress\n")
            f.write("# Format: address | status (done/failed/skipped)\n")
            for addr in processed_addrs:
                f.write("{:X}|done\n".format(addr))
            for addr, name, reason in failed_funcs:
                f.write("{:X}|failed|{}|{}\n".format(addr, name, reason))
            for addr, name, reason in skipped_funcs:
                f.write("{:X}|skipped|{}|{}\n".format(addr, name, reason))
    except Exception as e:
        print("[!] Failed to save progress: {}".format(str(e)))


def load_progress(export_dir):
    """从文件加载进度"""
    progress_file = os.path.join(export_dir, ".export_progress")
    processed = set()
    failed = []
    skipped = []

    if not os.path.exists(progress_file):
        return processed, failed, skipped

    try:
        with open(progress_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('|')
                if len(parts) >= 2:
                    addr = int(parts[0], 16)
                    status = parts[1]
                    if status == 'done':
                        processed.add(addr)
                    elif status == 'failed' and len(parts) >= 4:
                        failed.append((addr, parts[2], parts[3]))
                    elif status == 'skipped' and len(parts) >= 4:
                        skipped.append((addr, parts[2], parts[3]))
        print("[+] Loaded progress: {} functions already processed".format(len(processed)))
    except Exception as e:
        print("[!] Failed to load progress: {}".format(str(e)))

    return processed, failed, skipped


def export_decompiled_functions(export_dir, skip_existing=True):
    """导出所有函数的反编译代码（内存优化版 - 流式处理）

    Args:
        export_dir: 导出目录
        skip_existing: 是否跳过已存在的文件
    """
    decompile_dir = os.path.join(export_dir, "decompile")
    ensure_dir(decompile_dir)

    total_funcs = 0
    exported_funcs = 0
    failed_funcs = []
    skipped_funcs = []
    function_index = []
    addr_to_info = {}

    # 使用单线程I/O避免内存累积
    io_executor = ThreadPoolExecutor(max_workers=1)

    # 加载之前的进度
    processed_addrs, prev_failed, prev_skipped = load_progress(export_dir)
    failed_funcs.extend(prev_failed)
    skipped_funcs.extend(prev_skipped)

    # 收集所有函数地址
    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)

    # 过滤掉已处理的函数
    remaining_funcs = [ea for ea in all_funcs if ea not in processed_addrs]

    print("[*] Found {} functions total, {} remaining to process".format(total_funcs, len(remaining_funcs)))
    print("[*] Memory-optimized mode: processing one function at a time")

    if len(remaining_funcs) == 0:
        print("[+] All functions already exported!")
        io_executor.shutdown(wait=False)
        return

    total_remaining = len(remaining_funcs)
    _LAST_SUB_PROGRESS[0] = -1

    # 流式处理 - 不预加载所有调用关系
    BATCH_SIZE = 10  # 减小批量大小
    MEMORY_CLEAN_INTERVAL = 5  # 更频繁地清理内存
    pending_writes = []

    def write_function_file(args):
        """线程安全的文件写入"""
        func_ea, func_name, dec_str, callers, callees = args

        output_lines = []
        output_lines.append("/*")
        output_lines.append(" * func-name: {}".format(func_name))
        output_lines.append(" * func-address: {}".format(hex(func_ea)))
        output_lines.append(" * callers: {}".format(format_address_list(callers) if callers else "none"))
        output_lines.append(" * callees: {}".format(format_address_list(callees) if callees else "none"))
        output_lines.append(" */")
        output_lines.append("")
        output_lines.append(dec_str)

        output_filename = "{:X}.c".format(func_ea)
        output_path = os.path.join(decompile_dir, output_filename)

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(output_lines))
            return func_ea, func_name, True, output_filename, callers, callees, None
        except IOError as e:
            return func_ea, func_name, False, output_filename, callers, callees, str(e)

    def aggressive_memory_cleanup():
        """激进的内存清理"""
        # 强制删除大对象引用
        import sys
        # 清理IDA内部缓存
        try:
            ida_hexrays.clear_cached_cfuncs()
        except:
            pass
        # 强制垃圾回收
        gc.collect()
        gc.collect()  # 两次收集确保清理

    for idx, func_ea in enumerate(remaining_funcs):
        print_sub_progress(idx + 1, total_remaining, "decompiling")
        # 实时获取函数信息（不缓存）
        func_name = idc.get_func_name(func_ea)

        # 跳过外部函数和导入函数
        func = ida_funcs.get_func(func_ea)
        if func is None:
            skipped_funcs.append((func_ea, func_name, "not a valid function"))
            processed_addrs.add(func_ea)
            continue

        if func.flags & ida_funcs.FUNC_LIB:
            skipped_funcs.append((func_ea, func_name, "library function"))
            processed_addrs.add(func_ea)
            continue

        dec_str = None
        dec_obj = None

        try:
            # 尝试反编译
            dec_obj = ida_hexrays.decompile(func_ea)
            if dec_obj is None:
                failed_funcs.append((func_ea, func_name, "decompile returned None"))
                processed_addrs.add(func_ea)
                continue

            dec_str = str(dec_obj)
            # 立即释放反编译对象
            dec_obj = None

            if not dec_str or len(dec_str.strip()) == 0:
                failed_funcs.append((func_ea, func_name, "empty decompilation result"))
                processed_addrs.add(func_ea)
                continue

            # 只在需要时获取调用关系
            callers = get_callers(func_ea)
            callees = get_callees(func_ea)

            output_filename = "{:X}.c".format(func_ea)
            output_path = os.path.join(decompile_dir, output_filename)

            # 如果文件已存在且skip_existing为True，则跳过
            if skip_existing and os.path.exists(output_path):
                exported_funcs += 1
                processed_addrs.add(func_ea)
                # 立即释放dec_str
                dec_str = None
                if (exported_funcs + len(prev_failed) + len(prev_skipped)) % 100 == 0:
                    print("[+] Exported {} / {} functions...".format(
                        exported_funcs + len(prev_failed) + len(prev_skipped), total_funcs))
                continue

            # 提交写入任务
            write_args = (func_ea, func_name, dec_str, callers, callees)
            future = io_executor.submit(write_function_file, write_args)
            pending_writes.append((future, func_ea, func_name, output_filename, callers, callees))

            # 立即释放dec_str，因为已经传递给写入任务
            dec_str = None

        except ida_hexrays.DecompilationFailure as e:
            failed_funcs.append((func_ea, func_name, "decompilation failure: {}".format(str(e))))
            processed_addrs.add(func_ea)
            continue
        except Exception as e:
            failed_funcs.append((func_ea, func_name, "unexpected error: {}".format(str(e))))
            print("[!] Error decompiling {} at {}: {}".format(func_name, hex(func_ea), str(e)))
            processed_addrs.add(func_ea)
            continue
        finally:
            # 确保反编译对象被释放
            dec_obj = None
            dec_str = None

        # 定期清理撤销缓冲区
        if (idx + 1) % MEMORY_CLEAN_INTERVAL == 0:
            clear_undo_buffer()
            aggressive_memory_cleanup()

        # 批量等待写入完成并收集结果
        if len(pending_writes) >= BATCH_SIZE:
            for future, func_ea, func_name, output_filename, callers, callees in pending_writes:
                try:
                    result = future.result()
                    func_ea, func_name, success, output_filename, callers, callees, error = result

                    if success:
                        func_info = {
                            'address': func_ea,
                            'name': func_name,
                            'filename': output_filename,
                            'callers': callers,
                            'callees': callees
                        }
                        function_index.append(func_info)
                        addr_to_info[func_ea] = func_info
                        exported_funcs += 1
                        processed_addrs.add(func_ea)
                    else:
                        failed_funcs.append((func_ea, func_name, "IO error: {}".format(error)))
                        processed_addrs.add(func_ea)

                except Exception as e:
                    print("[!] Write error: {}".format(str(e)))

            # 保存进度并清理
            save_progress(export_dir, processed_addrs, failed_funcs, skipped_funcs)
            if exported_funcs % 100 == 0:
                print("[+] Exported {} / {} functions...".format(exported_funcs + len(prev_failed) + len(prev_skipped),
                                                                 total_funcs))

            # 清理索引，避免内存无限增长
            if len(function_index) > 1000:
                # 保存到临时文件后清空
                function_index = []
                addr_to_info = {}

            pending_writes = []
            aggressive_memory_cleanup()

    # 处理剩余的写入任务
    if pending_writes:
        for future, func_ea, func_name, output_filename, callers, callees in pending_writes:
            try:
                result = future.result()
                func_ea, func_name, success, output_filename, callers, callees, error = result

                if success:
                    func_info = {
                        'address': func_ea,
                        'name': func_name,
                        'filename': output_filename,
                        'callers': callers,
                        'callees': callees
                    }
                    function_index.append(func_info)
                    addr_to_info[func_ea] = func_info
                    exported_funcs += 1
                    processed_addrs.add(func_ea)
                else:
                    failed_funcs.append((func_ea, func_name, "IO error: {}".format(error)))
                    processed_addrs.add(func_ea)

            except Exception as e:
                print("[!] Write error: {}".format(str(e)))

    # 关闭线程池
    io_executor.shutdown(wait=True)

    # 最终保存进度
    save_progress(export_dir, processed_addrs, failed_funcs, skipped_funcs)

    print("\n[*] Decompilation Summary:")
    print("    Total functions: {}".format(total_funcs))
    print("    Exported: {}".format(exported_funcs))
    print("    Skipped: {} (library/invalid functions)".format(len(skipped_funcs)))
    print("    Failed: {}".format(len(failed_funcs)))

    # 保存失败列表
    if failed_funcs:
        failed_log_path = os.path.join(export_dir, "decompile_failed.txt")
        with open(failed_log_path, 'w', encoding='utf-8') as f:
            f.write("# Failed to decompile {} functions\n".format(len(failed_funcs)))
            f.write("# Format: address | function_name | reason\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason in failed_funcs:
                f.write("{} | {} | {}\n".format(hex(addr), name, reason))
        print("    Failed list saved to: decompile_failed.txt")

    # 保存跳过列表
    if skipped_funcs:
        skipped_log_path = os.path.join(export_dir, "decompile_skipped.txt")
        with open(skipped_log_path, 'w', encoding='utf-8') as f:
            f.write("# Skipped {} functions\n".format(len(skipped_funcs)))
            f.write("# Format: address | function_name | reason\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason in skipped_funcs:
                f.write("{} | {} | {}\n".format(hex(addr), name, reason))
        print("    Skipped list saved to: decompile_skipped.txt")

    # 生成函数索引文件
    if function_index:
        index_path = os.path.join(export_dir, "function_index.txt")
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write("# Function Index\n")
            f.write("# Total exported functions: {}\n".format(len(function_index)))
            f.write("#" + "=" * 80 + "\n\n")

            for func_info in function_index:
                f.write("=" * 80 + "\n")
                f.write("Function: {}\n".format(func_info['name']))
                f.write("Address: {}\n".format(hex(func_info['address'])))
                f.write("File: {}\n".format(func_info['filename']))
                f.write("\n")

                if func_info['callers']:
                    f.write("Called by ({} callers):\n".format(len(func_info['callers'])))
                    for caller_addr in func_info['callers']:
                        if caller_addr in addr_to_info:
                            caller_info = addr_to_info[caller_addr]
                            f.write("  - {} ({}) -> {}\n".format(
                                hex(caller_addr),
                                caller_info['name'],
                                caller_info['filename']
                            ))
                        else:
                            caller_name = idc.get_func_name(caller_addr)
                            f.write("  - {} ({})\n".format(hex(caller_addr), caller_name))
                else:
                    f.write("Called by: none\n")

                f.write("\n")

                if func_info['callees']:
                    f.write("Calls ({} callees):\n".format(len(func_info['callees'])))
                    for callee_addr in func_info['callees']:
                        if callee_addr in addr_to_info:
                            callee_info = addr_to_info[callee_addr]
                            f.write("  - {} ({}) -> {}\n".format(
                                hex(callee_addr),
                                callee_info['name'],
                                callee_info['filename']
                            ))
                        else:
                            callee_name = idc.get_func_name(callee_addr)
                            f.write("  - {} ({})\n".format(hex(callee_addr), callee_name))
                else:
                    f.write("Calls: none\n")

                f.write("\n")

        print("    Function index saved to: function_index.txt")


def export_strings(export_dir):
    """导出所有字符串"""
    strings_path = os.path.join(export_dir, "strings.txt")

    string_count = 0
    BATCH_SIZE = 500  # 每500个字符串清理一次
    _LAST_SUB_PROGRESS[0] = -1

    with open(strings_path, 'w', encoding='utf-8') as f:
        f.write("# Strings exported from IDA\n")
        f.write("# Format: address | length | type | string\n")
        f.write("#" + "=" * 80 + "\n\n")

        for idx, s in enumerate(idautils.Strings()):
            if idx % 100 == 0:
                print("    [{} strings processed]".format(idx))
            try:
                string_content = str(s)
                str_type = "ASCII"
                if s.strtype == ida_nalt.STRTYPE_C_16:
                    str_type = "UTF-16"
                elif s.strtype == ida_nalt.STRTYPE_C_32:
                    str_type = "UTF-32"

                f.write("{} | {} | {} | {}\n".format(
                    hex(s.ea),
                    s.length,
                    str_type,
                    string_content.replace('\n', '\\n').replace('\r', '\\r')
                ))
                string_count += 1

                # 定期清理撤销缓冲区
                if (idx + 1) % BATCH_SIZE == 0:
                    clear_undo_buffer()

            except Exception as e:
                continue

    print("[*] Strings Summary:")
    print("    Total strings exported: {}".format(string_count))


def export_imports(export_dir):
    """导出导入表"""
    imports_path = os.path.join(export_dir, "imports.txt")

    import_count = 0
    with open(imports_path, 'w', encoding='utf-8') as f:
        f.write("# Imports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")

        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)

            def imp_cb(ea, name, ordinal):
                nonlocal import_count
                if name:
                    f.write("{}:{}\n".format(hex(ea), name))
                else:
                    f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
                import_count += 1
                return True

            ida_nalt.enum_import_names(i, imp_cb)

    print("[*] Imports Summary:")
    print("    Total imports exported: {}".format(import_count))


def export_exports(export_dir):
    """导出导出表"""
    exports_path = os.path.join(export_dir, "exports.txt")

    export_count = 0
    with open(exports_path, 'w', encoding='utf-8') as f:
        f.write("# Exports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")

        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)

            if name:
                f.write("{}:{}\n".format(hex(ea), name))
            else:
                f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
            export_count += 1

    print("[*] Exports Summary:")
    print("    Total exports exported: {}".format(export_count))


def export_memory(export_dir):
    """导出内存数据，按 1MB 分割，hexdump 格式"""
    memory_dir = os.path.join(export_dir, "memory")
    ensure_dir(memory_dir)

    CHUNK_SIZE = 1 * 1024 * 1024  # 1MB
    BYTES_PER_LINE = 16

    total_bytes = 0
    file_count = 0
    total_segs = ida_segment.get_segm_qty()
    _LAST_SUB_PROGRESS[0] = -1

    for seg_idx in range(total_segs):
        seg = ida_segment.getnseg(seg_idx)
        if seg is None:
            continue

        print_sub_progress(seg_idx + 1, total_segs, "memory segments")
        seg_start = seg.start_ea
        seg_end = seg.end_ea
        seg_name = ida_segment.get_segm_name(seg)

        print("[*] Processing segment: {} ({} - {})".format(
            seg_name, hex(seg_start), hex(seg_end)))

        current_addr = seg_start
        while current_addr < seg_end:
            chunk_end = min(current_addr + CHUNK_SIZE, seg_end)

            filename = "{:08X}--{:08X}.txt".format(current_addr, chunk_end)
            filepath = os.path.join(memory_dir, filename)

            # 跳过已存在的文件
            if os.path.exists(filepath):
                file_count += 1
                current_addr = chunk_end
                total_bytes += (chunk_end - current_addr)
                continue

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("# Memory dump: {} - {}\n".format(hex(current_addr), hex(chunk_end)))
                f.write("# Segment: {}\n".format(seg_name))
                f.write("#" + "=" * 76 + "\n\n")
                f.write("# Address        | Hex Bytes                                       | ASCII\n")
                f.write("#" + "-" * 76 + "\n")

                addr = current_addr
                while addr < chunk_end:
                    line_bytes = []
                    for i in range(BYTES_PER_LINE):
                        if addr + i < chunk_end:
                            byte_val = ida_bytes.get_byte(addr + i)
                            if byte_val is not None:
                                line_bytes.append(byte_val)
                            else:
                                line_bytes.append(0)
                        else:
                            break

                    if not line_bytes:
                        addr += BYTES_PER_LINE
                        continue

                    hex_part = ""
                    for i, b in enumerate(line_bytes):
                        hex_part += "{:02X} ".format(b)
                        if i == 7:
                            hex_part += " "
                    remaining = BYTES_PER_LINE - len(line_bytes)
                    if remaining > 0:
                        if len(line_bytes) <= 8:
                            hex_part += " "
                        hex_part += "   " * remaining

                    ascii_part = ""
                    for b in line_bytes:
                        if 0x20 <= b <= 0x7E:
                            ascii_part += chr(b)
                        else:
                            ascii_part += "."

                    f.write("{:016X} | {} | {}\n".format(addr, hex_part.ljust(49), ascii_part))

                    addr += BYTES_PER_LINE
                    total_bytes += len(line_bytes)

            file_count += 1
            current_addr = chunk_end

            # 每处理完一个chunk清理一次撤销缓冲区
            clear_undo_buffer()

    print("\n[*] Memory Export Summary:")
    print("    Total bytes exported: {} ({:.2f} MB)".format(total_bytes, total_bytes / (1024 * 1024)))
    print("    Files created: {}".format(file_count))


def _ptr_export_get_ptr_size():
    """获取当前数据库的指针大小"""
    return 8 if ida_ida.inf_is_64bit() else 4


def _ptr_export_read_pointer(ea, ptr_size):
    """读取指针值"""
    return ida_bytes.get_qword(ea) if ptr_size == 8 else ida_bytes.get_dword(ea)


def _ptr_export_get_segment_name(ea):
    """获取地址所在段名"""
    seg = ida_segment.getseg(ea)
    if not seg:
        return "unknown"
    name = ida_segment.get_segm_name(seg)
    return name if name else "unknown"


def _ptr_export_is_valid_target(target_ea):
    """判断目标地址是否落在有效段内"""
    if target_ea in (0, ida_idaapi.BADADDR):
        return False
    return ida_segment.getseg(target_ea) is not None


def _ptr_export_safe_text(value):
    """将文本压成单行，便于写入导出文件"""
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            value = repr(value)
    else:
        value = str(value)

    value = value.replace("\r", " ").replace("\n", " ").replace("|", "/").strip()
    if len(value) > 80:
        value = value[:77] + "..."
    return value


def _ptr_export_get_target_name(target_ea):
    """获取目标符号名"""
    name = idc.get_name(target_ea, idc.GN_VISIBLE)
    if not name:
        func = ida_funcs.get_func(target_ea)
        if func:
            name = idc.get_func_name(func.start_ea)
    if not name:
        name = "unknown"
    return _ptr_export_safe_text(name)


def _ptr_export_try_get_string_preview(target_ea):
    """尝试提取字符串预览"""
    try:
        flags = ida_bytes.get_full_flags(target_ea)
        if not ida_bytes.is_strlit(flags):
            return ""
    except Exception:
        return ""

    try:
        strtype = idc.get_str_type(target_ea)
    except Exception:
        strtype = -1

    try:
        raw = ida_bytes.get_strlit_contents(target_ea, -1, strtype)
    except Exception:
        raw = None

    preview = _ptr_export_safe_text(raw)
    if preview:
        return '"{}"'.format(preview)
    return "string_literal"


def _ptr_export_is_import_target(target_ea, target_name):
    """启发式判断是否为导入项/IAT"""
    seg_name = _ptr_export_get_segment_name(target_ea).lower()
    name_l = (target_name or "").lower()

    if name_l.startswith("__imp_") or name_l.startswith("imp_"):
        return True

    import_like_segments = {
        "extern", ".idata", "idata", ".idata$2", ".idata$4", ".idata$5", ".idata$6",
        ".got", "got", ".got.plt", "got.plt", "__la_symbol_ptr", "__nl_symbol_ptr"
    }
    return seg_name in import_like_segments


def _ptr_export_classify_target(target_ea):
    """返回 (target_name, target_type, target_detail)"""
    target_name = _ptr_export_get_target_name(target_ea)

    try:
        flags = ida_bytes.get_full_flags(target_ea)
    except Exception:
        flags = 0

    if _ptr_export_is_import_target(target_ea, target_name):
        return target_name, "import_pointer", "import_entry"

    try:
        if ida_bytes.is_strlit(flags):
            return target_name, "string_pointer", _ptr_export_try_get_string_preview(target_ea)
    except Exception:
        pass

    try:
        func = ida_funcs.get_func(target_ea)
    except Exception:
        func = None

    if func:
        if func.start_ea == target_ea:
            return target_name, "function_pointer", "function_start"
        func_name = _ptr_export_get_target_name(func.start_ea)
        return target_name, "code_pointer", "inside_{}".format(func_name)

    try:
        if ida_bytes.is_code(flags):
            return target_name, "code_pointer", "instruction"
    except Exception:
        pass

    try:
        if ida_bytes.is_struct(flags):
            return target_name, "struct_pointer", "struct_data"
    except Exception:
        pass

    try:
        if ida_bytes.is_data(flags):
            return target_name, "data_pointer", "data_item_size={}".format(ida_bytes.get_item_size(target_ea))
    except Exception:
        pass

    return target_name, "unknown_pointer", ""


def _ptr_export_add_record(records, seen, source_ea, target_ea):
    """去重后加入一条记录"""
    key = (source_ea, target_ea)
    if key in seen:
        return
    seen.add(key)

    target_name, target_type, target_detail = _ptr_export_classify_target(target_ea)
    records.append({
        "source_addr": source_ea,
        "source_seg": _ptr_export_get_segment_name(source_ea),
        "points_to": target_ea,
        "target_name": target_name,
        "target_type": target_type,
        "target_detail": target_detail,
    })


def _ptr_export_collect_data_xrefs(records, seen):
    """收集所有代码头/数据头上的 data xref"""
    total = 0

    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if not seg:
            continue

        for head in idautils.Heads(seg.start_ea, seg.end_ea):
            try:
                flags = ida_bytes.get_full_flags(head)
            except Exception:
                continue

            if not ida_bytes.is_head(flags):
                continue
            if not (ida_bytes.is_code(flags) or ida_bytes.is_data(flags)):
                continue

            try:
                target = ida_xref.get_first_dref_from(head)
            except Exception:
                target = ida_idaapi.BADADDR

            while target != ida_idaapi.BADADDR:
                if _ptr_export_is_valid_target(target):
                    _ptr_export_add_record(records, seen, head, target)
                    total += 1
                try:
                    target = ida_xref.get_next_dref_from(head, target)
                except Exception:
                    break

    return total


def _ptr_export_collect_raw_pointers(records, seen, ptr_size):
    """扫描常见数据段中的裸指针，补齐未建立 xref 的项"""
    total = 0

    for seg_ea in idautils.Segments():
        seg_name = idc.get_segm_name(seg_ea)
        seg_start = idc.get_segm_start(seg_ea)
        seg_end = idc.get_segm_end(seg_ea)

        if not seg_name or not (
                seg_name.startswith(".data") or seg_name.startswith(".rdata") or seg_name.startswith("data")):
            continue

        print("[*] Scanning segment: {} ({:X} - {:X})".format(seg_name, seg_start, seg_end))

        for head in idautils.Heads(seg_start, seg_end):
            try:
                flags = ida_bytes.get_full_flags(head)
            except Exception:
                continue

            if not ida_bytes.is_head(flags):
                continue
            if not ida_bytes.is_data(flags):
                continue

            try:
                item_size = ida_bytes.get_item_size(head)
            except Exception:
                item_size = 0

            if item_size < ptr_size:
                continue

            slot_count = item_size // ptr_size
            if slot_count <= 0:
                continue

            for i in range(slot_count):
                slot_ea = head + i * ptr_size
                try:
                    target = _ptr_export_read_pointer(slot_ea, ptr_size)
                except Exception:
                    continue

                if _ptr_export_is_valid_target(target):
                    _ptr_export_add_record(records, seen, slot_ea, target)
                    total += 1

    return total


def export_pointers(export_dir):
    """导出指针引用，保留原有导出目录模式"""
    output_path = os.path.join(export_dir, "pointers.txt")
    ptr_size = _ptr_export_get_ptr_size()
    records = []
    seen = set()

    print("[*] Starting pointer scan. Pointer size: {} bytes".format(ptr_size))

    dref_hits = _ptr_export_collect_data_xrefs(records, seen)
    raw_hits = _ptr_export_collect_raw_pointers(records, seen, ptr_size)

    records.sort(key=lambda item: (
        item["source_addr"],
        item["points_to"],
        item["source_seg"],
        item["target_name"],
        item["target_type"],
        item["target_detail"],
    ))

    if records:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("# Total Pointers Found: {}\n".format(len(records)))
                f.write(
                    "# Format: Source_Address | Segment | Points_To_Address | Target_Name | Target_Type | Target_Detail\n")
                f.write("# Pointer size: {}\n".format(ptr_size))
                f.write("# Data xref hits: {}\n".format(dref_hits))
                f.write("# Raw pointer hits: {}\n".format(raw_hits))
                f.write("-" * 120 + "\n")
                for p in records:
                    f.write("{:X} | {} | {:X} | {} | {} | {}\n".format(
                        p["source_addr"],
                        p["source_seg"],
                        p["points_to"],
                        p["target_name"],
                        p["target_type"],
                        p["target_detail"]
                    ))
            print("[+] Pointers exported to: {}".format(output_path))
            print("[*] Pointers Summary:")
            print("    Data xref hits: {}".format(dref_hits))
            print("    Raw pointer hits: {}".format(raw_hits))
            print("    Unique pointer references exported: {}".format(len(records)))
        except Exception as e:
            print("[!] Failed to write pointers: {}".format(str(e)))
    else:
        print("[*] No pointers found or no data segments scanned.")


def export_structs_enums(export_dir):
    """Export local type library: structs, enums, typedefs"""
    import ida_typeinf

    types_path = os.path.join(export_dir, "types.txt")
    til = ida_typeinf.get_idati()

    type_count = 0
    total_ordinals = ida_typeinf.get_ordinal_count(til)
    _LAST_SUB_PROGRESS[0] = -1

    with open(types_path, 'w', encoding='utf-8') as f:
        f.write("# Local Types (structs, enums, typedefs)\n")
        f.write("# Format: ordinal | name | type_kind | definition\n")
        f.write("#" + "=" * 80 + "\n\n")

        for ordinal in range(1, total_ordinals):
            print_sub_progress(ordinal, total_ordinals, "types")
            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.get_numbered_type(til, ordinal):
                continue

            name = tinfo.get_type_name()
            if not name:
                name = "unnamed_{}".format(ordinal)

            if tinfo.is_struct():
                kind = "struct"
            elif tinfo.is_union():
                kind = "union"
            elif tinfo.is_enum():
                kind = "enum"
            elif tinfo.is_typedef():
                kind = "typedef"
            else:
                kind = "other"

            definition = ""
            try:
                definition = tinfo.dstr()
            except:
                pass

            # For structs/unions, enumerate members
            if tinfo.is_struct() or tinfo.is_union():
                f.write("=" * 60 + "\n")
                f.write("{} {} (ordinal {}):\n".format(kind, name, ordinal))
                try:
                    for i, udm in enumerate(tinfo.iter_struct()):
                        member_name = udm.name if udm.name else "field_{}".format(i)
                        member_type = udm.type.dstr() if udm.type else "?"
                        member_size = udm.size // 8 if udm.size else 0
                        f.write("  +0x{:X} {} : {} (size=0x{:X})\n".format(
                            udm.offset // 8, member_name, member_type, member_size))
                except Exception:
                    # Fallback to get_udt_details
                    try:
                        udt = ida_typeinf.udt_type_data_t()
                        if tinfo.get_udt_details(udt):
                            for i in range(udt.size()):
                                member = udt[i]
                                member_name = member.name if member.name else "field_{}".format(i)
                                member_type = member.type.dstr() if member.type else "?"
                                f.write("  +0x{:X} {} : {}\n".format(
                                    member.offset // 8, member_name, member_type))
                    except Exception:
                        f.write("  <could not enumerate members>\n")
                f.write("\n")
                type_count += 1
                continue

            # For enums, enumerate members
            if tinfo.is_enum():
                f.write("=" * 60 + "\n")
                f.write("enum {} (ordinal {}):\n".format(name, ordinal))
                try:
                    edm = ida_typeinf.enum_type_data_t()
                    if tinfo.get_enum_details(edm):
                        for i in range(edm.size()):
                            member = edm[i]
                            f.write("  {} = {}\n".format(member.name, member.value))
                except Exception:
                    f.write("  <could not enumerate members>\n")
                f.write("\n")
                type_count += 1
                continue

            # Fallback for typedefs and others
            f.write("{} | {} | {} | {}\n".format(ordinal, name, kind, definition))
            type_count += 1

    print("[*] Types Summary:")
    print("    Total types exported: {}".format(type_count))


def export_segments(export_dir):
    """Export segment metadata: name, range, permissions, class"""
    segments_path = os.path.join(export_dir, "segments.txt")

    seg_count = 0
    with open(segments_path, 'w', encoding='utf-8') as f:
        f.write("# Segment Metadata\n")
        f.write("# Format: name | start | end | size | perms | class | bitness | align\n")
        f.write("#" + "=" * 80 + "\n\n")

        for seg_idx in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(seg_idx)
            if seg is None:
                continue

            seg_name = ida_segment.get_segm_name(seg)
            seg_class = ida_segment.get_segm_class(seg)
            seg_start = seg.start_ea
            seg_end = seg.end_ea
            seg_size = seg_end - seg_start

            # Permissions (seg.perm uses SFL_ or segperm constants)
            perms = ""
            perms += "R" if seg.perm & 4 else "-"  # read
            perms += "W" if seg.perm & 2 else "-"  # write
            perms += "X" if seg.perm & 1 else "-"  # exec

            # Bitness
            bitness_val = seg.bitness
            if bitness_val == 0:
                bitness = "16"
            elif bitness_val == 1:
                bitness = "32"
            elif bitness_val == 2:
                bitness = "64"
            else:
                bitness = "?"

            align = seg.align

            f.write("{} | {} - {} | size=0x{:X} ({}) | {} | class={} | {}bit | align={}\n".format(
                seg_name,
                hex(seg_start), hex(seg_end),
                seg_size, seg_size,
                perms,
                seg_class if seg_class else "none",
                bitness,
                align
            ))
            seg_count += 1

    print("[*] Segments Summary:")
    print("    Total segments exported: {}".format(seg_count))


def export_function_prototypes(export_dir):
    """Export function prototypes/signatures inferred by Hex-Rays"""
    import ida_typeinf

    protos_path = os.path.join(export_dir, "prototypes.txt")

    proto_count = 0
    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)
    _LAST_SUB_PROGRESS[0] = -1

    with open(protos_path, 'w', encoding='utf-8') as f:
        f.write("# Function Prototypes\n")
        f.write("# Format: address | name | prototype\n")
        f.write("#" + "=" * 80 + "\n\n")

        for idx, func_ea in enumerate(all_funcs):
            print_sub_progress(idx + 1, total_funcs, "prototypes")
            func_name = idc.get_func_name(func_ea)

            # Try idc.get_type first (most readable C-like declaration)
            decl_str = None
            try:
                decl_str = idc.get_type(func_ea)
            except:
                pass

            if not decl_str:
                # Fallback: ida_nalt.get_tinfo
                try:
                    tinfo = ida_typeinf.tinfo_t()
                    if ida_nalt.get_tinfo(tinfo, func_ea):
                        decl_str = tinfo.dstr()
                except:
                    pass

            if not decl_str:
                # Last resort: guess_type
                try:
                    decl_str = idc.guess_type(func_ea)
                except:
                    pass

            if decl_str:
                f.write("{} | {} | {}\n".format(hex(func_ea), func_name, decl_str))
            else:
                f.write("{} | {} | <no type info>\n".format(hex(func_ea), func_name))
            proto_count += 1

            if proto_count % 500 == 0:
                clear_undo_buffer()

    print("[*] Prototypes Summary:")
    print("    Total prototypes exported: {}".format(proto_count))


def export_comments(export_dir):
    """Export all analyst-applied comments and renamed labels"""
    comments_path = os.path.join(export_dir, "comments.txt")

    comment_count = 0
    label_count = 0
    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)

    with open(comments_path, 'w', encoding='utf-8') as f:
        f.write("# Comments and Labels\n")
        f.write("#" + "=" * 80 + "\n\n")

        # Function comments
        f.write("## Function Comments\n")
        f.write("# Format: address | name | comment_type | comment\n")
        f.write("#" + "-" * 60 + "\n\n")

        _LAST_SUB_PROGRESS[0] = -1
        for idx, func_ea in enumerate(all_funcs):
            print_sub_progress(idx + 1, total_funcs, "func comments")
            func_name = idc.get_func_name(func_ea)

            # Regular function comment
            cmt = idc.get_func_cmt(func_ea, 0)
            if cmt:
                f.write("{} | {} | func_comment | {}\n".format(
                    hex(func_ea), func_name, cmt.replace('\n', '\\n')))
                comment_count += 1

            # Repeatable function comment
            cmt_rep = idc.get_func_cmt(func_ea, 1)
            if cmt_rep:
                f.write("{} | {} | func_comment_rep | {}\n".format(
                    hex(func_ea), func_name, cmt_rep.replace('\n', '\\n')))
                comment_count += 1

        f.write("\n## Line Comments\n")
        f.write("# Format: address | comment_type | comment\n")
        f.write("#" + "-" * 60 + "\n\n")

        # Iterate all heads for line comments
        total_segs = ida_segment.get_segm_qty()
        _LAST_SUB_PROGRESS[0] = -1
        for seg_idx in range(total_segs):
            seg = ida_segment.getnseg(seg_idx)
            if seg is None:
                continue

            print_sub_progress(seg_idx + 1, total_segs, "line comments")
            for head in idautils.Heads(seg.start_ea, seg.end_ea):
                # Regular comment
                cmt = idc.get_cmt(head, 0)
                if cmt:
                    f.write("{} | comment | {}\n".format(
                        hex(head), cmt.replace('\n', '\\n')))
                    comment_count += 1

                # Repeatable comment
                cmt_rep = idc.get_cmt(head, 1)
                if cmt_rep:
                    f.write("{} | comment_rep | {}\n".format(
                        hex(head), cmt_rep.replace('\n', '\\n')))
                    comment_count += 1

        f.write("\n## User-Defined Labels (renamed addresses)\n")
        f.write("# Format: address | label\n")
        f.write("#" + "-" * 60 + "\n\n")

        # Iterate names window for user-renamed labels
        for ea, name in idautils.Names():
            # Skip default auto-generated names - check if name is user-defined
            flags = idc.get_full_flags(ea)
            try:
                has_user = ida_bytes.has_user_name(flags)
            except:
                # Fallback: check FF_NAME bit directly
                has_user = bool(flags & 0x4000)  # FF_NAME
            if has_user:
                f.write("{} | {}\n".format(hex(ea), name))
                label_count += 1

    print("[*] Comments & Labels Summary:")
    print("    Total comments exported: {}".format(comment_count))
    print("    Total user labels exported: {}".format(label_count))


def export_xrefs(export_dir):
    """Export full cross-reference map (code + data xrefs)"""
    xrefs_path = os.path.join(export_dir, "xrefs.txt")

    code_xref_count = 0
    data_xref_count = 0
    total_segs = ida_segment.get_segm_qty()
    _LAST_SUB_PROGRESS[0] = -1

    with open(xrefs_path, 'w', encoding='utf-8') as f:
        f.write("# Full Cross-Reference Map\n")
        f.write("# Format: from_addr | to_addr | xref_type | type_name\n")
        f.write("#" + "=" * 80 + "\n\n")

        xref_type_names = {
            ida_xref.fl_CF: "call_far",
            ida_xref.fl_CN: "call_near",
            ida_xref.fl_JF: "jump_far",
            ida_xref.fl_JN: "jump_near",
            ida_xref.fl_F: "flow",
            ida_xref.dr_O: "data_offset",
            ida_xref.dr_W: "data_write",
            ida_xref.dr_R: "data_read",
            ida_xref.dr_T: "data_text",
            ida_xref.dr_I: "data_info",
        }

        for seg_idx in range(total_segs):
            seg = ida_segment.getnseg(seg_idx)
            if seg is None:
                continue

            print_sub_progress(seg_idx + 1, total_segs, "xref segments")
            for head in idautils.Heads(seg.start_ea, seg.end_ea):
                # Code xrefs from this address
                for xref in idautils.XrefsFrom(head, 0):
                    if xref.to == head + idc.get_item_size(head):
                        continue  # skip ordinary flow to next instruction
                    type_name = xref_type_names.get(xref.type, "unknown_{}".format(xref.type))
                    is_code = xref.type in (ida_xref.fl_CF, ida_xref.fl_CN, ida_xref.fl_JF, ida_xref.fl_JN, ida_xref.fl_F)
                    if is_code:
                        f.write("{} | {} | code | {}\n".format(hex(head), hex(xref.to), type_name))
                        code_xref_count += 1
                    else:
                        f.write("{} | {} | data | {}\n".format(hex(head), hex(xref.to), type_name))
                        data_xref_count += 1

            if (seg_idx + 1) % 5 == 0:
                clear_undo_buffer()

    print("[*] Cross-References Summary:")
    print("    Code xrefs: {}".format(code_xref_count))
    print("    Data xrefs: {}".format(data_xref_count))
    print("    Total: {}".format(code_xref_count + data_xref_count))


def export_callgraph(export_dir):
    """Export full call graph as JSON adjacency list"""
    import json

    callgraph_path = os.path.join(export_dir, "callgraph.json")

    graph = {}
    func_names = {}
    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)

    # Build name lookup
    for func_ea in all_funcs:
        func_names[func_ea] = idc.get_func_name(func_ea)

    # Build adjacency list
    _LAST_SUB_PROGRESS[0] = -1
    for idx, func_ea in enumerate(all_funcs):
        print_sub_progress(idx + 1, total_funcs, "callgraph")
        callees = get_callees(func_ea)
        addr_key = hex(func_ea)
        graph[addr_key] = {
            "name": func_names.get(func_ea, "unknown"),
            "calls": [hex(c) for c in callees],
            "call_names": [func_names.get(c, idc.get_func_name(c) or "unknown") for c in callees]
        }

    with open(callgraph_path, 'w', encoding='utf-8') as f:
        json.dump(graph, f, indent=2)

    print("[*] Call Graph Summary:")
    print("    Total functions in graph: {}".format(len(graph)))
    print("    Total edges: {}".format(sum(len(v["calls"]) for v in graph.values())))


def export_vtables(export_dir):
    """Export vtables and RTTI class hierarchy info if available"""
    vtables_path = os.path.join(export_dir, "vtables.txt")

    vtable_count = 0
    ptr_size = _ptr_export_get_ptr_size()
    all_names = list(idautils.Names())
    total_names = len(all_names)
    _LAST_SUB_PROGRESS[0] = -1

    with open(vtables_path, 'w', encoding='utf-8') as f:
        f.write("# Vtables and Class Hierarchy\n")
        f.write("#" + "=" * 80 + "\n\n")

        # Strategy 1: Find vtables by name patterns
        for idx, (ea, name) in enumerate(all_names):
            print_sub_progress(idx + 1, total_names, "vtables")
            is_vtable = False
            # Common vtable naming patterns
            if any(pattern in name.lower() for pattern in
                   ["vtable", "vftable", "`vftable'", "??_7", "__ZTV"]):
                is_vtable = True

            # RTTI type descriptors
            is_rtti = any(pattern in name for pattern in
                         ["??_R0", "??_R1", "??_R2", "??_R3", "??_R4",
                          "__RTTI", "typeinfo", "__ZTI", "__ZTS"])

            if is_vtable:
                f.write("=" * 60 + "\n")
                f.write("VTABLE: {} at {}\n".format(name, hex(ea)))

                # Read vtable entries (function pointers)
                slot_ea = ea
                entry_idx = 0
                max_entries = 200  # safety limit
                while entry_idx < max_entries:
                    try:
                        target = _ptr_export_read_pointer(slot_ea, ptr_size)
                    except:
                        break

                    if target == 0 or target == ida_idaapi.BADADDR:
                        break

                    # Check if target is a valid function
                    func = ida_funcs.get_func(target)
                    if func is None and not idc.is_code(idc.get_full_flags(target)):
                        break

                    target_name = idc.get_func_name(target) if func else idc.get_name(target)
                    if not target_name:
                        target_name = "sub_{:X}".format(target)

                    f.write("  [{}] {} -> {} ({})\n".format(
                        entry_idx, hex(slot_ea), hex(target), target_name))

                    slot_ea += ptr_size
                    entry_idx += 1

                f.write("  ({} entries)\n\n".format(entry_idx))
                vtable_count += 1

            elif is_rtti:
                f.write("RTTI: {} at {}\n".format(name, hex(ea)))

        # Strategy 2: Scan for vtable-like patterns in .rdata/.rodata
        if vtable_count == 0:
            f.write("\n# No named vtables found. Scanning for vtable-like pointer arrays...\n\n")
            for seg_ea in idautils.Segments():
                seg_name = idc.get_segm_name(seg_ea)
                if not seg_name:
                    continue
                seg_name_l = seg_name.lower()
                if not any(x in seg_name_l for x in [".rdata", ".rodata", "const"]):
                    continue

                seg_start = idc.get_segm_start(seg_ea)
                seg_end = idc.get_segm_end(seg_ea)

                addr = seg_start
                while addr < seg_end:
                    # Look for sequences of 3+ function pointers
                    consecutive_funcs = 0
                    check_addr = addr
                    while check_addr < seg_end:
                        try:
                            target = _ptr_export_read_pointer(check_addr, ptr_size)
                        except:
                            break
                        func = ida_funcs.get_func(target) if _ptr_export_is_valid_target(target) else None
                        if func and func.start_ea == target:
                            consecutive_funcs += 1
                            check_addr += ptr_size
                        else:
                            break

                    if consecutive_funcs >= 3:
                        f.write("POSSIBLE_VTABLE at {} ({} function pointers):\n".format(
                            hex(addr), consecutive_funcs))
                        for i in range(consecutive_funcs):
                            slot = addr + i * ptr_size
                            target = _ptr_export_read_pointer(slot, ptr_size)
                            target_name = idc.get_func_name(target) or "sub_{:X}".format(target)
                            f.write("  [{}] {} -> {} ({})\n".format(i, hex(slot), hex(target), target_name))
                        f.write("\n")
                        vtable_count += 1
                        addr = check_addr
                    else:
                        addr += ptr_size

    print("[*] Vtables Summary:")
    print("    Total vtables found: {}".format(vtable_count))


def export_patches(export_dir):
    """Export analyst-applied byte patches"""
    patches_path = os.path.join(export_dir, "patches.txt")

    patch_count = 0
    with open(patches_path, 'w', encoding='utf-8') as f:
        f.write("# Patched Bytes\n")
        f.write("# Format: address | original_byte | patched_byte\n")
        f.write("#" + "=" * 80 + "\n\n")

        # visit_patched_bytes callback approach
        def patch_visitor(ea, fpos, orig, val):
            nonlocal patch_count
            f.write("{} | 0x{:02X} | 0x{:02X}\n".format(hex(ea), orig, val))
            patch_count += 1
            return 0  # continue

        try:
            ida_bytes.visit_patched_bytes(0, ida_idaapi.BADADDR, patch_visitor)
        except Exception as e:
            # Fallback: scan segments for patched bytes
            f.write("# Note: visit_patched_bytes failed ({}), using fallback scan\n\n".format(str(e)))
            for seg_idx in range(ida_segment.get_segm_qty()):
                seg = ida_segment.getnseg(seg_idx)
                if seg is None:
                    continue
                for ea in range(seg.start_ea, seg.end_ea):
                    orig = ida_bytes.get_original_byte(ea)
                    curr = ida_bytes.get_byte(ea)
                    if orig != curr:
                        f.write("{} | 0x{:02X} | 0x{:02X}\n".format(hex(ea), orig, curr))
                        patch_count += 1

    print("[*] Patches Summary:")
    print("    Total patched bytes: {}".format(patch_count))


def export_disassembly(export_dir):
    """Export raw disassembly (assembly instructions) per function"""
    disasm_dir = os.path.join(export_dir, "disassembly")
    ensure_dir(disasm_dir)

    exported = 0
    skipped = 0
    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)
    _LAST_SUB_PROGRESS[0] = -1

    for idx, func_ea in enumerate(all_funcs):
        print_sub_progress(idx + 1, total_funcs, "disassembly")
        func = ida_funcs.get_func(func_ea)
        if func is None:
            continue
        if func.flags & ida_funcs.FUNC_LIB:
            skipped += 1
            continue

        func_name = idc.get_func_name(func_ea)
        lines = []
        lines.append("; function: {} at {}".format(func_name, hex(func_ea)))
        lines.append("; size: {} bytes".format(func.end_ea - func.start_ea))
        lines.append("")

        for head in idautils.Heads(func.start_ea, func.end_ea):
            flags = idc.get_full_flags(head)
            if idc.is_code(flags):
                disasm = idc.GetDisasm(head)
                mnem = idc.print_insn_mnem(head)
                size = idc.get_item_size(head)
                # Get raw bytes
                raw_bytes = ""
                for i in range(min(size, 16)):
                    raw_bytes += "{:02X} ".format(ida_bytes.get_byte(head + i))
                lines.append("{} | {:20s} | {}".format(hex(head), raw_bytes.strip(), disasm))

        output_path = os.path.join(disasm_dir, "{:X}.asm".format(func_ea))
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        exported += 1

        if exported % 500 == 0:
            clear_undo_buffer()

    print("[*] Disassembly Summary:")
    print("    Exported: {}".format(exported))
    print("    Skipped: {} (library functions)".format(skipped))


def export_globals(export_dir):
    """Export global variables with names, addresses, types, and initial values"""
    globals_path = os.path.join(export_dir, "globals.txt")

    count = 0
    all_names = list(idautils.Names())
    total_names = len(all_names)
    _LAST_SUB_PROGRESS[0] = -1

    with open(globals_path, 'w', encoding='utf-8') as f:
        f.write("# Global Variables\n")
        f.write("# Format: address | name | segment | size | type | value\n")
        f.write("#" + "=" * 80 + "\n\n")

        for idx, (ea, name) in enumerate(all_names):
            print_sub_progress(idx + 1, total_names, "globals")
            flags = idc.get_full_flags(ea)
            if not ida_bytes.is_data(flags):
                continue

            seg = ida_segment.getseg(ea)
            if not seg:
                continue
            seg_name = ida_segment.get_segm_name(seg)

            size = ida_bytes.get_item_size(ea)

            # Get type info
            tinfo = ida_typeinf.tinfo_t()
            has_type = ida_nalt.get_tinfo(tinfo, ea)
            type_str = tinfo.dstr() if has_type else ""

            # Get value
            val = ""
            if ida_bytes.is_strlit(flags):
                try:
                    strtype = idc.get_str_type(ea)
                    raw = ida_bytes.get_strlit_contents(ea, -1, strtype)
                    if raw:
                        val = '"{}"'.format(raw.decode('utf-8', errors='replace').replace('\n', '\\n')[:200])
                except:
                    val = "<string>"
            elif size == 1:
                val = "0x{:02X}".format(ida_bytes.get_byte(ea))
            elif size == 2:
                val = "0x{:04X}".format(ida_bytes.get_word(ea))
            elif size == 4:
                val = "0x{:08X}".format(ida_bytes.get_dword(ea))
            elif size == 8:
                val = "0x{:016X}".format(ida_bytes.get_qword(ea))
            elif size <= 64:
                # Small data blobs - show hex
                hex_bytes = []
                for i in range(size):
                    hex_bytes.append("{:02X}".format(ida_bytes.get_byte(ea + i)))
                val = " ".join(hex_bytes)
            else:
                val = "<{} bytes>".format(size)

            f.write("{} | {} | {} | {} | {} | {}\n".format(
                hex(ea), name, seg_name, size, type_str, val))
            count += 1

            if count % 500 == 0:
                clear_undo_buffer()

    print("[*] Globals Summary:")
    print("    Total global variables exported: {}".format(count))


def export_bookmarks(export_dir):
    """Export analyst-placed bookmarks"""
    bookmarks_path = os.path.join(export_dir, "bookmarks.txt")

    count = 0
    with open(bookmarks_path, 'w', encoding='utf-8') as f:
        f.write("# Bookmarks\n")
        f.write("# Format: slot | address | description\n")
        f.write("#" + "=" * 80 + "\n\n")

        for i in range(ida_moves.MAX_MARK_SLOT):
            ea = idc.get_bookmark(i)
            if ea is None or ea == ida_idaapi.BADADDR:
                continue
            desc = idc.get_bookmark_desc(i)
            if desc is None:
                desc = ""

            # Get context (function name if in a function)
            func = ida_funcs.get_func(ea)
            func_name = idc.get_func_name(func.start_ea) if func else "<no function>"

            f.write("{} | {} | {} | in: {}\n".format(i, hex(ea), desc, func_name))
            count += 1

    print("[*] Bookmarks Summary:")
    print("    Total bookmarks exported: {}".format(count))


def export_stack_frames(export_dir):
    """Export stack frame layouts with local variable names, offsets, and types"""
    frames_path = os.path.join(export_dir, "stack_frames.txt")

    count = 0
    has_hexrays = False
    try:
        has_hexrays = ida_hexrays.init_hexrays_plugin()
    except:
        pass

    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)
    _LAST_SUB_PROGRESS[0] = -1

    with open(frames_path, 'w', encoding='utf-8') as f:
        f.write("# Stack Frame Layouts\n")
        f.write("#" + "=" * 80 + "\n\n")

        for idx, func_ea in enumerate(all_funcs):
            print_sub_progress(idx + 1, total_funcs, "stack frames")
            func = ida_funcs.get_func(func_ea)
            if func is None or func.flags & ida_funcs.FUNC_LIB:
                continue

            func_name = idc.get_func_name(func_ea)

            # Get frame info from function struct
            frsize = func.frsize
            argsize = func.argsize
            frregs = func.frregs

            if frsize == 0 and argsize == 0:
                continue

            f.write("=" * 60 + "\n")
            f.write("Function: {} at {}\n".format(func_name, hex(func_ea)))
            f.write("  frame_size={} arg_size={} saved_regs={}\n".format(frsize, argsize, frregs))

            # Try get_func_frame (IDA 9: returns tinfo_t)
            try:
                ti = ida_typeinf.tinfo_t()
                if ida_frame.get_func_frame(ti, func):
                    f.write("  Frame type: {}\n".format(ti.dstr()))
                    # Iterate frame members
                    if ti.is_struct():
                        for i, udm in enumerate(ti.iter_struct()):
                            member_name = udm.name if udm.name else "var_{}".format(i)
                            member_type = udm.type.dstr() if udm.type else "?"
                            member_size = udm.size // 8 if udm.size else 0
                            offset = udm.offset // 8
                            f.write("    +0x{:X} {} : {} (size=0x{:X})\n".format(
                                offset, member_name, member_type, member_size))
            except:
                pass

            # If Hex-Rays available, get richer local var info
            if has_hexrays:
                try:
                    cfunc = ida_hexrays.decompile(func_ea)
                    if cfunc:
                        lvars = cfunc.get_lvars()
                        if lvars and len(lvars) > 0:
                            f.write("  Hex-Rays local variables ({}):\n".format(len(lvars)))
                            for lv in lvars:
                                ty = lv.type()
                                tstr = ty.dstr() if ty else "?"
                                kind = "arg" if lv.is_arg_var() else "local"
                                loc = ""
                                if lv.is_stk_var():
                                    try:
                                        loc = " [stack+0x{:X}]".format(lv.get_stkoff())
                                    except:
                                        loc = " [stack]"
                                elif lv.is_reg_var():
                                    loc = " [reg]"
                                f.write("    {} {} : {}{}\n".format(kind, lv.name, tstr, loc))
                except:
                    pass

            f.write("\n")
            count += 1

            if count % 200 == 0:
                clear_undo_buffer()

    print("[*] Stack Frames Summary:")
    print("    Total functions with frames: {}".format(count))


def export_flirt_matches(export_dir):
    """Export FLIRT/signature matched functions"""
    flirt_path = os.path.join(export_dir, "flirt_matches.txt")

    count = 0
    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)
    _LAST_SUB_PROGRESS[0] = -1

    with open(flirt_path, 'w', encoding='utf-8') as f:
        f.write("# FLIRT Signature Matches\n")
        f.write("# Format: address | name | flags | library_flag\n")
        f.write("#" + "=" * 80 + "\n\n")

        for idx, func_ea in enumerate(all_funcs):
            print_sub_progress(idx + 1, total_funcs, "flirt matches")
            func = ida_funcs.get_func(func_ea)
            if func is None:
                continue

            func_name = idc.get_func_name(func_ea)
            is_lib = bool(func.flags & ida_funcs.FUNC_LIB)
            is_thunk = bool(func.flags & ida_funcs.FUNC_THUNK)

            if is_lib or is_thunk:
                flags_str = []
                if is_lib:
                    flags_str.append("FUNC_LIB")
                if is_thunk:
                    flags_str.append("FUNC_THUNK")
                try:
                    if func.flags & ida_funcs.FUNC_STATIC:
                        flags_str.append("FUNC_STATIC")
                except:
                    pass

                f.write("{} | {} | {} | size={}\n".format(
                    hex(func_ea), func_name, ",".join(flags_str),
                    func.end_ea - func.start_ea))
                count += 1

    print("[*] FLIRT Matches Summary:")
    print("    Total matched functions: {}".format(count))


def export_enum_usage(export_dir):
    """Export where enum values are used in the code"""
    enum_path = os.path.join(export_dir, "enum_usage.txt")

    count = 0
    til = ida_typeinf.get_idati()

    with open(enum_path, 'w', encoding='utf-8') as f:
        f.write("# Enum Value Usage in Code\n")
        f.write("# Format: address | operand | enum_name | member_name | value\n")
        f.write("#" + "=" * 80 + "\n\n")

        # Collect all enums and their members
        enums = {}
        for ordinal in range(1, ida_typeinf.get_ordinal_count(til)):
            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.get_numbered_type(til, ordinal):
                continue
            if not tinfo.is_enum():
                continue
            enum_name = tinfo.get_type_name()
            try:
                edm = ida_typeinf.enum_type_data_t()
                if tinfo.get_enum_details(edm):
                    members = {}
                    for i in range(edm.size()):
                        member = edm[i]
                        members[member.value] = member.name
                    enums[enum_name] = members
            except:
                pass

        if not enums:
            f.write("# No enums found in local type library\n")
            print("[*] Enum Usage Summary:")
            print("    No enums found")
            return

        # Scan code for operands that reference enum values
        total_segs = ida_segment.get_segm_qty()
        _LAST_SUB_PROGRESS[0] = -1
        for seg_idx in range(total_segs):
            seg = ida_segment.getnseg(seg_idx)
            if seg is None:
                continue
            print_sub_progress(seg_idx + 1, total_segs, "enum usage")
            # Only scan code segments
            seg_class = ida_segment.get_segm_class(seg)
            if seg_class != "CODE":
                continue

            for head in idautils.Heads(seg.start_ea, seg.end_ea):
                flags = idc.get_full_flags(head)
                if not idc.is_code(flags):
                    continue

                # Check each operand
                for op_idx in range(8):
                    op_type = idc.get_operand_type(head, op_idx)
                    if op_type == 0:
                        break
                    if op_type == idc.o_imm:  # Immediate value
                        val = idc.get_operand_value(head, op_idx)
                        # Check against all enum members
                        for enum_name, members in enums.items():
                            if val in members:
                                f.write("{} | op{} | {} | {} | {}\n".format(
                                    hex(head), op_idx, enum_name, members[val], val))
                                count += 1

            if (seg_idx + 1) % 5 == 0:
                clear_undo_buffer()

    print("[*] Enum Usage Summary:")
    print("    Total enum references found: {}".format(count))


def export_data_xref_graph(export_dir):
    """Export data xref graph: which functions read/write which globals"""
    data_graph_path = os.path.join(export_dir, "data_xref_graph.json")

    # Collect global data items
    globals_info = {}
    all_names = list(idautils.Names())
    total_names = len(all_names)
    _LAST_SUB_PROGRESS[0] = -1
    for idx, (ea, name) in enumerate(all_names):
        print_sub_progress(idx + 1, total_names, "collecting globals")
        flags = idc.get_full_flags(ea)
        if ida_bytes.is_data(flags):
            seg = ida_segment.getseg(ea)
            if seg:
                globals_info[ea] = {
                    "name": name,
                    "segment": ida_segment.get_segm_name(seg),
                    "readers": [],
                    "writers": [],
                    "reader_names": [],
                    "writer_names": []
                }

    # For each global, find which functions reference it
    total_globals = len(globals_info)
    _LAST_SUB_PROGRESS[0] = -1
    for idx, (data_ea, info) in enumerate(globals_info.items()):
        print_sub_progress(idx + 1, total_globals, "data xrefs")
        for xref in idautils.XrefsTo(data_ea, 0):
            func = ida_funcs.get_func(xref.frm)
            if not func:
                continue
            func_addr = hex(func.start_ea)
            func_name = idc.get_func_name(func.start_ea)

            # Classify as read or write based on xref type
            if xref.type in (ida_xref.dr_W,):
                if func_addr not in info["writers"]:
                    info["writers"].append(func_addr)
                    info["writer_names"].append(func_name)
            else:
                if func_addr not in info["readers"]:
                    info["readers"].append(func_addr)
                    info["reader_names"].append(func_name)

    # Filter to only globals with references
    graph = {}
    for ea, info in globals_info.items():
        if info["readers"] or info["writers"]:
            graph[hex(ea)] = info

    with open(data_graph_path, 'w', encoding='utf-8') as f:
        json.dump(graph, f, indent=2)

    print("[*] Data Xref Graph Summary:")
    print("    Globals with references: {}".format(len(graph)))
    print("    Total reader edges: {}".format(sum(len(v["readers"]) for v in graph.values())))
    print("    Total writer edges: {}".format(sum(len(v["writers"]) for v in graph.values())))


def export_switch_tables(export_dir):
    """Export switch/jump tables"""
    switch_path = os.path.join(export_dir, "switch_tables.txt")

    count = 0
    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)
    _LAST_SUB_PROGRESS[0] = -1

    with open(switch_path, 'w', encoding='utf-8') as f:
        f.write("# Switch / Jump Tables\n")
        f.write("#" + "=" * 80 + "\n\n")

        for idx, func_ea in enumerate(all_funcs):
            print_sub_progress(idx + 1, total_funcs, "switch tables")
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue

            for head in idautils.Heads(func.start_ea, func.end_ea):
                si = ida_nalt.get_switch_info(head)
                if si is None:
                    continue

                func_name = idc.get_func_name(func_ea)
                ncases = si.get_jtable_size()

                f.write("=" * 60 + "\n")
                f.write("Switch at {} in {}\n".format(hex(head), func_name))
                f.write("  Jump table at: {}\n".format(hex(si.jumps)))
                f.write("  Cases: {}\n".format(ncases))
                f.write("  Element size: {}\n".format(si.get_jtable_element_size()))

                # Read jump targets
                elem_size = si.get_jtable_element_size()
                for i in range(ncases):
                    target_ea = si.jumps + i * elem_size
                    try:
                        if elem_size == 4:
                            offset = ida_bytes.get_dword(target_ea)
                        elif elem_size == 8:
                            offset = ida_bytes.get_qword(target_ea)
                        elif elem_size == 2:
                            offset = ida_bytes.get_word(target_ea)
                        else:
                            offset = ida_bytes.get_dword(target_ea)

                        # Target may be relative to switch base
                        if si.flags & 0x1:  # SWI_SIGNED
                            if elem_size == 4 and offset > 0x7FFFFFFF:
                                offset -= 0x100000000
                        target = si.elbase + offset if hasattr(si, 'elbase') else offset

                        f.write("  case {}: -> {}\n".format(i, hex(target)))
                    except:
                        f.write("  case {}: -> <read error>\n".format(i))

                f.write("\n")
                count += 1

    print("[*] Switch Tables Summary:")
    print("    Total switch tables: {}".format(count))


def export_exceptions(export_dir):
    """Export exception handlers / SEH / try-catch info"""
    exceptions_path = os.path.join(export_dir, "exceptions.txt")

    count = 0
    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)
    _LAST_SUB_PROGRESS[0] = -1

    with open(exceptions_path, 'w', encoding='utf-8') as f:
        f.write("# Exception Handlers / SEH / Try-Catch\n")
        f.write("#" + "=" * 80 + "\n\n")

        for idx, func_ea in enumerate(all_funcs):
            print_sub_progress(idx + 1, total_funcs, "exceptions")
            func = ida_funcs.get_func(func_ea)
            if func is None:
                continue

            func_name = idc.get_func_name(func_ea)

            # Check for exception-related function flags
            has_eh = False

            # Check if function has FUNC_FRAME flag (often set with SEH)
            if func.flags & ida_funcs.FUNC_FRAME:
                has_eh = True

            # Look for exception-related xrefs or names
            eh_indicators = []

            # Check for common exception handler patterns in callees
            for head in idautils.Heads(func.start_ea, func.end_ea):
                if idc.is_code(idc.get_full_flags(head)):
                    disasm = idc.GetDisasm(head)
                    # Check for exception-related instructions/patterns
                    if any(x in disasm.lower() for x in
                           ['__cxa_begin_catch', '__cxa_end_catch', '__cxa_throw',
                            '_except_handler', 'unwind', '__try', '__except',
                            'personality', 'lsda', 'landing_pad']):
                        eh_indicators.append((head, disasm))
                        has_eh = True

            if has_eh or eh_indicators:
                f.write("Function: {} at {} (flags=0x{:X})\n".format(
                    func_name, hex(func_ea), func.flags))
                if func.flags & ida_funcs.FUNC_FRAME:
                    f.write("  Has FUNC_FRAME flag\n")
                for addr, dis in eh_indicators:
                    f.write("  {} : {}\n".format(hex(addr), dis))
                f.write("\n")
                count += 1

    print("[*] Exceptions Summary:")
    print("    Functions with exception info: {}".format(count))


def export_fixups(export_dir):
    """Export segment relocations / fixups"""
    fixups_path = os.path.join(export_dir, "fixups.txt")

    count = 0
    type_names = {
        ida_fixup.FIXUP_OFF8: "OFF8",
        ida_fixup.FIXUP_OFF16: "OFF16",
        ida_fixup.FIXUP_OFF32: "OFF32",
        ida_fixup.FIXUP_OFF64: "OFF64",
    }
    _LAST_SUB_PROGRESS[0] = -1

    with open(fixups_path, 'w', encoding='utf-8') as f:
        f.write("# Relocations / Fixups\n")
        f.write("# Format: address | type | target_offset | flags | segment\n")
        f.write("#" + "=" * 80 + "\n\n")

        ea = ida_fixup.get_first_fixup_ea()
        while ea != ida_idaapi.BADADDR:
            if count % 100 == 0:
                print("    [{} fixups processed]".format(count))
            fd = ida_fixup.fixup_data_t()
            if ida_fixup.get_fixup(fd, ea):
                fix_type = fd.get_type()
                type_name = type_names.get(fix_type, "type_{}".format(fix_type))
                flags_str = []
                if fd.has_base():
                    flags_str.append("HAS_BASE")
                if fd.is_extdef():
                    flags_str.append("EXTDEF")

                seg = ida_segment.getseg(ea)
                seg_name = ida_segment.get_segm_name(seg) if seg else "?"

                f.write("{} | {} | off={} | {} | {}\n".format(
                    hex(ea), type_name, hex(fd.off),
                    ",".join(flags_str) if flags_str else "-", seg_name))
                count += 1

            ea = ida_fixup.get_next_fixup_ea(ea)

            if count % 1000 == 0:
                clear_undo_buffer()

    print("[*] Fixups Summary:")
    print("    Total fixups/relocations: {}".format(count))


def export_microcode(export_dir):
    """Export Hex-Rays microcode/ctree intermediate representation"""
    micro_dir = os.path.join(export_dir, "microcode")
    ensure_dir(micro_dir)

    exported = 0
    has_hexrays = False
    try:
        has_hexrays = ida_hexrays.init_hexrays_plugin()
    except:
        pass

    if not has_hexrays:
        print("[*] Microcode Summary:")
        print("    Hex-Rays not available, skipping")
        return

    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)
    _LAST_SUB_PROGRESS[0] = -1

    for idx, func_ea in enumerate(all_funcs):
        print_sub_progress(idx + 1, total_funcs, "microcode")
        func = ida_funcs.get_func(func_ea)
        if func is None or func.flags & ida_funcs.FUNC_LIB:
            continue

        func_name = idc.get_func_name(func_ea)

        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc is None:
                continue

            # Get the ctree pseudocode with types
            lines = []
            lines.append("// Function: {} at {}".format(func_name, hex(func_ea)))
            lines.append("// Hex-Rays ctree output")
            lines.append("")

            # Get pseudocode lines with all detail
            sv = cfunc.get_pseudocode()
            for i in range(sv.size()):
                line = ida_lines.tag_remove(sv[i].line) if hasattr(ida_lines, 'tag_remove') else str(sv[i].line)
                lines.append(line)

            output_path = os.path.join(micro_dir, "{:X}.ctree".format(func_ea))
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            exported += 1

            cfunc = None

        except:
            pass

        if exported % 200 == 0 and exported > 0:
            clear_undo_buffer()

    print("[*] Microcode Summary:")
    print("    Exported ctree for {} functions".format(exported))


def export_objc_metadata(export_dir):
    """Export Objective-C selectors/classes for iOS/macOS binaries"""
    objc_path = os.path.join(export_dir, "objc_metadata.txt")

    count = 0
    with open(objc_path, 'w', encoding='utf-8') as f:
        f.write("# Objective-C Metadata\n")
        f.write("#" + "=" * 80 + "\n\n")

        # Look for ObjC-related segments
        objc_segments = []
        for seg_ea in idautils.Segments():
            seg_name = idc.get_segm_name(seg_ea)
            if seg_name and ('objc' in seg_name.lower() or '__OBJC' in seg_name):
                objc_segments.append((seg_ea, seg_name))

        if not objc_segments:
            # Check for ObjC-related names
            for ea, name in idautils.Names():
                if any(x in name for x in ['_OBJC_CLASS_', '_OBJC_SELECTOR_',
                                            'objc_msgSend', '_OBJC_METACLASS_',
                                            '_OBJC_IVAR_', '__objc_methname',
                                            '+[', '-[']):
                    kind = "selector" if 'SEL' in name or 'msgSend' in name else \
                           "class" if 'CLASS' in name else \
                           "metaclass" if 'METACLASS' in name else \
                           "ivar" if 'IVAR' in name else "method"
                    f.write("{} | {} | {}\n".format(hex(ea), kind, name))
                    count += 1
        else:
            for seg_ea, seg_name in objc_segments:
                f.write("\n## Segment: {}\n".format(seg_name))
                seg_start = idc.get_segm_start(seg_ea)
                seg_end = idc.get_segm_end(seg_ea)
                for ea, name in idautils.Names():
                    if seg_start <= ea < seg_end:
                        f.write("{} | {}\n".format(hex(ea), name))
                        count += 1

    print("[*] ObjC Metadata Summary:")
    print("    Total ObjC items: {}".format(count))


def export_debug_info(export_dir):
    """Export debug info mapping (source file/line if DWARF present)"""
    debug_path = os.path.join(export_dir, "debug_info.txt")

    count = 0
    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)
    _LAST_SUB_PROGRESS[0] = -1

    with open(debug_path, 'w', encoding='utf-8') as f:
        f.write("# Debug Information (Source Mappings)\n")
        f.write("#" + "=" * 80 + "\n\n")

        # Check for source line info via idc.get_sourcefile / get_source_linnum
        for idx, func_ea in enumerate(all_funcs):
            print_sub_progress(idx + 1, total_funcs, "debug info")
            func = ida_funcs.get_func(func_ea)
            if func is None:
                continue

            func_name = idc.get_func_name(func_ea)
            func_has_debug = False

            for head in idautils.Heads(func.start_ea, func.end_ea):
                try:
                    srcfile = idc.get_sourcefile(head)
                    srcline = idc.get_source_linnum(head)
                    if srcfile or srcline:
                        if not func_has_debug:
                            f.write("\n{} ({})\n".format(func_name, hex(func_ea)))
                            func_has_debug = True
                        f.write("  {} | {}:{}\n".format(
                            hex(head),
                            srcfile if srcfile else "?",
                            srcline if srcline else "?"))
                        count += 1
                except:
                    pass

    print("[*] Debug Info Summary:")
    print("    Source line mappings: {}".format(count))


def export_colors(export_dir):
    """Export analyst color markings"""
    colors_path = os.path.join(export_dir, "colors.txt")

    count = 0
    total_segs = ida_segment.get_segm_qty()
    _LAST_SUB_PROGRESS[0] = -1

    with open(colors_path, 'w', encoding='utf-8') as f:
        f.write("# Color Markings\n")
        f.write("# Format: address | color (RRGGBB) | context\n")
        f.write("#" + "=" * 80 + "\n\n")

        for seg_idx in range(total_segs):
            seg = ida_segment.getnseg(seg_idx)
            if seg is None:
                continue

            print_sub_progress(seg_idx + 1, total_segs, "colors")
            for head in idautils.Heads(seg.start_ea, seg.end_ea):
                color = ida_nalt.get_item_color(head)
                if color != 0xFFFFFFFF and color != ida_idaapi.BADADDR:
                    # Get context
                    func = ida_funcs.get_func(head)
                    func_name = idc.get_func_name(func.start_ea) if func else ""
                    name = idc.get_name(head) if idc.get_name(head) else ""
                    context = func_name if func_name else name

                    f.write("{} | #{:06X} | {}\n".format(hex(head), color & 0xFFFFFF, context))
                    count += 1

    print("[*] Colors Summary:")
    print("    Colored items: {}".format(count))


def export_custom_data_types(export_dir):
    """Export custom struct instances applied at specific addresses"""
    custom_path = os.path.join(export_dir, "applied_structs.txt")

    count = 0
    til = ida_typeinf.get_idati()
    all_names = list(idautils.Names())
    total_names = len(all_names)
    _LAST_SUB_PROGRESS[0] = -1

    with open(custom_path, 'w', encoding='utf-8') as f:
        f.write("# Applied Structure Types at Addresses\n")
        f.write("# Format: address | name | applied_type | size\n")
        f.write("#" + "=" * 80 + "\n\n")

        for idx, (ea, name) in enumerate(all_names):
            print_sub_progress(idx + 1, total_names, "applied structs")
            flags = idc.get_full_flags(ea)
            if not ida_bytes.is_data(flags):
                continue

            tinfo = ida_typeinf.tinfo_t()
            if not ida_nalt.get_tinfo(tinfo, ea):
                continue

            # Check if it's a struct/union type
            if tinfo.is_struct() or tinfo.is_union() or tinfo.is_array():
                size = ida_bytes.get_item_size(ea)
                type_str = tinfo.dstr()
                seg = ida_segment.getseg(ea)
                seg_name = ida_segment.get_segm_name(seg) if seg else "?"

                f.write("{} | {} | {} | size={} | seg={}\n".format(
                    hex(ea), name, type_str, size, seg_name))
                count += 1

    print("[*] Applied Structs Summary:")
    print("    Addresses with struct types: {}".format(count))


def export_entry_points(export_dir):
    """Export all entry points with detailed info"""
    entry_path = os.path.join(export_dir, "entry_points.txt")

    count = 0
    with open(entry_path, 'w', encoding='utf-8') as f:
        f.write("# Entry Points\n")
        f.write("# Format: ordinal | address | name | is_function\n")
        f.write("#" + "=" * 80 + "\n\n")

        # Main entry point
        main_entry = idc.get_inf_attr(idc.INF_START_EA)
        if main_entry != ida_idaapi.BADADDR:
            f.write("MAIN_ENTRY: {} ({})\n\n".format(hex(main_entry), idc.get_name(main_entry)))

        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)

            func = ida_funcs.get_func(ea)
            is_func = func is not None

            f.write("{} | {} | {} | func={}\n".format(ordinal, hex(ea), name or "?", is_func))
            count += 1

    print("[*] Entry Points Summary:")
    print("    Total entry points: {}".format(count))


def export_binary_info(export_dir):
    """Export overall binary metadata/info"""
    info_path = os.path.join(export_dir, "binary_info.txt")

    with open(info_path, 'w', encoding='utf-8') as f:
        f.write("# Binary Information\n")
        f.write("#" + "=" * 80 + "\n\n")

        # File info
        f.write("Input file: {}\n".format(ida_nalt.get_input_file_path()))
        f.write("Input MD5: {}\n".format(ida_nalt.retrieve_input_file_md5().hex() if hasattr(ida_nalt.retrieve_input_file_md5(), 'hex') else str(ida_nalt.retrieve_input_file_md5())))

        # Architecture
        is_64 = ida_ida.inf_is_64bit()
        is_32 = ida_ida.inf_is_32bit_exactly()
        f.write("Architecture: {}\n".format("64-bit" if is_64 else "32-bit" if is_32 else "16-bit"))
        f.write("Processor: {}\n".format(ida_idp.get_idp_name()))

        # Endianness
        f.write("Endian: {}\n".format("big" if ida_ida.inf_is_be() else "little"))

        # File type
        f.write("File type: {}\n".format(ida_ida.inf_get_filetype()))

        # Compiler
        try:
            cc = ida_typeinf.get_compiler_name(ida_ida.inf_get_cc_id())
            f.write("Compiler: {}\n".format(cc))
        except:
            pass

        # Statistics
        func_count = sum(1 for _ in idautils.Functions())
        seg_count = ida_segment.get_segm_qty()
        name_count = sum(1 for _ in idautils.Names())

        f.write("\nStatistics:\n")
        f.write("  Functions: {}\n".format(func_count))
        f.write("  Segments: {}\n".format(seg_count))
        f.write("  Named items: {}\n".format(name_count))

        # Image base
        try:
            f.write("  Image base: {}\n".format(hex(ida_nalt.get_imagebase())))
        except:
            pass

        # Min/max addresses
        try:
            f.write("  Min EA: {}\n".format(hex(idc.get_inf_attr(idc.INF_MIN_EA))))
            f.write("  Max EA: {}\n".format(hex(idc.get_inf_attr(idc.INF_MAX_EA))))
        except:
            pass

    print("[*] Binary info exported")


def export_string_xrefs(export_dir):
    """Export which functions reference which strings"""
    sxref_path = os.path.join(export_dir, "string_xrefs.txt")

    count = 0
    str_idx = 0
    _LAST_SUB_PROGRESS[0] = -1

    with open(sxref_path, 'w', encoding='utf-8') as f:
        f.write("# String Cross-References\n")
        f.write("# Format: string_addr | string_value | referencing_functions\n")
        f.write("#" + "=" * 80 + "\n\n")

        for s in idautils.Strings():
            if str_idx % 100 == 0:
                print("    [{} strings processed]".format(str_idx))
            str_idx += 1
            try:
                string_content = str(s).replace('\n', '\\n').replace('\r', '\\r')
            except:
                continue

            refs = []
            for xref in idautils.XrefsTo(s.ea, 0):
                func = ida_funcs.get_func(xref.frm)
                if func:
                    fname = idc.get_func_name(func.start_ea)
                    ref_entry = "{}@{}".format(fname, hex(xref.frm))
                    if ref_entry not in refs:
                        refs.append(ref_entry)

            if refs:
                f.write("{} | {} | {}\n".format(
                    hex(s.ea),
                    string_content[:120],
                    ", ".join(refs)))
                count += 1

            if count % 500 == 0 and count > 0:
                clear_undo_buffer()

    print("[*] String Xrefs Summary:")
    print("    Strings with references: {}".format(count))


def export_function_chunks(export_dir):
    """Export non-contiguous function chunks (scattered code)"""
    chunks_path = os.path.join(export_dir, "function_chunks.txt")

    count = 0
    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)
    _LAST_SUB_PROGRESS[0] = -1

    with open(chunks_path, 'w', encoding='utf-8') as f:
        f.write("# Function Chunks (Non-Contiguous Code)\n")
        f.write("# Functions with multiple code chunks (e.g., separated by optimization)\n")
        f.write("#" + "=" * 80 + "\n\n")

        for idx, func_ea in enumerate(all_funcs):
            print_sub_progress(idx + 1, total_funcs, "function chunks")
            chunks = list(idautils.Chunks(func_ea))
            if len(chunks) <= 1:
                continue

            func_name = idc.get_func_name(func_ea)
            f.write("{} at {} ({} chunks):\n".format(func_name, hex(func_ea), len(chunks)))
            total_size = 0
            for chunk_start, chunk_end in chunks:
                size = chunk_end - chunk_start
                total_size += size
                f.write("  {} - {} (size=0x{:X})\n".format(hex(chunk_start), hex(chunk_end), size))
            f.write("  total size: 0x{:X}\n\n".format(total_size))
            count += 1

    print("[*] Function Chunks Summary:")
    print("    Functions with multiple chunks: {}".format(count))


def export_undefined_ranges(export_dir):
    """Export undefined/unexplored byte ranges"""
    undef_path = os.path.join(export_dir, "undefined_ranges.txt")

    count = 0
    total_bytes = 0
    total_segs = ida_segment.get_segm_qty()
    _LAST_SUB_PROGRESS[0] = -1

    with open(undef_path, 'w', encoding='utf-8') as f:
        f.write("# Undefined / Unexplored Byte Ranges\n")
        f.write("# Regions where IDA couldn't determine code or data\n")
        f.write("#" + "=" * 80 + "\n\n")

        for seg_idx in range(total_segs):
            print_sub_progress(seg_idx + 1, total_segs, "undefined ranges")
            seg = ida_segment.getnseg(seg_idx)
            if seg is None:
                continue

            seg_name = ida_segment.get_segm_name(seg)
            range_start = None
            range_len = 0

            ea = seg.start_ea
            while ea < seg.end_ea:
                flags = idc.get_full_flags(ea)
                is_undef = ida_bytes.is_unknown(flags)

                if is_undef:
                    if range_start is None:
                        range_start = ea
                    range_len += 1
                else:
                    if range_start is not None and range_len > 0:
                        f.write("{} - {} | size=0x{:X} | seg={}\n".format(
                            hex(range_start), hex(range_start + range_len), range_len, seg_name))
                        total_bytes += range_len
                        count += 1
                        range_start = None
                        range_len = 0
                ea += 1

            # Close any open range
            if range_start is not None and range_len > 0:
                f.write("{} - {} | size=0x{:X} | seg={}\n".format(
                    hex(range_start), hex(range_start + range_len), range_len, seg_name))
                total_bytes += range_len
                count += 1

    f_summary = open(undef_path, 'a')
    f_summary.write("\n# Total: {} ranges, 0x{:X} bytes undefined\n".format(count, total_bytes))
    f_summary.close()

    print("[*] Undefined Ranges Summary:")
    print("    Ranges: {}, Total bytes: 0x{:X}".format(count, total_bytes))


def export_hidden_ranges(export_dir):
    """Export analyst-hidden/collapsed code ranges"""
    hidden_path = os.path.join(export_dir, "hidden_ranges.txt")

    count = 0
    with open(hidden_path, 'w', encoding='utf-8') as f:
        f.write("# Hidden / Collapsed Ranges\n")
        f.write("# Regions the analyst has collapsed in IDA\n")
        f.write("#" + "=" * 80 + "\n\n")

        qty = ida_bytes.get_hidden_range_qty()
        for i in range(qty):
            hr = ida_bytes.getn_hidden_range(i)
            if hr is None:
                continue

            desc = hr.description if hasattr(hr, 'description') else ""
            f.write("{} - {} | size=0x{:X} | {}\n".format(
                hex(hr.start_ea), hex(hr.end_ea),
                hr.end_ea - hr.start_ea,
                desc))
            count += 1

    print("[*] Hidden Ranges Summary:")
    print("    Hidden ranges: {}".format(count))


def export_loaded_tils(export_dir):
    """Export loaded type libraries"""
    tils_path = os.path.join(export_dir, "loaded_tils.txt")

    with open(tils_path, 'w', encoding='utf-8') as f:
        f.write("# Loaded Type Libraries (TILs)\n")
        f.write("#" + "=" * 80 + "\n\n")

        til = ida_typeinf.get_idati()
        f.write("Main TIL: {}\n".format(til.name))
        f.write("Description: {}\n".format(til.desc))

        ordinal_count = ida_typeinf.get_ordinal_count(til)
        f.write("Local types: {}\n\n".format(ordinal_count))

        try:
            nbases = til.nbases
            f.write("Loaded base libraries ({}):\n".format(nbases))
            for i in range(nbases):
                base = til.base(i)
                f.write("  [{}] {} - {}\n".format(i, base.name, base.desc))
                f.write("       Types: {}\n".format(ida_typeinf.get_ordinal_count(base)))
        except Exception as e:
            f.write("  Could not enumerate base TILs: {}\n".format(str(e)))

    print("[*] Loaded TILs exported")


def export_imports_grouped(export_dir):
    """Export imports grouped by module/DLL"""
    imports_grouped_path = os.path.join(export_dir, "imports_grouped.txt")

    total = 0
    with open(imports_grouped_path, 'w', encoding='utf-8') as f:
        f.write("# Imports Grouped by Module\n")
        f.write("#" + "=" * 80 + "\n\n")

        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            f.write("## {} (module {})\n".format(module_name, i))

            funcs = []
            def imp_cb(ea, name, ordinal):
                funcs.append((ea, name, ordinal))
                return True
            ida_nalt.enum_import_names(i, imp_cb)

            for ea, name, ordinal in funcs:
                if name:
                    f.write("  {} | {}\n".format(hex(ea), name))
                else:
                    f.write("  {} | ordinal_{}\n".format(hex(ea), ordinal))
                total += 1
            f.write("\n")

    print("[*] Grouped Imports Summary:")
    print("    Modules: {}, Total imports: {}".format(nimps, total))


def export_problems(export_dir):
    """Export IDA analysis problems/warnings"""
    problems_path = os.path.join(export_dir, "problems.txt")

    problem_types = [
        (ida_problems.PR_ATTN, "ATTN"),
        (ida_problems.PR_BADSTACK, "BAD_STACK"),
        (ida_problems.PR_COLLISION, "COLLISION"),
        (ida_problems.PR_DECIMP, "DEC_IMP"),
        (ida_problems.PR_DISASM, "DISASM"),
        (ida_problems.PR_HEAD, "HEAD"),
        (ida_problems.PR_ILLADDR, "ILL_ADDR"),
        (ida_problems.PR_JUMP, "JUMP"),
        (ida_problems.PR_MANYLINES, "MANY_LINES"),
        (ida_problems.PR_NOBASE, "NO_BASE"),
        (ida_problems.PR_NOCMT, "NO_CMT"),
        (ida_problems.PR_NOFOP, "NO_FOP"),
        (ida_problems.PR_NONAME, "NO_NAME"),
        (ida_problems.PR_NOXREFS, "NO_XREFS"),
        (ida_problems.PR_ROLLED, "ROLLED"),
    ]

    count = 0
    with open(problems_path, 'w', encoding='utf-8') as f:
        f.write("# IDA Analysis Problems\n")
        f.write("# Issues found during auto-analysis\n")
        f.write("#" + "=" * 80 + "\n\n")

        for prob_type, prob_name in problem_types:
            ea = ida_problems.get_problem(prob_type, 0)
            type_count = 0
            while ea != ida_idaapi.BADADDR:
                desc = ida_problems.get_problem_desc(prob_type, ea)
                func = ida_funcs.get_func(ea)
                func_name = idc.get_func_name(func.start_ea) if func else ""
                f.write("{} | {} | {} | {}\n".format(
                    hex(ea), prob_name, func_name, desc if desc else ""))
                type_count += 1
                count += 1
                ea = ida_problems.get_problem(prob_type, ea + 1)

    print("[*] Problems Summary:")
    print("    Total analysis problems: {}".format(count))


def export_operand_types(export_dir):
    """Export detailed operand type info for instructions with non-trivial operands"""
    opinfo_path = os.path.join(export_dir, "operand_info.txt")

    count = 0
    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)
    _LAST_SUB_PROGRESS[0] = -1

    with open(opinfo_path, 'w', encoding='utf-8') as f:
        f.write("# Detailed Operand Information\n")
        f.write("# Instructions with offset/struct/enum operand representations\n")
        f.write("#" + "=" * 80 + "\n\n")

        OP_NAMES = {
            0: "void", 1: "reg", 2: "mem", 3: "phrase",
            4: "displ", 5: "imm", 6: "far", 7: "near"
        }

        for idx, func_ea in enumerate(all_funcs):
            print_sub_progress(idx + 1, total_funcs, "operand types")
            func = ida_funcs.get_func(func_ea)
            if func is None or func.flags & ida_funcs.FUNC_LIB:
                continue

            func_name = idc.get_func_name(func_ea)
            func_written = False

            for head in idautils.Heads(func.start_ea, func.end_ea):
                flags = idc.get_full_flags(head)
                if not idc.is_code(flags):
                    continue

                has_interesting = False
                ops_info = []
                for n in range(8):
                    ot = idc.get_operand_type(head, n)
                    if ot == 0:
                        break
                    ov = idc.get_operand_value(head, n)

                    # Check if operand has special representation (offset, enum, struct)
                    op_repr = ""
                    if ot == 5:  # immediate
                        # Check if it's been converted to an offset or enum
                        if idc.is_defarg0(flags) and n == 0:
                            op_repr = "custom_repr"
                            has_interesting = True
                        elif idc.is_defarg1(flags) and n == 1:
                            op_repr = "custom_repr"
                            has_interesting = True

                    type_name = OP_NAMES.get(ot, "type_{}".format(ot))
                    ops_info.append("op{}={}({})".format(n, type_name, hex(ov) if ov else "0"))

                if has_interesting and ops_info:
                    if not func_written:
                        f.write("\n## {} ({})\n".format(func_name, hex(func_ea)))
                        func_written = True
                    disasm = idc.GetDisasm(head)
                    f.write("  {} | {} | {}\n".format(hex(head), disasm, " ".join(ops_info)))
                    count += 1

    print("[*] Operand Info Summary:")
    print("    Instructions with special operands: {}".format(count))


# ============================================================================
# Consolidated Single-Pass Export Functions
# ============================================================================

def export_per_function_pass(export_dir, skip_tasks=None):
    """Single pass over all functions, writing to multiple output files simultaneously.

    Replaces: export_function_prototypes, export_stack_frames, export_callgraph,
    export_disassembly, export_function_chunks, export_flirt_matches,
    export_switch_tables, export_exceptions, export_debug_info,
    export_operand_types, export_comments (function comments),
    export_decompiled_functions, export_microcode
    """
    # Determine which sub-tasks to perform
    do_prototypes = not skip_tasks or "Function prototypes" not in skip_tasks
    do_stack_frames = not skip_tasks or "Stack frames" not in skip_tasks
    do_callgraph = not skip_tasks or "Call graph" not in skip_tasks
    do_disassembly = not skip_tasks or "Disassembly" not in skip_tasks
    do_chunks = not skip_tasks or "Function chunks" not in skip_tasks
    do_flirt = not skip_tasks or "FLIRT matches" not in skip_tasks
    do_switch = not skip_tasks or "Switch tables" not in skip_tasks
    do_exceptions = not skip_tasks or "Exceptions" not in skip_tasks
    do_debug = not skip_tasks or "Debug info" not in skip_tasks
    do_operand = not skip_tasks or "Operand info" not in skip_tasks
    do_comments = not skip_tasks or "Comments and labels" not in skip_tasks
    do_decompile = not skip_tasks or "Decompiled functions" not in skip_tasks
    do_microcode = not skip_tasks or "Microcode/ctree" not in skip_tasks

    has_hexrays = False
    try:
        has_hexrays = ida_hexrays.init_hexrays_plugin()
    except:
        pass
    if not has_hexrays:
        do_decompile = False
        do_microcode = False
        do_stack_frames_hexrays = False
    else:
        do_stack_frames_hexrays = do_stack_frames

    # Create directories
    if do_disassembly:
        disasm_dir = os.path.join(export_dir, "disassembly")
        ensure_dir(disasm_dir)
    if do_decompile:
        decompile_dir = os.path.join(export_dir, "decompile")
        ensure_dir(decompile_dir)
    if do_microcode:
        micro_dir = os.path.join(export_dir, "microcode")
        ensure_dir(micro_dir)

    # Open all output files
    files = {}
    try:
        if do_prototypes:
            files['prototypes'] = open(os.path.join(export_dir, "prototypes.txt"), 'w', encoding='utf-8')
            files['prototypes'].write("# Function Prototypes\n")
            files['prototypes'].write("# Format: address | name | prototype\n")
            files['prototypes'].write("#" + "=" * 80 + "\n\n")

        if do_stack_frames:
            files['stack_frames'] = open(os.path.join(export_dir, "stack_frames.txt"), 'w', encoding='utf-8')
            files['stack_frames'].write("# Stack Frame Layouts\n")
            files['stack_frames'].write("#" + "=" * 80 + "\n\n")

        if do_chunks:
            files['chunks'] = open(os.path.join(export_dir, "function_chunks.txt"), 'w', encoding='utf-8')
            files['chunks'].write("# Function Chunks (Non-Contiguous Code)\n")
            files['chunks'].write("# Functions with multiple code chunks (e.g., separated by optimization)\n")
            files['chunks'].write("#" + "=" * 80 + "\n\n")

        if do_flirt:
            files['flirt'] = open(os.path.join(export_dir, "flirt_matches.txt"), 'w', encoding='utf-8')
            files['flirt'].write("# FLIRT Signature Matches\n")
            files['flirt'].write("# Format: address | name | flags | library_flag\n")
            files['flirt'].write("#" + "=" * 80 + "\n\n")

        if do_switch:
            files['switch'] = open(os.path.join(export_dir, "switch_tables.txt"), 'w', encoding='utf-8')
            files['switch'].write("# Switch / Jump Tables\n")
            files['switch'].write("#" + "=" * 80 + "\n\n")

        if do_exceptions:
            files['exceptions'] = open(os.path.join(export_dir, "exceptions.txt"), 'w', encoding='utf-8')
            files['exceptions'].write("# Exception Handlers / SEH / Try-Catch\n")
            files['exceptions'].write("#" + "=" * 80 + "\n\n")

        if do_debug:
            files['debug'] = open(os.path.join(export_dir, "debug_info.txt"), 'w', encoding='utf-8')
            files['debug'].write("# Debug Information (Source Mappings)\n")
            files['debug'].write("#" + "=" * 80 + "\n\n")

        if do_operand:
            files['operand'] = open(os.path.join(export_dir, "operand_info.txt"), 'w', encoding='utf-8')
            files['operand'].write("# Detailed Operand Information\n")
            files['operand'].write("# Instructions with offset/struct/enum operand representations\n")
            files['operand'].write("#" + "=" * 80 + "\n\n")

        if do_comments:
            files['comments'] = open(os.path.join(export_dir, "comments.txt"), 'w', encoding='utf-8')
            files['comments'].write("# Comments and Labels\n")
            files['comments'].write("#" + "=" * 80 + "\n\n")
            files['comments'].write("## Function Comments\n")
            files['comments'].write("# Format: address | name | comment_type | comment\n")
            files['comments'].write("#" + "-" * 60 + "\n\n")

        # Counters
        counts = {
            'prototypes': 0, 'stack_frames': 0, 'callgraph_edges': 0,
            'disasm_exported': 0, 'disasm_skipped': 0, 'chunks': 0,
            'flirt': 0, 'switch': 0, 'exceptions': 0, 'debug': 0,
            'operand': 0, 'comments': 0, 'decompiled': 0, 'microcode': 0,
        }

        # Callgraph data (collected in memory, written at end)
        callgraph = {}
        func_names_map = {}

        # Decompile resume logic
        processed_addrs = set()
        failed_funcs = []
        skipped_funcs = []
        if do_decompile:
            processed_addrs, prev_failed, prev_skipped = load_progress(export_dir)
            failed_funcs.extend(prev_failed)
            skipped_funcs.extend(prev_skipped)

        OP_NAMES = {
            0: "void", 1: "reg", 2: "mem", 3: "phrase",
            4: "displ", 5: "imm", 6: "far", 7: "near"
        }

        all_funcs = list(idautils.Functions())
        total_funcs = len(all_funcs)
        _LAST_SUB_PROGRESS[0] = -1

        active_tasks = []
        if do_prototypes: active_tasks.append('prototypes')
        if do_stack_frames: active_tasks.append('stack_frames')
        if do_callgraph: active_tasks.append('callgraph')
        if do_disassembly: active_tasks.append('disassembly')
        if do_chunks: active_tasks.append('chunks')
        if do_flirt: active_tasks.append('flirt')
        if do_switch: active_tasks.append('switch')
        if do_exceptions: active_tasks.append('exceptions')
        if do_debug: active_tasks.append('debug')
        if do_operand: active_tasks.append('operand')
        if do_comments: active_tasks.append('comments')
        if do_decompile: active_tasks.append('decompile')
        if do_microcode: active_tasks.append('microcode')
        print("[*] Per-function pass: {} functions, sub-tasks: {}".format(
            total_funcs, ", ".join(active_tasks)))

        for idx, func_ea in enumerate(all_funcs):
            print_sub_progress(idx + 1, total_funcs, "functions")

            func = ida_funcs.get_func(func_ea)
            func_name = idc.get_func_name(func_ea)
            is_lib = func is not None and bool(func.flags & ida_funcs.FUNC_LIB)
            is_thunk = func is not None and bool(func.flags & ida_funcs.FUNC_THUNK)

            # --- Prototypes ---
            if do_prototypes:
                decl_str = None
                try:
                    decl_str = idc.get_type(func_ea)
                except:
                    pass
                if not decl_str:
                    try:
                        tinfo = ida_typeinf.tinfo_t()
                        if ida_nalt.get_tinfo(tinfo, func_ea):
                            decl_str = tinfo.dstr()
                    except:
                        pass
                if not decl_str:
                    try:
                        decl_str = idc.guess_type(func_ea)
                    except:
                        pass
                if decl_str:
                    files['prototypes'].write("{} | {} | {}\n".format(hex(func_ea), func_name, decl_str))
                else:
                    files['prototypes'].write("{} | {} | <no type info>\n".format(hex(func_ea), func_name))
                counts['prototypes'] += 1

            # --- Comments (function comments) ---
            if do_comments:
                cmt = idc.get_func_cmt(func_ea, 0)
                if cmt:
                    files['comments'].write("{} | {} | func_comment | {}\n".format(
                        hex(func_ea), func_name, cmt.replace('\n', '\\n')))
                    counts['comments'] += 1
                cmt_rep = idc.get_func_cmt(func_ea, 1)
                if cmt_rep:
                    files['comments'].write("{} | {} | func_comment_rep | {}\n".format(
                        hex(func_ea), func_name, cmt_rep.replace('\n', '\\n')))
                    counts['comments'] += 1

            # --- FLIRT matches ---
            if do_flirt and func is not None and (is_lib or is_thunk):
                flags_str = []
                if is_lib:
                    flags_str.append("FUNC_LIB")
                if is_thunk:
                    flags_str.append("FUNC_THUNK")
                try:
                    if func.flags & ida_funcs.FUNC_STATIC:
                        flags_str.append("FUNC_STATIC")
                except:
                    pass
                files['flirt'].write("{} | {} | {} | size={}\n".format(
                    hex(func_ea), func_name, ",".join(flags_str),
                    func.end_ea - func.start_ea))
                counts['flirt'] += 1

            # --- Function chunks ---
            if do_chunks:
                chunks = list(idautils.Chunks(func_ea))
                if len(chunks) > 1:
                    files['chunks'].write("{} at {} ({} chunks):\n".format(func_name, hex(func_ea), len(chunks)))
                    total_size = 0
                    for chunk_start, chunk_end in chunks:
                        size = chunk_end - chunk_start
                        total_size += size
                        files['chunks'].write("  {} - {} (size=0x{:X})\n".format(hex(chunk_start), hex(chunk_end), size))
                    files['chunks'].write("  total size: 0x{:X}\n\n".format(total_size))
                    counts['chunks'] += 1

            # --- Callgraph (collect in memory) ---
            if do_callgraph:
                func_names_map[func_ea] = func_name
                callees = get_callees(func_ea)
                addr_key = hex(func_ea)
                callgraph[addr_key] = {
                    "name": func_names_map.get(func_ea, "unknown"),
                    "calls": [hex(c) for c in callees],
                    "call_names": [func_names_map.get(c, idc.get_func_name(c) or "unknown") for c in callees]
                }

            # Skip library functions for the heavier per-instruction analyses
            if func is None or is_lib:
                if do_decompile and func_ea not in processed_addrs:
                    if func is None:
                        skipped_funcs.append((func_ea, func_name, "not a valid function"))
                    else:
                        skipped_funcs.append((func_ea, func_name, "library function"))
                    processed_addrs.add(func_ea)
                continue

            # --- Stack frames ---
            if do_stack_frames:
                frsize = func.frsize
                argsize = func.argsize
                frregs = func.frregs
                if frsize > 0 or argsize > 0:
                    files['stack_frames'].write("=" * 60 + "\n")
                    files['stack_frames'].write("Function: {} at {}\n".format(func_name, hex(func_ea)))
                    files['stack_frames'].write("  frame_size={} arg_size={} saved_regs={}\n".format(frsize, argsize, frregs))
                    try:
                        ti = ida_typeinf.tinfo_t()
                        if ida_frame.get_func_frame(ti, func):
                            files['stack_frames'].write("  Frame type: {}\n".format(ti.dstr()))
                            if ti.is_struct():
                                for i, udm in enumerate(ti.iter_struct()):
                                    member_name = udm.name if udm.name else "var_{}".format(i)
                                    member_type = udm.type.dstr() if udm.type else "?"
                                    member_size = udm.size // 8 if udm.size else 0
                                    offset = udm.offset // 8
                                    files['stack_frames'].write("    +0x{:X} {} : {} (size=0x{:X})\n".format(
                                        offset, member_name, member_type, member_size))
                    except:
                        pass
                    # Hex-Rays lvars will be written below from the shared cfunc
                    counts['stack_frames'] += 1

            # --- Decompile once, reuse for decompile/microcode/stack_frames ---
            cfunc = None
            if do_decompile or do_microcode or do_stack_frames_hexrays:
                if func_ea not in processed_addrs or (not do_decompile):
                    try:
                        cfunc = ida_hexrays.decompile(func_ea)
                    except ida_hexrays.DecompilationFailure as e:
                        if do_decompile and func_ea not in processed_addrs:
                            failed_funcs.append((func_ea, func_name, "decompilation failure: {}".format(str(e))))
                            processed_addrs.add(func_ea)
                    except Exception as e:
                        if do_decompile and func_ea not in processed_addrs:
                            failed_funcs.append((func_ea, func_name, "unexpected error: {}".format(str(e))))
                            processed_addrs.add(func_ea)

            # Write stack_frames Hex-Rays local vars
            if do_stack_frames_hexrays and cfunc is not None:
                frsize = func.frsize
                argsize = func.argsize
                if frsize > 0 or argsize > 0:
                    lvars = cfunc.get_lvars()
                    if lvars and len(lvars) > 0:
                        files['stack_frames'].write("  Hex-Rays local variables ({}):\n".format(len(lvars)))
                        for lv in lvars:
                            ty = lv.type()
                            tstr = ty.dstr() if ty else "?"
                            # IDA 9: these may be properties or methods
                            try:
                                is_arg = lv.is_arg_var() if callable(lv.is_arg_var) else lv.is_arg_var
                            except:
                                is_arg = False
                            kind = "arg" if is_arg else "local"
                            loc = ""
                            try:
                                is_stk = lv.is_stk_var() if callable(lv.is_stk_var) else lv.is_stk_var
                            except:
                                is_stk = False
                            try:
                                is_reg = lv.is_reg_var() if callable(lv.is_reg_var) else lv.is_reg_var
                            except:
                                is_reg = False
                            if is_stk:
                                try:
                                    loc = " [stack+0x{:X}]".format(lv.get_stkoff())
                                except:
                                    loc = " [stack]"
                            elif is_reg:
                                loc = " [reg]"
                            files['stack_frames'].write("    {} {} : {}{}\n".format(kind, lv.name, tstr, loc))
                    files['stack_frames'].write("\n")

            # Write decompiled output
            if do_decompile and cfunc is not None and func_ea not in processed_addrs:
                dec_str = str(cfunc)
                if dec_str and len(dec_str.strip()) > 0:
                    callers = get_callers(func_ea)
                    callees_dec = get_callees(func_ea)
                    output_lines = []
                    output_lines.append("/*")
                    output_lines.append(" * func-name: {}".format(func_name))
                    output_lines.append(" * func-address: {}".format(hex(func_ea)))
                    output_lines.append(" * callers: {}".format(format_address_list(callers) if callers else "none"))
                    output_lines.append(" * callees: {}".format(format_address_list(callees_dec) if callees_dec else "none"))
                    output_lines.append(" */")
                    output_lines.append("")
                    output_lines.append(dec_str)
                    output_path = os.path.join(decompile_dir, "{:X}.c".format(func_ea))
                    try:
                        with open(output_path, 'w', encoding='utf-8') as df:
                            df.write('\n'.join(output_lines))
                        counts['decompiled'] += 1
                    except IOError as e:
                        failed_funcs.append((func_ea, func_name, "IO error: {}".format(str(e))))
                    processed_addrs.add(func_ea)
                else:
                    failed_funcs.append((func_ea, func_name, "empty decompilation result"))
                    processed_addrs.add(func_ea)
            elif do_decompile and cfunc is None and func_ea not in processed_addrs:
                failed_funcs.append((func_ea, func_name, "decompile returned None"))
                processed_addrs.add(func_ea)

            # Write microcode/ctree output
            if do_microcode and cfunc is not None:
                try:
                    lines = []
                    lines.append("// Function: {} at {}".format(func_name, hex(func_ea)))
                    lines.append("// Hex-Rays ctree output")
                    lines.append("")
                    sv = cfunc.get_pseudocode()
                    for i in range(sv.size()):
                        line = ida_lines.tag_remove(sv[i].line) if hasattr(ida_lines, 'tag_remove') else str(sv[i].line)
                        lines.append(line)
                    output_path = os.path.join(micro_dir, "{:X}.ctree".format(func_ea))
                    with open(output_path, 'w', encoding='utf-8') as mf:
                        mf.write('\n'.join(lines))
                    counts['microcode'] += 1
                except:
                    pass

            # Release cfunc
            cfunc = None

            # --- Disassembly ---
            if do_disassembly:
                lines = []
                lines.append("; function: {} at {}".format(func_name, hex(func_ea)))
                lines.append("; size: {} bytes".format(func.end_ea - func.start_ea))
                lines.append("")
                for head in idautils.Heads(func.start_ea, func.end_ea):
                    flags = idc.get_full_flags(head)
                    if idc.is_code(flags):
                        disasm = idc.GetDisasm(head)
                        size = idc.get_item_size(head)
                        raw_bytes = ""
                        for i in range(min(size, 16)):
                            raw_bytes += "{:02X} ".format(ida_bytes.get_byte(head + i))
                        lines.append("{} | {:20s} | {}".format(hex(head), raw_bytes.strip(), disasm))
                output_path = os.path.join(disasm_dir, "{:X}.asm".format(func_ea))
                with open(output_path, 'w', encoding='utf-8') as df:
                    df.write('\n'.join(lines))
                counts['disasm_exported'] += 1

            # --- Per-instruction analyses: switch tables, exceptions, debug info, operand types ---
            func_has_debug = False
            func_written_operand = False
            has_eh = False
            eh_indicators = []

            if do_switch or do_exceptions or do_debug or do_operand:
                for head in idautils.Heads(func.start_ea, func.end_ea):
                    # Switch tables
                    if do_switch:
                        si = ida_nalt.get_switch_info(head)
                        if si is not None:
                            ncases = si.get_jtable_size()
                            files['switch'].write("=" * 60 + "\n")
                            files['switch'].write("Switch at {} in {}\n".format(hex(head), func_name))
                            files['switch'].write("  Jump table at: {}\n".format(hex(si.jumps)))
                            files['switch'].write("  Cases: {}\n".format(ncases))
                            files['switch'].write("  Element size: {}\n".format(si.get_jtable_element_size()))
                            elem_size = si.get_jtable_element_size()
                            for i in range(ncases):
                                target_ea = si.jumps + i * elem_size
                                try:
                                    if elem_size == 4:
                                        offset = ida_bytes.get_dword(target_ea)
                                    elif elem_size == 8:
                                        offset = ida_bytes.get_qword(target_ea)
                                    elif elem_size == 2:
                                        offset = ida_bytes.get_word(target_ea)
                                    else:
                                        offset = ida_bytes.get_dword(target_ea)
                                    if si.flags & 0x1:
                                        if elem_size == 4 and offset > 0x7FFFFFFF:
                                            offset -= 0x100000000
                                    target = si.elbase + offset if hasattr(si, 'elbase') else offset
                                    files['switch'].write("  case {}: -> {}\n".format(i, hex(target)))
                                except:
                                    files['switch'].write("  case {}: -> <read error>\n".format(i))
                            files['switch'].write("\n")
                            counts['switch'] += 1

                    head_flags = idc.get_full_flags(head)
                    is_code = idc.is_code(head_flags)

                    # Exceptions
                    if do_exceptions and is_code:
                        disasm = idc.GetDisasm(head)
                        if any(x in disasm.lower() for x in
                               ['__cxa_begin_catch', '__cxa_end_catch', '__cxa_throw',
                                '_except_handler', 'unwind', '__try', '__except',
                                'personality', 'lsda', 'landing_pad']):
                            eh_indicators.append((head, disasm))
                            has_eh = True

                    # Debug info
                    if do_debug:
                        try:
                            srcfile = idc.get_sourcefile(head)
                            srcline = idc.get_source_linnum(head)
                            if srcfile or srcline:
                                if not func_has_debug:
                                    files['debug'].write("\n{} ({})\n".format(func_name, hex(func_ea)))
                                    func_has_debug = True
                                files['debug'].write("  {} | {}:{}\n".format(
                                    hex(head),
                                    srcfile if srcfile else "?",
                                    srcline if srcline else "?"))
                                counts['debug'] += 1
                        except:
                            pass

                    # Operand types
                    if do_operand and is_code:
                        has_interesting = False
                        ops_info = []
                        for n in range(8):
                            ot = idc.get_operand_type(head, n)
                            if ot == 0:
                                break
                            ov = idc.get_operand_value(head, n)
                            if ot == 5:
                                if idc.is_defarg0(head_flags) and n == 0:
                                    has_interesting = True
                                elif idc.is_defarg1(head_flags) and n == 1:
                                    has_interesting = True
                            type_name = OP_NAMES.get(ot, "type_{}".format(ot))
                            ops_info.append("op{}={}({})".format(n, type_name, hex(ov) if ov else "0"))
                        if has_interesting and ops_info:
                            if not func_written_operand:
                                files['operand'].write("\n## {} ({})\n".format(func_name, hex(func_ea)))
                                func_written_operand = True
                            disasm = idc.GetDisasm(head)
                            files['operand'].write("  {} | {} | {}\n".format(hex(head), disasm, " ".join(ops_info)))
                            counts['operand'] += 1

            # Exceptions: write if found
            if do_exceptions:
                if func.flags & ida_funcs.FUNC_FRAME:
                    has_eh = True
                if has_eh or eh_indicators:
                    files['exceptions'].write("Function: {} at {} (flags=0x{:X})\n".format(
                        func_name, hex(func_ea), func.flags))
                    if func.flags & ida_funcs.FUNC_FRAME:
                        files['exceptions'].write("  Has FUNC_FRAME flag\n")
                    for addr, dis in eh_indicators:
                        files['exceptions'].write("  {} : {}\n".format(hex(addr), dis))
                    files['exceptions'].write("\n")
                    counts['exceptions'] += 1

            # Periodic cleanup
            if (idx + 1) % 200 == 0:
                clear_undo_buffer()
                gc.collect()
                if do_decompile:
                    save_progress(export_dir, processed_addrs, failed_funcs, skipped_funcs)

        # --- Write callgraph JSON ---
        if do_callgraph:
            callgraph_path = os.path.join(export_dir, "callgraph.json")
            with open(callgraph_path, 'w', encoding='utf-8') as f:
                json.dump(callgraph, f, indent=2)
            print("[*] Call Graph: {} functions, {} edges".format(
                len(callgraph), sum(len(v["calls"]) for v in callgraph.values())))

        # --- Save decompile progress and failure logs ---
        if do_decompile:
            save_progress(export_dir, processed_addrs, failed_funcs, skipped_funcs)
            if failed_funcs:
                failed_log_path = os.path.join(export_dir, "decompile_failed.txt")
                with open(failed_log_path, 'w', encoding='utf-8') as f:
                    f.write("# Failed to decompile {} functions\n".format(len(failed_funcs)))
                    f.write("# Format: address | function_name | reason\n")
                    f.write("#" + "=" * 80 + "\n\n")
                    for addr, name, reason in failed_funcs:
                        f.write("{} | {} | {}\n".format(hex(addr), name, reason))
            if skipped_funcs:
                skipped_log_path = os.path.join(export_dir, "decompile_skipped.txt")
                with open(skipped_log_path, 'w', encoding='utf-8') as f:
                    f.write("# Skipped {} functions\n".format(len(skipped_funcs)))
                    f.write("# Format: address | function_name | reason\n")
                    f.write("#" + "=" * 80 + "\n\n")
                    for addr, name, reason in skipped_funcs:
                        f.write("{} | {} | {}\n".format(hex(addr), name, reason))

        # Print summaries
        print("[*] Per-function pass summary:")
        if do_prototypes:
            print("    Prototypes: {}".format(counts['prototypes']))
        if do_stack_frames:
            print("    Stack frames: {}".format(counts['stack_frames']))
        if do_chunks:
            print("    Multi-chunk functions: {}".format(counts['chunks']))
        if do_flirt:
            print("    FLIRT matches: {}".format(counts['flirt']))
        if do_switch:
            print("    Switch tables: {}".format(counts['switch']))
        if do_exceptions:
            print("    Exception handlers: {}".format(counts['exceptions']))
        if do_debug:
            print("    Debug mappings: {}".format(counts['debug']))
        if do_operand:
            print("    Operand info: {}".format(counts['operand']))
        if do_comments:
            print("    Function comments: {}".format(counts['comments']))
        if do_disassembly:
            print("    Disassembly files: {}".format(counts['disasm_exported']))
        if do_decompile:
            print("    Decompiled: {}, failed: {}, skipped: {}".format(
                counts['decompiled'], len(failed_funcs), len(skipped_funcs)))
        if do_microcode:
            print("    Microcode/ctree: {}".format(counts['microcode']))

    finally:
        for fobj in files.values():
            try:
                fobj.close()
            except:
                pass


def export_per_segment_pass(export_dir, skip_tasks=None):
    """Single pass over all segments and their heads, writing to multiple output files.

    Replaces: export_xrefs, export_comments (line comments), export_enum_usage,
    export_colors, export_undefined_ranges
    """
    do_xrefs = not skip_tasks or "Cross-references" not in skip_tasks
    do_comments = not skip_tasks or "Comments and labels" not in skip_tasks
    do_enum = not skip_tasks or "Enum usage" not in skip_tasks
    do_colors = not skip_tasks or "Colors" not in skip_tasks
    do_undef = not skip_tasks or "Undefined ranges" not in skip_tasks

    # Pre-collect enums for enum_usage
    enums = {}
    if do_enum:
        til = ida_typeinf.get_idati()
        for ordinal in range(1, ida_typeinf.get_ordinal_count(til)):
            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.get_numbered_type(til, ordinal):
                continue
            if not tinfo.is_enum():
                continue
            enum_name = tinfo.get_type_name()
            try:
                edm = ida_typeinf.enum_type_data_t()
                if tinfo.get_enum_details(edm):
                    members = {}
                    for i in range(edm.size()):
                        member = edm[i]
                        members[member.value] = member.name
                    enums[enum_name] = members
            except:
                pass
        if not enums:
            do_enum = False

    xref_type_names = {
        ida_xref.fl_CF: "call_far",
        ida_xref.fl_CN: "call_near",
        ida_xref.fl_JF: "jump_far",
        ida_xref.fl_JN: "jump_near",
        ida_xref.fl_F: "flow",
        ida_xref.dr_O: "data_offset",
        ida_xref.dr_W: "data_write",
        ida_xref.dr_R: "data_read",
        ida_xref.dr_T: "data_text",
        ida_xref.dr_I: "data_info",
    }

    files = {}
    try:
        if do_xrefs:
            files['xrefs'] = open(os.path.join(export_dir, "xrefs.txt"), 'w', encoding='utf-8')
            files['xrefs'].write("# Full Cross-Reference Map\n")
            files['xrefs'].write("# Format: from_addr | to_addr | xref_type | type_name\n")
            files['xrefs'].write("#" + "=" * 80 + "\n\n")

        if do_comments:
            # Append to comments.txt (function comments already written by function pass)
            files['comments'] = open(os.path.join(export_dir, "comments.txt"), 'a', encoding='utf-8')
            files['comments'].write("\n## Line Comments\n")
            files['comments'].write("# Format: address | comment_type | comment\n")
            files['comments'].write("#" + "-" * 60 + "\n\n")

        if do_enum:
            files['enum'] = open(os.path.join(export_dir, "enum_usage.txt"), 'w', encoding='utf-8')
            files['enum'].write("# Enum Value Usage in Code\n")
            files['enum'].write("# Format: address | operand | enum_name | member_name | value\n")
            files['enum'].write("#" + "=" * 80 + "\n\n")

        if do_colors:
            files['colors'] = open(os.path.join(export_dir, "colors.txt"), 'w', encoding='utf-8')
            files['colors'].write("# Color Markings\n")
            files['colors'].write("# Format: address | color (RRGGBB) | context\n")
            files['colors'].write("#" + "=" * 80 + "\n\n")

        if do_undef:
            files['undef'] = open(os.path.join(export_dir, "undefined_ranges.txt"), 'w', encoding='utf-8')
            files['undef'].write("# Undefined / Unexplored Byte Ranges\n")
            files['undef'].write("# Regions where IDA couldn't determine code or data\n")
            files['undef'].write("#" + "=" * 80 + "\n\n")

        counts = {
            'code_xrefs': 0, 'data_xrefs': 0, 'comments': 0,
            'enum': 0, 'colors': 0, 'undef_ranges': 0, 'undef_bytes': 0,
        }

        total_segs = ida_segment.get_segm_qty()
        _LAST_SUB_PROGRESS[0] = -1

        for seg_idx in range(total_segs):
            seg = ida_segment.getnseg(seg_idx)
            if seg is None:
                continue

            print_sub_progress(seg_idx + 1, total_segs, "segments")
            seg_name = ida_segment.get_segm_name(seg)
            seg_class = ida_segment.get_segm_class(seg)
            is_code_seg = seg_class == "CODE"

            # Undefined ranges tracking
            undef_range_start = None
            undef_range_len = 0

            for head in idautils.Heads(seg.start_ea, seg.end_ea):
                head_flags = idc.get_full_flags(head)

                # --- Xrefs ---
                if do_xrefs:
                    for xref in idautils.XrefsFrom(head, 0):
                        if xref.to == head + idc.get_item_size(head):
                            continue
                        type_name = xref_type_names.get(xref.type, "unknown_{}".format(xref.type))
                        is_code_xref = xref.type in (ida_xref.fl_CF, ida_xref.fl_CN, ida_xref.fl_JF, ida_xref.fl_JN, ida_xref.fl_F)
                        if is_code_xref:
                            files['xrefs'].write("{} | {} | code | {}\n".format(hex(head), hex(xref.to), type_name))
                            counts['code_xrefs'] += 1
                        else:
                            files['xrefs'].write("{} | {} | data | {}\n".format(hex(head), hex(xref.to), type_name))
                            counts['data_xrefs'] += 1

                # --- Line comments ---
                if do_comments:
                    cmt = idc.get_cmt(head, 0)
                    if cmt:
                        files['comments'].write("{} | comment | {}\n".format(
                            hex(head), cmt.replace('\n', '\\n')))
                        counts['comments'] += 1
                    cmt_rep = idc.get_cmt(head, 1)
                    if cmt_rep:
                        files['comments'].write("{} | comment_rep | {}\n".format(
                            hex(head), cmt_rep.replace('\n', '\\n')))
                        counts['comments'] += 1

                # --- Enum usage ---
                if do_enum and is_code_seg and idc.is_code(head_flags):
                    for op_idx in range(8):
                        op_type = idc.get_operand_type(head, op_idx)
                        if op_type == 0:
                            break
                        if op_type == idc.o_imm:
                            val = idc.get_operand_value(head, op_idx)
                            for enum_name, members in enums.items():
                                if val in members:
                                    files['enum'].write("{} | op{} | {} | {} | {}\n".format(
                                        hex(head), op_idx, enum_name, members[val], val))
                                    counts['enum'] += 1

                # --- Colors ---
                if do_colors:
                    color = ida_nalt.get_item_color(head)
                    if color != 0xFFFFFFFF and color != ida_idaapi.BADADDR:
                        func = ida_funcs.get_func(head)
                        func_name = idc.get_func_name(func.start_ea) if func else ""
                        name = idc.get_name(head) if idc.get_name(head) else ""
                        context = func_name if func_name else name
                        files['colors'].write("{} | #{:06X} | {}\n".format(hex(head), color & 0xFFFFFF, context))
                        counts['colors'] += 1

            # --- Undefined ranges (byte-by-byte scan within segment) ---
            if do_undef:
                undef_range_start = None
                undef_range_len = 0
                ea = seg.start_ea
                while ea < seg.end_ea:
                    flags = idc.get_full_flags(ea)
                    is_unknown = ida_bytes.is_unknown(flags)
                    if is_unknown:
                        if undef_range_start is None:
                            undef_range_start = ea
                        undef_range_len += 1
                    else:
                        if undef_range_start is not None and undef_range_len > 0:
                            files['undef'].write("{} - {} | size=0x{:X} | seg={}\n".format(
                                hex(undef_range_start), hex(undef_range_start + undef_range_len),
                                undef_range_len, seg_name))
                            counts['undef_bytes'] += undef_range_len
                            counts['undef_ranges'] += 1
                            undef_range_start = None
                            undef_range_len = 0
                    ea += 1
                if undef_range_start is not None and undef_range_len > 0:
                    files['undef'].write("{} - {} | size=0x{:X} | seg={}\n".format(
                        hex(undef_range_start), hex(undef_range_start + undef_range_len),
                        undef_range_len, seg_name))
                    counts['undef_bytes'] += undef_range_len
                    counts['undef_ranges'] += 1

            if (seg_idx + 1) % 5 == 0:
                clear_undo_buffer()

        # Append summary to undefined ranges file
        if do_undef:
            files['undef'].write("\n# Total: {} ranges, 0x{:X} bytes undefined\n".format(
                counts['undef_ranges'], counts['undef_bytes']))

        print("[*] Per-segment pass summary:")
        if do_xrefs:
            print("    Code xrefs: {}, Data xrefs: {}".format(counts['code_xrefs'], counts['data_xrefs']))
        if do_comments:
            print("    Line comments: {}".format(counts['comments']))
        if do_enum:
            print("    Enum references: {}".format(counts['enum']))
        if do_colors:
            print("    Colored items: {}".format(counts['colors']))
        if do_undef:
            print("    Undefined ranges: {}, bytes: 0x{:X}".format(counts['undef_ranges'], counts['undef_bytes']))

    finally:
        for fobj in files.values():
            try:
                fobj.close()
            except:
                pass


def export_per_name_pass(export_dir, skip_tasks=None):
    """Single pass over all names, writing to multiple output files.

    Replaces: export_globals, export_vtables, export_custom_data_types,
    export_data_xref_graph, export_comments (user labels)
    """
    do_globals = not skip_tasks or "Global variables" not in skip_tasks
    do_vtables = not skip_tasks or "Vtables" not in skip_tasks
    do_structs = not skip_tasks or "Applied structs" not in skip_tasks
    do_data_xref = not skip_tasks or "Data xref graph" not in skip_tasks
    do_comments = not skip_tasks or "Comments and labels" not in skip_tasks

    ptr_size = _ptr_export_get_ptr_size()

    files = {}
    try:
        if do_globals:
            files['globals'] = open(os.path.join(export_dir, "globals.txt"), 'w', encoding='utf-8')
            files['globals'].write("# Global Variables\n")
            files['globals'].write("# Format: address | name | segment | size | type | value\n")
            files['globals'].write("#" + "=" * 80 + "\n\n")

        if do_vtables:
            files['vtables'] = open(os.path.join(export_dir, "vtables.txt"), 'w', encoding='utf-8')
            files['vtables'].write("# Vtables and Class Hierarchy\n")
            files['vtables'].write("#" + "=" * 80 + "\n\n")

        if do_structs:
            files['structs'] = open(os.path.join(export_dir, "applied_structs.txt"), 'w', encoding='utf-8')
            files['structs'].write("# Applied Structure Types at Addresses\n")
            files['structs'].write("# Format: address | name | applied_type | size\n")
            files['structs'].write("#" + "=" * 80 + "\n\n")

        if do_comments:
            # Append user labels to comments.txt
            files['comments'] = open(os.path.join(export_dir, "comments.txt"), 'a', encoding='utf-8')
            files['comments'].write("\n## User-Defined Labels (renamed addresses)\n")
            files['comments'].write("# Format: address | label\n")
            files['comments'].write("#" + "-" * 60 + "\n\n")

        counts = {
            'globals': 0, 'vtables': 0, 'structs': 0,
            'labels': 0,
        }

        # Data xref graph collection
        globals_info = {}

        all_names = list(idautils.Names())
        total_names = len(all_names)
        _LAST_SUB_PROGRESS[0] = -1

        for idx, (ea, name) in enumerate(all_names):
            print_sub_progress(idx + 1, total_names, "names")

            flags = idc.get_full_flags(ea)
            is_data = ida_bytes.is_data(flags)

            # --- Globals ---
            if do_globals and is_data:
                seg = ida_segment.getseg(ea)
                if seg:
                    seg_name = ida_segment.get_segm_name(seg)
                    size = ida_bytes.get_item_size(ea)
                    tinfo = ida_typeinf.tinfo_t()
                    has_type = ida_nalt.get_tinfo(tinfo, ea)
                    type_str = tinfo.dstr() if has_type else ""
                    val = ""
                    if ida_bytes.is_strlit(flags):
                        try:
                            strtype = idc.get_str_type(ea)
                            raw = ida_bytes.get_strlit_contents(ea, -1, strtype)
                            if raw:
                                val = '"{}"'.format(raw.decode('utf-8', errors='replace').replace('\n', '\\n')[:200])
                        except:
                            val = "<string>"
                    elif size == 1:
                        val = "0x{:02X}".format(ida_bytes.get_byte(ea))
                    elif size == 2:
                        val = "0x{:04X}".format(ida_bytes.get_word(ea))
                    elif size == 4:
                        val = "0x{:08X}".format(ida_bytes.get_dword(ea))
                    elif size == 8:
                        val = "0x{:016X}".format(ida_bytes.get_qword(ea))
                    elif size <= 64:
                        hex_bytes = []
                        for i in range(size):
                            hex_bytes.append("{:02X}".format(ida_bytes.get_byte(ea + i)))
                        val = " ".join(hex_bytes)
                    else:
                        val = "<{} bytes>".format(size)
                    files['globals'].write("{} | {} | {} | {} | {} | {}\n".format(
                        hex(ea), name, seg_name, size, type_str, val))
                    counts['globals'] += 1

            # --- Vtables ---
            if do_vtables:
                is_vtable = any(pattern in name.lower() for pattern in
                               ["vtable", "vftable", "`vftable'", "??_7", "__ZTV"])
                is_rtti = any(pattern in name for pattern in
                             ["??_R0", "??_R1", "??_R2", "??_R3", "??_R4",
                              "__RTTI", "typeinfo", "__ZTI", "__ZTS"])
                if is_vtable:
                    files['vtables'].write("=" * 60 + "\n")
                    files['vtables'].write("VTABLE: {} at {}\n".format(name, hex(ea)))
                    slot_ea = ea
                    entry_idx = 0
                    max_entries = 200
                    while entry_idx < max_entries:
                        try:
                            target = _ptr_export_read_pointer(slot_ea, ptr_size)
                        except:
                            break
                        if target == 0 or target == ida_idaapi.BADADDR:
                            break
                        func = ida_funcs.get_func(target)
                        if func is None and not idc.is_code(idc.get_full_flags(target)):
                            break
                        target_name = idc.get_func_name(target) if func else idc.get_name(target)
                        if not target_name:
                            target_name = "sub_{:X}".format(target)
                        files['vtables'].write("  [{}] {} -> {} ({})\n".format(
                            entry_idx, hex(slot_ea), hex(target), target_name))
                        slot_ea += ptr_size
                        entry_idx += 1
                    files['vtables'].write("  ({} entries)\n\n".format(entry_idx))
                    counts['vtables'] += 1
                elif is_rtti:
                    files['vtables'].write("RTTI: {} at {}\n".format(name, hex(ea)))

            # --- Applied structs ---
            if do_structs and is_data:
                tinfo = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tinfo, ea):
                    if tinfo.is_struct() or tinfo.is_union() or tinfo.is_array():
                        size = ida_bytes.get_item_size(ea)
                        type_str = tinfo.dstr()
                        seg = ida_segment.getseg(ea)
                        seg_name = ida_segment.get_segm_name(seg) if seg else "?"
                        files['structs'].write("{} | {} | {} | size={} | seg={}\n".format(
                            hex(ea), name, type_str, size, seg_name))
                        counts['structs'] += 1

            # --- Data xref graph (collect globals) ---
            if do_data_xref and is_data:
                seg = ida_segment.getseg(ea)
                if seg:
                    globals_info[ea] = {
                        "name": name,
                        "segment": ida_segment.get_segm_name(seg),
                        "readers": [],
                        "writers": [],
                        "reader_names": [],
                        "writer_names": []
                    }

            # --- User labels ---
            if do_comments:
                try:
                    has_user = ida_bytes.has_user_name(flags)
                except:
                    has_user = bool(flags & 0x4000)
                if has_user:
                    files['comments'].write("{} | {}\n".format(hex(ea), name))
                    counts['labels'] += 1

            if (idx + 1) % 500 == 0:
                clear_undo_buffer()

        # --- Vtable fallback scan (if no named vtables found) ---
        if do_vtables and counts['vtables'] == 0:
            files['vtables'].write("\n# No named vtables found. Scanning for vtable-like pointer arrays...\n\n")
            for seg_ea in idautils.Segments():
                seg_name = idc.get_segm_name(seg_ea)
                if not seg_name:
                    continue
                seg_name_l = seg_name.lower()
                if not any(x in seg_name_l for x in [".rdata", ".rodata", "const"]):
                    continue
                seg_start = idc.get_segm_start(seg_ea)
                seg_end = idc.get_segm_end(seg_ea)
                addr = seg_start
                while addr < seg_end:
                    consecutive_funcs = 0
                    check_addr = addr
                    while check_addr < seg_end:
                        try:
                            target = _ptr_export_read_pointer(check_addr, ptr_size)
                        except:
                            break
                        func = ida_funcs.get_func(target) if _ptr_export_is_valid_target(target) else None
                        if func and func.start_ea == target:
                            consecutive_funcs += 1
                            check_addr += ptr_size
                        else:
                            break
                    if consecutive_funcs >= 3:
                        files['vtables'].write("POSSIBLE_VTABLE at {} ({} function pointers):\n".format(
                            hex(addr), consecutive_funcs))
                        for i in range(consecutive_funcs):
                            slot = addr + i * ptr_size
                            target = _ptr_export_read_pointer(slot, ptr_size)
                            target_name = idc.get_func_name(target) or "sub_{:X}".format(target)
                            files['vtables'].write("  [{}] {} -> {} ({})\n".format(i, hex(slot), hex(target), target_name))
                        files['vtables'].write("\n")
                        counts['vtables'] += 1
                        addr = check_addr
                    else:
                        addr += ptr_size

        # --- Data xref graph: resolve xrefs for collected globals ---
        if do_data_xref:
            total_globals = len(globals_info)
            _LAST_SUB_PROGRESS[0] = -1
            for gidx, (data_ea, info) in enumerate(globals_info.items()):
                if (gidx + 1) % 200 == 0:
                    print_sub_progress(gidx + 1, total_globals, "data xrefs")
                for xref in idautils.XrefsTo(data_ea, 0):
                    func = ida_funcs.get_func(xref.frm)
                    if not func:
                        continue
                    func_addr = hex(func.start_ea)
                    func_name = idc.get_func_name(func.start_ea)
                    if xref.type in (ida_xref.dr_W,):
                        if func_addr not in info["writers"]:
                            info["writers"].append(func_addr)
                            info["writer_names"].append(func_name)
                    else:
                        if func_addr not in info["readers"]:
                            info["readers"].append(func_addr)
                            info["reader_names"].append(func_name)

            graph = {}
            for ea, info in globals_info.items():
                if info["readers"] or info["writers"]:
                    graph[hex(ea)] = info

            data_graph_path = os.path.join(export_dir, "data_xref_graph.json")
            with open(data_graph_path, 'w', encoding='utf-8') as f:
                json.dump(graph, f, indent=2)
            print("[*] Data Xref Graph: {} globals with refs, {} reader edges, {} writer edges".format(
                len(graph),
                sum(len(v["readers"]) for v in graph.values()),
                sum(len(v["writers"]) for v in graph.values())))

        print("[*] Per-name pass summary:")
        if do_globals:
            print("    Globals: {}".format(counts['globals']))
        if do_vtables:
            print("    Vtables: {}".format(counts['vtables']))
        if do_structs:
            print("    Applied structs: {}".format(counts['structs']))
        if do_comments:
            print("    User labels: {}".format(counts['labels']))

    finally:
        for fobj in files.values():
            try:
                fobj.close()
            except:
                pass


def do_export(export_dir=None, ask_user=True, skip_auto_analysis=False, worker_count=None, skip_tasks=None):
    """执行导出操作

    Args:
        export_dir: 导出目录路径，如果为None则使用默认或询问用户
        ask_user: 是否询问用户选择目录
        skip_auto_analysis: 是否跳过等待自动分析（如果已经分析完成）
        worker_count: 并行工作线程数，默认为CPU核心数-1
    """
    global WORKER_COUNT

    if worker_count is not None:
        WORKER_COUNT = max(1, worker_count)

    print("=" * 60)
    print("IDA Export for AI Analysis")
    print("=" * 60)
    print("[*] Using {} worker threads for parallel I/O".format(WORKER_COUNT))

    # 初始清理
    clear_undo_buffer()

    # 尝试禁用撤销功能以减少内存使用
    disable_undo()

    if not ida_hexrays.init_hexrays_plugin():
        print("[!] Hex-Rays decompiler is not available!")
        print("[!] Strings will still be exported, but no decompilation.")
        has_hexrays = False
    else:
        has_hexrays = True
        print("[+] Hex-Rays decompiler initialized")

    if not skip_auto_analysis:
        print("[*] Waiting for auto-analysis to complete...")
        print("[*] Tip: This may take a while for large files. Press Ctrl+Break to cancel.")

        # 在auto_wait之前清理一次
        clear_undo_buffer()

        ida_auto.auto_wait()

        # auto_wait之后立即清理
        clear_undo_buffer()
    else:
        print("[*] Skipping auto-analysis wait (assuming already complete)")

    if export_dir is None:
        idb_dir = get_idb_directory()
        default_export_dir = os.path.join(idb_dir, "export-for-ai")

        if ask_user:
            choice = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES,
                                        "Export to default directory?\n\n{}\n\nYes: Use default directory\nNo: Choose custom directory\nCancel: Abort export".format(
                                            default_export_dir))

            if choice == ida_kernwin.ASKBTN_CANCEL:
                print("[*] Export cancelled by user")
                enable_undo()
                return
            elif choice == ida_kernwin.ASKBTN_NO:
                selected_dir = ida_kernwin.ask_str(default_export_dir, 0, "Enter export directory path:")
                if selected_dir:
                    export_dir = selected_dir
                    print("[*] Using custom directory: {}".format(export_dir))
                else:
                    print("[*] Export cancelled by user")
                    enable_undo()
                    return
            else:
                export_dir = default_export_dir
        else:
            export_dir = default_export_dir

    ensure_dir(export_dir)

    print("[+] Export directory: {}".format(export_dir))
    print("")

    # Phase 1: Independent exports (not part of the 3 consolidated passes)
    independent_tasks = [
        ("Binary info",           export_binary_info),
        ("Strings",               export_strings),
        ("String xrefs",          export_string_xrefs),
        ("Imports",               export_imports),
        ("Imports (grouped)",     export_imports_grouped),
        ("Exports",               export_exports),
        ("Entry points",          export_entry_points),
        ("Segment metadata",      export_segments),
        ("Loaded TILs",          export_loaded_tils),
        ("Structs/enums/typedefs", export_structs_enums),
        ("Patches",               export_patches),
        ("Pointers",              export_pointers),
        ("Bookmarks",             export_bookmarks),
        ("Hidden ranges",         export_hidden_ranges),
        ("Analysis problems",     export_problems),
        ("Fixups/relocations",    export_fixups),
        ("ObjC metadata",         export_objc_metadata),
        ("Memory",                export_memory),
    ]

    # Filter independent tasks by skip_tasks
    if skip_tasks:
        independent_tasks = [(n, f) for n, f in independent_tasks if n not in skip_tasks]

    def print_progress_bar(current, total, task_name, width=40):
        """Print an ASCII progress bar"""
        pct = current / total if total > 0 else 0
        filled = int(width * pct)
        bar = "█" * filled + "░" * (width - filled)
        print("\n┌─ Progress: [{}/{}] {:.0f}%".format(current, total, pct * 100))
        print("│  [{}]".format(bar))
        print("└─ {}".format(task_name))
        print("")

    # Total: independent tasks + 3 consolidated passes
    total_tasks = len(independent_tasks) + 3
    start_time = time.time()

    # Run independent exports
    for task_idx, (task_name, task_func) in enumerate(independent_tasks):
        print_progress_bar(task_idx, total_tasks, task_name)
        print("[*] [{}/{}] Exporting {}...".format(task_idx + 1, total_tasks, task_name))
        try:
            task_func(export_dir)
        except Exception as e:
            print("[!] Failed to export {}: {}".format(task_name, str(e)))
        clear_undo_buffer()

    task_idx = len(independent_tasks)

    # Phase 2: Per-name pass
    task_idx += 1
    print_progress_bar(task_idx - 1, total_tasks, "Per-name pass (globals, vtables, structs, data xrefs, labels)")
    print("[*] [{}/{}] Running per-name pass...".format(task_idx, total_tasks))
    try:
        export_per_name_pass(export_dir, skip_tasks=skip_tasks)
    except Exception as e:
        print("[!] Per-name pass failed: {}".format(str(e)))
        import traceback
        traceback.print_exc()
    clear_undo_buffer()

    # Phase 3: Per-segment pass
    task_idx += 1
    print_progress_bar(task_idx - 1, total_tasks, "Per-segment pass (xrefs, comments, enums, colors, undef)")
    print("[*] [{}/{}] Running per-segment pass...".format(task_idx, total_tasks))
    try:
        export_per_segment_pass(export_dir, skip_tasks=skip_tasks)
    except Exception as e:
        print("[!] Per-segment pass failed: {}".format(str(e)))
        import traceback
        traceback.print_exc()
    clear_undo_buffer()

    # Phase 4: Per-function pass (heaviest)
    task_idx += 1
    print_progress_bar(task_idx - 1, total_tasks, "Per-function pass (prototypes, decompile, disasm, callgraph, ...)")
    print("[*] [{}/{}] Running per-function pass...".format(task_idx, total_tasks))
    print("[*] Tip: If IDA crashes during decompilation, restart and export will resume")
    try:
        export_per_function_pass(export_dir, skip_tasks=skip_tasks)
    except Exception as e:
        print("[!] Per-function pass failed: {}".format(str(e)))
        import traceback
        traceback.print_exc()
    clear_undo_buffer()

    elapsed = time.time() - start_time
    print_progress_bar(total_tasks, total_tasks, "DONE in {:.1f}s".format(elapsed))

    # 恢复撤销功能
    enable_undo()

    print("")
    print("=" * 60)
    print("[+] Export completed!")
    print("    Output directory: {}".format(export_dir))
    print("=" * 60)

    ida_kernwin.info("Export completed!\n\nOutput directory:\n{}".format(export_dir))


# ============================================================================
# Export Task Registry
# ============================================================================

EXPORT_TASKS = [
    # Independent exports
    ("binary_info",    "Binary Info",            export_binary_info,          True),
    ("strings",        "Strings",                export_strings,              True),
    ("string_xrefs",   "String Xrefs",           export_string_xrefs,         True),
    ("imports",        "Imports",                 export_imports,              True),
    ("imports_grouped","Imports (by Module)",     export_imports_grouped,      True),
    ("exports",        "Exports",                 export_exports,              True),
    ("entry_points",   "Entry Points",            export_entry_points,         True),
    ("segments",       "Segment Metadata",        export_segments,             True),
    ("loaded_tils",    "Loaded TILs",             export_loaded_tils,          True),
    ("structs_enums",  "Structs/Enums/Typedefs",  export_structs_enums,        True),
    ("patches",        "Patches",                 export_patches,              True),
    ("pointers",       "Pointers",                export_pointers,             True),
    ("bookmarks",      "Bookmarks",               export_bookmarks,            True),
    ("hidden_ranges",  "Hidden Ranges",           export_hidden_ranges,        True),
    ("problems",       "Analysis Problems",       export_problems,             True),
    ("fixups",         "Fixups/Relocations",      export_fixups,               True),
    ("objc",           "ObjC Metadata",           export_objc_metadata,        False),
    ("memory",         "Memory Dump",             export_memory,               True),
    # Per-name pass sub-tasks (individual functions still available for GUI)
    ("globals",        "Global Variables",         export_globals,              True),
    ("vtables",        "Vtables",                  export_vtables,              True),
    ("applied_structs","Applied Structs",          export_custom_data_types,    True),
    ("data_xref",      "Data Xref Graph",          export_data_xref_graph,      True),
    # Per-segment pass sub-tasks
    ("xrefs",          "Cross-References",         export_xrefs,                True),
    ("comments",       "Comments & Labels",        export_comments,             True),
    ("enum_usage",     "Enum Usage",               export_enum_usage,           True),
    ("colors",         "Color Markings",           export_colors,               True),
    ("undef_ranges",   "Undefined Ranges",         export_undefined_ranges,     True),
    # Per-function pass sub-tasks
    ("prototypes",     "Function Prototypes",      export_function_prototypes,  True),
    ("stack_frames",   "Stack Frames",             export_stack_frames,         True),
    ("callgraph",      "Call Graph",               export_callgraph,            True),
    ("disassembly",    "Disassembly (ASM)",        export_disassembly,          True),
    ("func_chunks",    "Function Chunks",          export_function_chunks,      True),
    ("flirt",          "FLIRT Matches",            export_flirt_matches,        True),
    ("switch_tables",  "Switch Tables",            export_switch_tables,        True),
    ("exceptions",     "Exceptions/SEH",           export_exceptions,           True),
    ("debug_info",     "Debug Info",               export_debug_info,           True),
    ("operand_info",   "Operand Info",             export_operand_types,        True),
    ("decompiled",     "Decompiled Functions",     None,                        True),
    ("microcode",      "Microcode/Ctree",          None,                        True),
]


# ============================================================================
# GUI Dialog
# ============================================================================

if HAS_QT:
    class ExportDialog(QDialog):
        """Qt GUI for the export plugin with progress tracking"""

        def __init__(self, parent=None):
            super(ExportDialog, self).__init__(parent)
            self.setWindowTitle("Export for AI Analysis")
            self.setMinimumWidth(700)
            self.setMinimumHeight(700)
            self._cancelled = False
            self._last_process_events = 0
            self._build_ui()

        def _build_ui(self):
            layout = QVBoxLayout(self)

            # Output directory
            dir_group = QGroupBox("Output Directory")
            dir_layout = QHBoxLayout(dir_group)
            idb_dir = get_idb_directory()
            self.dir_edit = QLineEdit(os.path.join(idb_dir, "export-for-ai"))
            self.dir_btn = QPushButton("Browse...")
            self.dir_btn.clicked.connect(self._on_browse)
            dir_layout.addWidget(self.dir_edit)
            dir_layout.addWidget(self.dir_btn)
            layout.addWidget(dir_group)

            # Options
            opts_group = QGroupBox("Options")
            opts_layout = QHBoxLayout(opts_group)
            self.skip_analysis_cb = QCheckBox("Skip auto-analysis wait")
            self.skip_analysis_cb.setChecked(True)
            opts_layout.addWidget(self.skip_analysis_cb)
            layout.addWidget(opts_group)

            # Task checkboxes in a grid
            tasks_group = QGroupBox("Export Tasks")
            tasks_layout = QGridLayout(tasks_group)
            self.task_checkboxes = {}

            # Select All / Deselect All buttons
            btn_layout = QHBoxLayout()
            sel_all = QPushButton("Select All")
            sel_all.clicked.connect(lambda: self._set_all_checks(True))
            desel_all = QPushButton("Deselect All")
            desel_all.clicked.connect(lambda: self._set_all_checks(False))
            btn_layout.addWidget(sel_all)
            btn_layout.addWidget(desel_all)
            btn_layout.addStretch()
            tasks_layout.addLayout(btn_layout, 0, 0, 1, 3)

            row = 1
            col = 0
            cols = 3
            for key, label, func, default_on in EXPORT_TASKS:
                cb = QCheckBox(label)
                cb.setChecked(default_on)
                self.task_checkboxes[key] = cb
                tasks_layout.addWidget(cb, row, col)
                col += 1
                if col >= cols:
                    col = 0
                    row += 1

            layout.addWidget(tasks_group)

            # Progress bars
            progress_group = QGroupBox("Progress")
            progress_layout = QVBoxLayout(progress_group)

            self.overall_label = QLabel("Overall: waiting")
            self.overall_progress = QProgressBar()
            self.overall_progress.setMinimum(0)
            self.overall_progress.setMaximum(100)
            self.overall_progress.setValue(0)

            self.task_label = QLabel("Current task: -")
            self.task_progress = QProgressBar()
            self.task_progress.setMinimum(0)
            self.task_progress.setMaximum(0)

            progress_layout.addWidget(self.overall_label)
            progress_layout.addWidget(self.overall_progress)
            progress_layout.addWidget(self.task_label)
            progress_layout.addWidget(self.task_progress)
            layout.addWidget(progress_group)

            # Log output
            log_group = QGroupBox("Log")
            log_layout = QVBoxLayout(log_group)
            self.log_text = QPlainTextEdit()
            self.log_text.setReadOnly(True)
            self.log_text.setMaximumBlockCount(5000)
            log_layout.addWidget(self.log_text)
            layout.addWidget(log_group)

            # Buttons
            btn_layout2 = QHBoxLayout()
            btn_layout2.addStretch()
            self.start_btn = QPushButton("Start Export")
            self.start_btn.setMinimumWidth(120)
            self.start_btn.clicked.connect(self._on_start)
            self.cancel_btn = QPushButton("Cancel")
            self.cancel_btn.setEnabled(False)
            self.cancel_btn.clicked.connect(self._on_cancel)
            self.close_btn = QPushButton("Close")
            self.close_btn.clicked.connect(self.close)
            btn_layout2.addWidget(self.start_btn)
            btn_layout2.addWidget(self.cancel_btn)
            btn_layout2.addWidget(self.close_btn)
            layout.addLayout(btn_layout2)

        def _set_all_checks(self, state):
            for cb in self.task_checkboxes.values():
                cb.setChecked(state)

        def _on_browse(self):
            d = QFileDialog.getExistingDirectory(self, "Select Export Directory", self.dir_edit.text())
            if d:
                self.dir_edit.setText(d)

        def _on_cancel(self):
            self._cancelled = True
            self.log("[!] Cancellation requested...")

        def log(self, message):
            self.log_text.appendPlainText(message)
            self._pump_events()

        def _pump_events(self):
            now = time.time()
            if now - self._last_process_events > 0.05:
                QApplication.processEvents()
                self._last_process_events = now

        def _on_start(self):
            self._cancelled = False
            self.start_btn.setEnabled(False)
            self.cancel_btn.setEnabled(True)
            self.log_text.clear()

            export_dir = self.dir_edit.text()
            if not export_dir:
                self.log("[!] No output directory specified")
                self.start_btn.setEnabled(True)
                self.cancel_btn.setEnabled(False)
                return

            ensure_dir(export_dir)
            disable_undo()
            clear_undo_buffer()

            # Auto-analysis
            if not self.skip_analysis_cb.isChecked():
                self.log("[*] Waiting for auto-analysis (UI may freeze)...")
                self._pump_events()
                ida_auto.auto_wait()
                clear_undo_buffer()
                self.log("[+] Auto-analysis complete")

            has_hexrays = False
            try:
                has_hexrays = ida_hexrays.init_hexrays_plugin()
            except:
                pass
            self.log("[+] Hex-Rays: {}".format("available" if has_hexrays else "not available"))
            self.log("[+] Export directory: {}".format(export_dir))

            # Build selected tasks
            selected = []
            for key, label, func, default_on in EXPORT_TASKS:
                if not self.task_checkboxes[key].isChecked():
                    continue
                if key == "decompiled":
                    if has_hexrays:
                        selected.append((key, label, lambda d: export_decompiled_functions(d, skip_existing=True)))
                    continue
                if key == "microcode":
                    if has_hexrays:
                        selected.append((key, label, export_microcode))
                    continue
                selected.append((key, label, func))

            total = len(selected)
            self.overall_progress.setMaximum(total)
            self.overall_progress.setValue(0)

            for idx, (key, label, func) in enumerate(selected):
                if self._cancelled:
                    break

                self.overall_label.setText("Overall: {}/{} - {}".format(idx + 1, total, label))
                self.task_label.setText("Current: {}".format(label))
                self.task_progress.setMaximum(0)  # indeterminate
                self.log("[*] [{}/{}] Exporting {}...".format(idx + 1, total, label))
                self._pump_events()

                try:
                    func(export_dir)
                except Exception as e:
                    self.log("[!] Failed: {} - {}".format(label, str(e)))

                clear_undo_buffer()
                self.overall_progress.setValue(idx + 1)
                self._pump_events()

            enable_undo()

            if self._cancelled:
                self.log("\n[!] Export cancelled by user")
                self.overall_label.setText("Cancelled")
            else:
                self.log("\n" + "=" * 60)
                self.log("[+] Export completed!")
                self.log("    Output: {}".format(export_dir))
                self.log("    Total tasks: {}".format(total))
                self.overall_label.setText("Complete: {}/{} tasks".format(total, total))

            self.task_label.setText("Done")
            self.task_progress.setMaximum(1)
            self.task_progress.setValue(1)
            self.start_btn.setEnabled(True)
            self.cancel_btn.setEnabled(False)


# ============================================================================
# Plugin Class
# ============================================================================

class ExportForAIPlugin(ida_idaapi.plugin_t):
    """IDA Plugin for exporting data for AI analysis"""

    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Export IDA data for AI analysis"
    help = "Export decompiled functions, strings, memory, imports and exports"
    wanted_name = "Export for AI"
    wanted_hotkey = "Ctrl-Shift-E"

    def init(self):
        print("[+] Export for AI plugin loaded")
        print("    Hotkey: {}".format(self.wanted_hotkey))
        print("    Menu: Edit -> Plugins -> Export for AI")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        try:
            if HAS_QT:
                dlg = ExportDialog(parent=None)
                dlg.exec_()
            else:
                # Fallback to old ask_yn flow
                choice = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES,
                                            "Has the auto-analysis already completed?\n\n"
                                            "Yes: Skip waiting for auto-analysis (faster)\n"
                                            "No: Wait for auto-analysis to complete\n"
                                            "Cancel: Abort export")
                if choice == ida_kernwin.ASKBTN_CANCEL:
                    print("[*] Export cancelled by user")
                    return
                skip_analysis = (choice == ida_kernwin.ASKBTN_YES)
                do_export(skip_auto_analysis=skip_analysis)
        except Exception as e:
            print("[!] Export failed: {}".format(str(e)))
            import traceback
            traceback.print_exc()
            ida_kernwin.warning("Export failed!\n\n{}".format(str(e)))

    def term(self):
        print("[-] Export for AI plugin unloaded")


def PLUGIN_ENTRY():
    """IDA插件入口点"""
    return ExportForAIPlugin()


# ============================================================================
# Standalone Script Support
# ============================================================================

if __name__ == "__main__":
    # Standalone script mode (for batch/headless)
    argc = int(idc.eval_idc("ARGV.count"))
    if argc < 2:
        export_dir = None
        skip_analysis = False
    elif argc < 3:
        export_dir = idc.eval_idc("ARGV[1]")
        skip_analysis = False
    else:
        export_dir = idc.eval_idc("ARGV[1]")
        skip_analysis = (idc.eval_idc("ARGV[2]") == "1")

    # Load skip_tasks from .skip file if it exists (written by GUI)
    skip_tasks = None
    if export_dir:
        skip_file = export_dir + ".skip"
        if os.path.exists(skip_file):
            with open(skip_file, 'r') as f:
                skip_tasks = set(line.strip() for line in f if line.strip())
            print("[*] Skipping {} tasks from {}".format(len(skip_tasks), skip_file))
            os.remove(skip_file)  # clean up

    do_export(export_dir, ask_user=False, skip_auto_analysis=skip_analysis, skip_tasks=skip_tasks)

    if argc >= 2:
        idc.qexit(0)
