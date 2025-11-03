# ida_patch_jmp_out.py (v1.1 - Corrected for IDA 9.x API)
#
# An IDA Python script to find and patch a common obfuscation pattern:
#   lea     <reg>, <location>
#   push    <reg>
#   retn
#
# This sequence is functionally equivalent to:
#   jmp     <location>
#
import idautils
import ida_ua
import ida_bytes
import ida_segment
import ida_kernwin
import ida_idaapi
import ida_allins
import ida_funcs

def patch_lea_push_ret():
    patch_count = 0
    ida_kernwin.msg("Starting scan for lea/push/ret patterns...\n")

    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg or not (seg.perm & ida_segment.SEGPERM_EXEC):
            continue

        ida_kernwin.msg(f"Scanning segment '{ida_segment.get_segm_name(seg)}'...\n")
        
        ea = seg.start_ea
        end_ea = seg.end_ea

        while ea < end_ea and ea != ida_idaapi.BADADDR:
            advanced_manually = False

            insn1 = ida_ua.insn_t()
            size1 = ida_ua.decode_insn(insn1, ea)
            if size1 > 0 and insn1.itype == ida_allins.NN_lea:
                if insn1.ops[0].type == ida_ua.o_reg and insn1.ops[1].type == ida_ua.o_mem:
                    
                    target_reg = insn1.ops[0].reg
                    jmp_destination = insn1.ops[1].addr
                    
                    ea2 = ea + size1
                    insn2 = ida_ua.insn_t()
                    size2 = ida_ua.decode_insn(insn2, ea2)

                    if size2 > 0 and insn2.itype == ida_allins.NN_push:
                        if insn2.ops[0].type == ida_ua.o_reg and insn2.ops[0].reg == target_reg:

                            ea3 = ea2 + size2
                            insn3 = ida_ua.insn_t()
                            size3 = ida_ua.decode_insn(insn3, ea3)

                            if size3 > 0 and insn3.itype == ida_allins.NN_retn:
                                original_size = size1 + size2 + size3
                                ida_kernwin.msg(f"Found pattern at 0x{ea:X}, jumping to 0x{jmp_destination:X}. Total size: {original_size} bytes.\n")
                                
                                func = ida_funcs.get_func(ea)
                                func_name = ida_funcs.get_func_name(ea)
                                ida_kernwin.msg(f"  -> Deleting function '{func_name}' at 0x{ea:X}\n")
                                ida_funcs.del_func(ea)
                                    
                                jmp_size = 5
                                if original_size < jmp_size:
                                    ida_kernwin.msg(f"  -> Skipping patch at 0x{ea:X}: original instructions ({original_size} bytes) are smaller than new jmp ({jmp_size} bytes).\n")
                                else:
                                    relative_offset = jmp_destination - (ea + jmp_size)

                                    jmp_bytes = b'\xE9' + relative_offset.to_bytes(4, byteorder='little', signed=True)

                                    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, original_size)
                                    ida_bytes.patch_bytes(ea, jmp_bytes)

                                    nop_count = original_size - jmp_size
                                    if nop_count > 0:
                                        ida_bytes.patch_bytes(ea + jmp_size, b'\x90' * nop_count)

                                    ida_ua.create_insn(ea)
                                    
                                    patch_count += 1
                                
                                ea += original_size
                                advanced_manually = True

            if not advanced_manually:
                ea = ida_bytes.next_head(ea, end_ea)

    ida_kernwin.msg(f"\nFinished scanning. Patched {patch_count} locations.\n")

if __name__ == "__main__":
    patch_lea_push_ret()
