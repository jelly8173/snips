import ida_kernwin
import ida_bytes
import ida_ua
import idautils

NOP_OPCODE = 0x90

def nop_selection():
    """
    Replaces all instructions in the current selection with NOPs.
    """

    found, start_ea, end_ea = ida_kernwin.read_range_selection(None)

    if not found:
        ida_kernwin.warning("NOP Selection: No code selected. Please select a range of instructions first.")
        return

    print(f"Nop Selection: Processing range from 0x{start_ea:X} to 0x{end_ea:X}")

    instructions_patched = 0

    for head in idautils.Heads(start_ea, end_ea):
        if not ida_bytes.is_code(ida_bytes.get_flags(head)):
            continue

        insn_size = ida_bytes.get_item_size(head)

        for i in range(insn_size):
            ida_bytes.patch_byte(head + i, NOP_OPCODE)

        instructions_patched += 1

    if instructions_patched > 0:
        print(f"Nop Selection: Successfully replaced {instructions_patched} instructions with NOPs.")
        print("Nop Selection: Re-analyzing patched area...")
        ida_ua.reanalyze_range(start_ea, end_ea)
        print("Nop Selection: Done.")
    else:
        print("Nop Selection: No valid instructions were found in the selected range.")


if __name__ == "__main__":
    nop_selection()