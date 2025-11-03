import ida_kernwin
import ida_bytes
import ida_idaapi

num = 64
size = 8
byte_order = 'little'

def print_data_at_cursor():
    start_ea = ida_kernwin.get_screen_ea()

    if start_ea == ida_idaapi.BADADDR:
        ida_kernwin.warning("Could not determine the current address. Please place your cursor in the disassembly or hex view.")
        return

    if num <= 0:
        print("Print QWORDS: Canceled or invalid number entered.")
        return

    print(f"\n--- Printing {num} QWORD(s) starting from 0x{start_ea:X} ---")
    print(f"Using {byte_order.title()}-Endian order")

    current_ea = start_ea

    for i in range(num):
        data_bytes = ida_bytes.get_bytes(current_ea, size)

        if data_bytes is None:
            ida_kernwin.warning(f"Failed to read {QWORD_SIZE} bytes at address 0x{current_ea:X}. Stopping.")
            break

        data_value = int.from_bytes(data_bytes, byte_order)

        #print(f"0x{current_ea:X}: 0x{data_value:016X}")
        print(f"0x{data_value:016X}, ", end="")

        current_ea += size

    print("--- Done ---")

if __name__ == "__main__":
    print_data_at_cursor()