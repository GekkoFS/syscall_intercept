
#include <link.h>

// Forward decl
static void alloc_trampoline_in_object(struct intercept_desc *desc, struct dl_phdr_info *info);

static void
alloc_trampoline_in_object(struct intercept_desc *desc, struct dl_phdr_info *info)
{
    // Search for a suitable writable segment close to text
    // We need a hole of 32 bytes (GP_SLOT_SIZE)
    
    // desc->text_start is available (already set in create_intercept_desc called by analyze_object? 
    // No, analyze_object calls create_intercept_desc. We can do this INSIDE analyze_object or just fill desc.
    
    // analyze_object calls get_object_path... then checks has_jump...
    // then calls find_syscalls(desc).
    // find_syscalls populates desc->items.
    // We should allocate trampoline before finding syscalls or after?
    // It doesn't matter, as long as it is done before activate_patches.
    // Ideally in analyze_object.
    
    // Iterate PHYDRs
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
        
        if (phdr->p_type == PT_LOAD && (phdr->p_flags & PF_W)) {
            uintptr_t seg_start = info->dlpi_addr + phdr->p_vaddr;
            uintptr_t seg_end = seg_start + phdr->p_memsz;
            
            // Check distance from text
            // We assume text is desc->text_start.
            // If desc->text_start is not set yet (it is set in find_syscalls -> find_text_section?), 
            // we might need to find text section first.
            // Actually info->dlpi_addr is mostly text start for PIE? No.
            // analyze_object logic:
            // if ((path = get_object_path(info)) == NULL) return 0;
            // ...
            // desc = create_intercept_desc(path, info->dlpi_addr);
            // create_intercept_desc finds text section and sets text_start/end.
            
            // So we can use desc->text_start.
            
            if (!desc->text_start) continue; // Should not happen if called after create
            
            // Simple check: check if segment itself is within range?
            // PC-relative jump range: +-2GB.
            // Check delta between seg_start and text_start.
            int64_t diff = (int64_t)seg_start - (int64_t)desc->text_start;
            if (diff > 0x70000000 || diff < -0x70000000) { // ~1.8GB conservative
                 // Try end?
                 diff = (int64_t)seg_end - (int64_t)desc->text_start;
                 if (diff > 0x70000000 || diff < -0x70000000) continue; 
            }
            
            // Now scan for 0s
            // Scan aligned 4 bytes?
            // We need 32 bytes of zeros.
            // Caution: we are reading process memory. It's mapped.
            uint8_t *scan_ptr = (uint8_t *)seg_start;
            // Avoid overwriting beginning of GOT?
            // Just scan until end.
            
            // Optimization: scan from end backwards? Or just scan.
            // GOT is usually small.
            
            for (uintptr_t curr = seg_start; curr <= seg_end - 32; curr += 8) {
                // Check 32 bytes
                bool empty = true;
                uint64_t *ptr = (uint64_t *)curr;
                // Check 4 x 64-bit words? 32 bytes = 4 x 8.
                if (ptr[0] != 0 || ptr[1] != 0 || ptr[2] != 0 || ptr[3] != 0) empty = false;
                
                if (empty) {
                    // Found hole!
                    desc->trampoline_address = (uint8_t *)curr;
                    

                    
                    // Make executable
                    uintptr_t page = curr & ~(PAGE_SIZE - 1);
                    syscall_no_intercept(SYS_mprotect, page, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
                    
                    // Write trampoline
                    extern void asm_entry_point(void);
                    uint8_t buff[32];
                    unsigned int size = rvp_jump_abs(buff, 0, 5, (uintptr_t)asm_entry_point); 
                    // Use t0 (reg 5) as temp? 
                    // rvp_jump_abs(buff, rd, rs, target).
                    // If we use 'jalr zero, t0, 0' -> rd=0.
                    // rs is temp register.
                    // rvp_jump_abs signature: (buff, rd, rs, to).
                    // Logic: load 'to' into 'rs'. Then 'jalr rd, rs, 0'.
                    // We want: jump to asm_entry_point. No return (it saves ra).
                    // So rd=0 (x0). rs=t0 (x5) or similar clobberable reg. 
                    // Jumps typically use REG_ZERO and REG_T0.
                    
                    // Check REG definition.
                    // REG_T0 is 5.
                    
                    uint8_t *tramp = desc->trampoline_address;
                    for(unsigned int k=0; k<size; ++k) tramp[k] = buff[k];
                    
                    __builtin___clear_cache((char *)tramp, (char *)tramp + 32);
                    return;
                }
            }
        }
    }
    
    syscall_no_intercept(SYS_write, 2, "DEBUG: FAILED to find trampoline slot in object\n", 48);
}
