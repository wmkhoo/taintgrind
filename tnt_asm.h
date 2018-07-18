#ifndef TNT_GUEST_ASM_H
#define TNT_GUEST_ASM_H


extern Bool TNT_(asm_init)(void);
extern void TNT_(asm_release)(void);
extern Bool TNT_(asm_guest_pprint)(Addr a, SizeT len, char *out, SizeT olen);

#endif // TNT_GUEST_ASM_H
